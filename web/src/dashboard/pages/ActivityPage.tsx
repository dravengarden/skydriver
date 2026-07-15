import {
    Alert,
    Box,
    Chip,
    CircularProgress,
    Divider,
    Paper,
    Stack,
    Typography,
} from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import { fetchManagementActivity } from "../../api/client";
import type { ManagementActivityItem } from "../../api/client";
import { PageHeading, formatDate } from "./shared";

function humanize(value: string): string {
    return value.replaceAll(/[._-]+/g, " ").replace(/^./, (character) => character.toUpperCase());
}

function shortIdentity(value: string): string {
    return value.length <= 26 ? value : `${value.slice(0, 12)}…${value.slice(-8)}`;
}

function ActivityItemCard({ item }: { readonly item: ManagementActivityItem }) {
    return (
        <Paper
            variant="outlined"
            sx={{
                p: { xs: 2, sm: 2.5 },
                borderColor: item.attention_required ? "warning.main" : "divider",
            }}
        >
            <Stack direction="row" sx={{ justifyContent: "space-between", gap: 2 }}>
                <Box sx={{ minWidth: 0 }}>
                    <Typography sx={{ fontWeight: 800 }}>{humanize(item.kind)}</Typography>
                    <Typography color="text.secondary" variant="body2" sx={{ mt: 0.25 }}>
                        {humanize(item.subject_kind)} · {shortIdentity(item.subject_id)}
                    </Typography>
                </Box>
                <Chip
                    label={humanize(item.state).toUpperCase()}
                    color={item.attention_required ? "warning" : "info"}
                    size="small"
                    variant={item.attention_required ? "filled" : "outlined"}
                />
            </Stack>
            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: { xs: "1fr", sm: "repeat(3, minmax(0, 1fr))" },
                    gap: 1.5,
                    mt: 2,
                }}
            >
                <Box>
                    <Typography color="text.secondary" variant="caption">
                        Driver
                    </Typography>
                    <Typography variant="body2" sx={{ fontWeight: 700 }}>
                        {item.driver_id ?? "Control plane"}
                    </Typography>
                </Box>
                <Box>
                    <Typography color="text.secondary" variant="caption">
                        Updated
                    </Typography>
                    <Typography variant="body2" sx={{ fontWeight: 700 }}>
                        {formatDate(item.updated_at)}
                    </Typography>
                </Box>
                <Box>
                    <Typography color="text.secondary" variant="caption">
                        Deadline / next action
                    </Typography>
                    <Typography variant="body2" sx={{ fontWeight: 700 }}>
                        {formatDate(item.deadline_at)}
                    </Typography>
                </Box>
            </Box>
            {(item.attempt_count > 0 || item.last_error_code !== null) && (
                <Typography
                    color="text.secondary"
                    variant="caption"
                    sx={{ mt: 1.5, display: "block" }}
                >
                    {item.attempt_count.toLocaleString()} attempts
                    {item.last_error_code === null ? "" : ` · ${humanize(item.last_error_code)}`}
                </Typography>
            )}
        </Paper>
    );
}

export function ActivityPage() {
    const activity = useQuery({
        queryKey: ["management-activity"],
        queryFn: fetchManagementActivity,
        refetchInterval: 10_000,
    });

    return (
        <>
            <PageHeading
                title="Activity"
                description="Durable VFS lifecycle work, provider health signals, and auditable changes."
            />
            <Alert severity="info" sx={{ mb: 3 }}>
                Payload bytes move directly between clients and storage drivers. Live byte progress
                stays client-local; this page reports only durable control-plane state.
            </Alert>

            {activity.isPending ? (
                <CircularProgress />
            ) : activity.isError ? (
                <Paper variant="outlined" sx={{ p: 3 }}>
                    <Typography color="error">Unable to load VFS activity.</Typography>
                </Paper>
            ) : (
                <Stack spacing={5}>
                    <Box>
                        <Stack
                            direction="row"
                            sx={{ alignItems: "baseline", justifyContent: "space-between", mb: 2 }}
                        >
                            <Box>
                                <Typography variant="h5" sx={{ fontWeight: 800 }}>
                                    Needs attention
                                </Typography>
                                <Typography color="text.secondary" variant="body2">
                                    Retry, blocked, or reauthorization states owned by the server.
                                </Typography>
                            </Box>
                            <Typography color="text.secondary" variant="caption">
                                {
                                    activity.data.active_items.filter(
                                        (item) => item.attention_required,
                                    ).length
                                }{" "}
                                open
                            </Typography>
                        </Stack>
                        {activity.data.active_items.some((item) => item.attention_required) ? (
                            <Stack spacing={2}>
                                {activity.data.active_items
                                    .filter((item) => item.attention_required)
                                    .map((item) => (
                                        <ActivityItemCard
                                            key={`${item.kind}:${item.id}`}
                                            item={item}
                                        />
                                    ))}
                            </Stack>
                        ) : (
                            <Alert severity="success">
                                No control-plane lifecycle issues need attention.
                            </Alert>
                        )}
                    </Box>

                    <Box>
                        <Typography variant="h5" sx={{ fontWeight: 800 }}>
                            Active control work
                        </Typography>
                        <Typography color="text.secondary" variant="body2" sx={{ mt: 0.5, mb: 2 }}>
                            Upload intents, read leases, cleanup jobs, and credential renewal
                            currently fenced by the control plane.
                        </Typography>
                        {activity.data.active_items.filter((item) => !item.attention_required)
                            .length === 0 ? (
                            <Paper variant="outlined" sx={{ p: 3 }}>
                                <Typography sx={{ fontWeight: 700 }}>
                                    No durable work is active
                                </Typography>
                                <Typography color="text.secondary" variant="body2" sx={{ mt: 0.5 }}>
                                    Direct transfers can still be running between API checkpoints.
                                </Typography>
                            </Paper>
                        ) : (
                            <Stack spacing={2}>
                                {activity.data.active_items
                                    .filter((item) => !item.attention_required)
                                    .map((item) => (
                                        <ActivityItemCard
                                            key={`${item.kind}:${item.id}`}
                                            item={item}
                                        />
                                    ))}
                            </Stack>
                        )}
                    </Box>

                    <Box>
                        <Stack
                            direction="row"
                            sx={{ alignItems: "baseline", justifyContent: "space-between", mb: 2 }}
                        >
                            <Box>
                                <Typography variant="h5" sx={{ fontWeight: 800 }}>
                                    Recent audit events
                                </Typography>
                                <Typography color="text.secondary" variant="body2">
                                    Newest committed namespace, access, driver, and lifecycle
                                    changes.
                                </Typography>
                            </Box>
                            <Typography color="text.secondary" variant="caption">
                                Cursor {activity.data.event_cursor.toLocaleString()}
                            </Typography>
                        </Stack>
                        {activity.data.events.length === 0 ? (
                            <Paper variant="outlined" sx={{ p: 3 }}>
                                <Typography sx={{ fontWeight: 700 }}>
                                    No audit events yet
                                </Typography>
                            </Paper>
                        ) : (
                            <Paper variant="outlined" sx={{ px: { xs: 2, sm: 2.5 } }}>
                                <Stack divider={<Divider flexItem />}>
                                    {activity.data.events.map((event) => (
                                        <Box key={event.id} sx={{ py: 2 }}>
                                            <Stack
                                                direction={{ xs: "column", sm: "row" }}
                                                sx={{ justifyContent: "space-between", gap: 0.75 }}
                                            >
                                                <Box sx={{ minWidth: 0 }}>
                                                    <Typography sx={{ fontWeight: 750 }}>
                                                        {humanize(event.event_kind)}
                                                    </Typography>
                                                    <Typography
                                                        color="text.secondary"
                                                        variant="body2"
                                                        sx={{ overflowWrap: "anywhere" }}
                                                    >
                                                        {humanize(event.subject_kind)} ·{" "}
                                                        {shortIdentity(event.subject_id)}
                                                    </Typography>
                                                </Box>
                                                <Typography
                                                    color="text.secondary"
                                                    variant="caption"
                                                >
                                                    {formatDate(event.created_at)}
                                                </Typography>
                                            </Stack>
                                            {JSON.stringify(event.details) !== "{}" && (
                                                <Typography
                                                    component="pre"
                                                    variant="caption"
                                                    sx={{
                                                        m: 0,
                                                        mt: 1,
                                                        color: "text.secondary",
                                                        whiteSpace: "pre-wrap",
                                                        overflowWrap: "anywhere",
                                                    }}
                                                >
                                                    {JSON.stringify(event.details, null, 2)}
                                                </Typography>
                                            )}
                                        </Box>
                                    ))}
                                </Stack>
                            </Paper>
                        )}
                    </Box>
                </Stack>
            )}
        </>
    );
}
