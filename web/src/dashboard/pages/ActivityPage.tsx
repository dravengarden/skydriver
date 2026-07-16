import {
    Alert,
    Box,
    Chip,
    CircularProgress,
    Paper,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Typography,
} from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import { fetchManagementActivity } from "../../api/client";
import type { ManagementActivityEvent, ManagementActivityItem } from "../../api/client";
import { PageHeading, formatDate } from "./shared";

function humanize(value: string): string {
    return value.replaceAll(/[._-]+/g, " ").replace(/^./, (character) => character.toUpperCase());
}

function shortIdentity(value: string): string {
    return value.length <= 26 ? value : `${value.slice(0, 12)}…${value.slice(-8)}`;
}

function ActivityTable({ items }: { readonly items: readonly ManagementActivityItem[] }) {
    return (
        <TableContainer component={Paper} variant="outlined">
            <Table size="small" sx={{ minWidth: 760 }}>
                <TableHead>
                    <TableRow>
                        <TableCell>State</TableCell>
                        <TableCell>Work</TableCell>
                        <TableCell>Subject</TableCell>
                        <TableCell>Driver</TableCell>
                        <TableCell align="right">Attempts</TableCell>
                        <TableCell>Updated</TableCell>
                        <TableCell>Next action</TableCell>
                        <TableCell>Error</TableCell>
                    </TableRow>
                </TableHead>
                <TableBody>
                    {items.map((item) => (
                        <TableRow
                            key={`${item.kind}:${item.id}`}
                            hover
                            sx={{
                                bgcolor: item.attention_required ? "warning.50" : undefined,
                                "& td": { py: 1.1 },
                            }}
                        >
                            <TableCell>
                                <Chip
                                    label={humanize(item.state).toUpperCase()}
                                    color={item.attention_required ? "warning" : "info"}
                                    size="small"
                                    variant={item.attention_required ? "filled" : "outlined"}
                                />
                            </TableCell>
                            <TableCell sx={{ fontWeight: 750 }}>{humanize(item.kind)}</TableCell>
                            <TableCell>
                                <Typography variant="body2" sx={{ fontWeight: 700 }}>
                                    {humanize(item.subject_kind)}
                                </Typography>
                                <Typography
                                    title={item.subject_id}
                                    color="text.secondary"
                                    variant="caption"
                                >
                                    {shortIdentity(item.subject_id)}
                                </Typography>
                            </TableCell>
                            <TableCell>{item.driver_id ?? "Control plane"}</TableCell>
                            <TableCell align="right">
                                {item.attempt_count.toLocaleString()}
                            </TableCell>
                            <TableCell sx={{ whiteSpace: "nowrap" }}>
                                {formatDate(item.updated_at)}
                            </TableCell>
                            <TableCell sx={{ whiteSpace: "nowrap" }}>
                                {formatDate(item.deadline_at)}
                            </TableCell>
                            <TableCell>
                                {item.last_error_code === null
                                    ? "—"
                                    : humanize(item.last_error_code)}
                            </TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </TableContainer>
    );
}

function AuditTable({ events }: { readonly events: readonly ManagementActivityEvent[] }) {
    return (
        <TableContainer component={Paper} variant="outlined">
            <Table size="small" sx={{ minWidth: 720 }}>
                <TableHead>
                    <TableRow>
                        <TableCell>Event</TableCell>
                        <TableCell>Subject</TableCell>
                        <TableCell>Token</TableCell>
                        <TableCell>Committed</TableCell>
                        <TableCell>Details</TableCell>
                    </TableRow>
                </TableHead>
                <TableBody>
                    {events.map((event) => {
                        const details = JSON.stringify(event.details);
                        return (
                            <TableRow key={event.id} hover sx={{ "& td": { py: 1.1 } }}>
                                <TableCell sx={{ fontWeight: 750 }}>
                                    {humanize(event.event_kind)}
                                </TableCell>
                                <TableCell>
                                    <Typography variant="body2">
                                        {humanize(event.subject_kind)}
                                    </Typography>
                                    <Typography
                                        title={event.subject_id}
                                        color="text.secondary"
                                        variant="caption"
                                    >
                                        {shortIdentity(event.subject_id)}
                                    </Typography>
                                </TableCell>
                                <TableCell title={event.token_id ?? undefined}>
                                    {event.token_id === null ? "—" : shortIdentity(event.token_id)}
                                </TableCell>
                                <TableCell sx={{ whiteSpace: "nowrap" }}>
                                    {formatDate(event.created_at)}
                                </TableCell>
                                <TableCell
                                    title={details}
                                    sx={{
                                        maxWidth: 320,
                                        overflow: "hidden",
                                        textOverflow: "ellipsis",
                                        whiteSpace: "nowrap",
                                        color: "text.secondary",
                                        fontFamily: "monospace",
                                        fontSize: "0.75rem",
                                    }}
                                >
                                    {details === "{}" ? "—" : details}
                                </TableCell>
                            </TableRow>
                        );
                    })}
                </TableBody>
            </Table>
        </TableContainer>
    );
}

export function ActivityPage() {
    const activity = useQuery({
        queryKey: ["management-activity"],
        queryFn: fetchManagementActivity,
        refetchInterval: 10_000,
    });
    const attention = activity.data?.active_items.filter((item) => item.attention_required) ?? [];
    const active = activity.data?.active_items.filter((item) => !item.attention_required) ?? [];

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
                <Stack spacing={4}>
                    <Box>
                        <Stack direction="row" sx={{ alignItems: "baseline", mb: 1.5 }}>
                            <Box>
                                <Typography variant="h5" sx={{ fontWeight: 800 }}>
                                    Needs attention
                                </Typography>
                                <Typography color="text.secondary" variant="body2">
                                    Retry, blocked, or reauthorization states owned by the server.
                                </Typography>
                            </Box>
                            <Typography
                                color="text.secondary"
                                variant="caption"
                                sx={{ ml: "auto" }}
                            >
                                {attention.length} open
                            </Typography>
                        </Stack>
                        {attention.length === 0 ? (
                            <Alert severity="success">
                                No control-plane lifecycle issues need attention.
                            </Alert>
                        ) : (
                            <ActivityTable items={attention} />
                        )}
                    </Box>

                    <Box>
                        <Typography variant="h5" sx={{ fontWeight: 800 }}>
                            Active control work
                        </Typography>
                        <Typography
                            color="text.secondary"
                            variant="body2"
                            sx={{ mt: 0.25, mb: 1.5 }}
                        >
                            Upload intents, read leases, cleanup jobs, and credential renewal
                            currently fenced by the control plane.
                        </Typography>
                        {active.length === 0 ? (
                            <Paper variant="outlined" sx={{ px: 2, py: 1.5 }}>
                                <Typography sx={{ fontWeight: 700 }}>
                                    No durable work is active
                                </Typography>
                                <Typography color="text.secondary" variant="body2">
                                    Direct transfers can still be running between API checkpoints.
                                </Typography>
                            </Paper>
                        ) : (
                            <ActivityTable items={active} />
                        )}
                    </Box>

                    <Box>
                        <Stack direction="row" sx={{ alignItems: "baseline", mb: 1.5 }}>
                            <Box>
                                <Typography variant="h5" sx={{ fontWeight: 800 }}>
                                    Recent audit events
                                </Typography>
                                <Typography color="text.secondary" variant="body2">
                                    Newest committed namespace, access, driver, and lifecycle
                                    changes.
                                </Typography>
                            </Box>
                            <Typography
                                color="text.secondary"
                                variant="caption"
                                sx={{ ml: "auto" }}
                            >
                                Cursor {activity.data.event_cursor.toLocaleString()}
                            </Typography>
                        </Stack>
                        {activity.data.events.length === 0 ? (
                            <Paper variant="outlined" sx={{ px: 2, py: 1.5 }}>
                                <Typography sx={{ fontWeight: 700 }}>
                                    No audit events yet
                                </Typography>
                            </Paper>
                        ) : (
                            <AuditTable events={activity.data.events} />
                        )}
                    </Box>
                </Stack>
            )}
        </>
    );
}
