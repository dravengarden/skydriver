import { Box, CircularProgress, LinearProgress, Paper, Stack, Typography } from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import { fetchLiveComponents } from "../../api/client";
import { IntegrityFindings } from "../IntegrityFindings";
import { PageHeading, formatBytes, formatDate } from "./shared";

export function ActivityPage() {
    const components = useQuery({
        queryKey: ["live-components"],
        queryFn: fetchLiveComponents,
        refetchInterval: 5_000,
    });
    return (
        <>
            <PageHeading
                title="Activity"
                description="Verified transfer progress, throughput, retries, and integrity intervention."
            />
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 2 }}>
                Live components
            </Typography>
            {components.isPending ? (
                <CircularProgress />
            ) : components.isError ? (
                <Paper variant="outlined" sx={{ p: 3 }}>
                    <Typography color="error">Unable to load live component state.</Typography>
                </Paper>
            ) : components.data.components.length === 0 ? (
                <Paper variant="outlined" sx={{ p: 3 }}>
                    <Typography sx={{ fontWeight: 700 }}>No active components</Typography>
                    <Typography color="text.secondary" variant="body2">
                        Running transfers and maintenance stages appear here.
                    </Typography>
                </Paper>
            ) : (
                <Stack spacing={2}>
                    {components.data.components.map((component) => {
                        const percent =
                            component.useful_bytes_total === null ||
                            component.useful_bytes_total === 0
                                ? null
                                : Math.min(
                                      100,
                                      (100 * component.useful_bytes_verified) /
                                          component.useful_bytes_total,
                                  );
                        return (
                            <Paper key={component.component_id} variant="outlined" sx={{ p: 3 }}>
                                <Stack
                                    direction="row"
                                    sx={{ justifyContent: "space-between", gap: 2 }}
                                >
                                    <Box>
                                        <Typography sx={{ fontWeight: 800 }}>
                                            {component.component_kind}
                                        </Typography>
                                        <Typography color="text.secondary" variant="body2">
                                            {component.operation_kind} · {component.operation_phase}{" "}
                                            · {component.client_name ?? "unassigned"}
                                        </Typography>
                                    </Box>
                                    <Typography sx={{ fontWeight: 700 }}>
                                        {component.component_state}
                                    </Typography>
                                </Stack>
                                <LinearProgress
                                    sx={{ mt: 2 }}
                                    variant={percent === null ? "indeterminate" : "determinate"}
                                    value={percent ?? 0}
                                />
                                <Typography
                                    color="text.secondary"
                                    variant="caption"
                                    sx={{ mt: 1, display: "block" }}
                                >
                                    {formatBytes(component.useful_bytes_verified)} verified ·{" "}
                                    {component.retry_count.toLocaleString()} retries · Last sample{" "}
                                    {formatDate(component.last_sample_at)}
                                </Typography>
                            </Paper>
                        );
                    })}
                </Stack>
            )}
            <Box sx={{ mt: 5 }}>
                <IntegrityFindings />
            </Box>
        </>
    );
}
