import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutlineOutlined";
import WarningAmberOutlinedIcon from "@mui/icons-material/WarningAmberOutlined";
import { Box, Chip, Paper, Stack, Typography } from "@mui/material";
import type { UseQueryResult } from "@tanstack/react-query";
import type { ManagementSnapshot } from "../../api/client";
import { ErrorState, LoadingState, PageHeading, formatBytes, formatDate } from "./shared";

export function DriversPage({ management }: { management: UseQueryResult<ManagementSnapshot> }) {
    if (management.isPending) {
        return <LoadingState />;
    }
    if (management.isError) {
        return <ErrorState message="Unable to load storage drivers." />;
    }

    return (
        <>
            <PageHeading
                title="Drivers"
                description="Storage identity, capability posture, complete objects, and redacted configuration."
            />
            <Stack spacing={2}>
                {management.data.drivers.map((driver) => (
                    <Paper key={driver.id} variant="outlined" sx={{ p: 3 }}>
                        <Stack
                            direction={{ xs: "column", sm: "row" }}
                            sx={{ justifyContent: "space-between", gap: 2 }}
                        >
                            <Box>
                                <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                                    <Typography variant="h6" sx={{ fontWeight: 800 }}>
                                        {driver.id}
                                    </Typography>
                                    <Chip label={driver.kind} size="small" variant="outlined" />
                                    <Chip
                                        label={driver.enabled ? "ENABLED" : "DISABLED"}
                                        size="small"
                                        color={driver.enabled ? "success" : "default"}
                                    />
                                </Stack>
                                <Typography color="text.secondary" variant="body2" sx={{ mt: 0.5 }}>
                                    Revision {driver.revision.toLocaleString()} · Updated{" "}
                                    {formatDate(driver.updated_at)}
                                </Typography>
                            </Box>
                            <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                                {driver.credential_present ? (
                                    <Chip
                                        icon={<CheckCircleOutlineIcon />}
                                        label="Credential sealed"
                                        color="success"
                                        size="small"
                                    />
                                ) : (
                                    <Chip
                                        icon={<WarningAmberOutlinedIcon />}
                                        label="No credential"
                                        color={
                                            driver.kind === "local-filesystem/v2"
                                                ? "default"
                                                : "warning"
                                        }
                                        size="small"
                                    />
                                )}
                            </Stack>
                        </Stack>

                        <Box
                            sx={{
                                display: "grid",
                                gridTemplateColumns: { xs: "repeat(2, 1fr)", lg: "repeat(4, 1fr)" },
                                gap: 2,
                                mt: 3,
                            }}
                        >
                            {[
                                ["Complete files", driver.file_count.toLocaleString()],
                                ["Encoded bytes", formatBytes(driver.encoded_bytes)],
                                [
                                    "Available locations",
                                    driver.available_location_count.toLocaleString(),
                                ],
                                ["Collection placements", driver.placement_count.toLocaleString()],
                            ].map(([label, value]) => (
                                <Box key={label}>
                                    <Typography color="text.secondary" variant="caption">
                                        {label}
                                    </Typography>
                                    <Typography sx={{ fontWeight: 750 }}>{value}</Typography>
                                </Box>
                            ))}
                        </Box>

                        <Box sx={{ mt: 3 }}>
                            <Typography color="text.secondary" variant="caption">
                                Redacted configuration
                            </Typography>
                            <Box
                                component="pre"
                                sx={{
                                    m: 0,
                                    mt: 0.75,
                                    p: 1.5,
                                    borderRadius: 1.5,
                                    bgcolor: "#f2f5f8",
                                    fontSize: 12,
                                    overflowX: "auto",
                                }}
                            >
                                {JSON.stringify(driver.config, null, 2)}
                            </Box>
                        </Box>
                    </Paper>
                ))}
                {management.data.drivers.length === 0 && (
                    <Paper variant="outlined" sx={{ p: 4 }}>
                        <Typography sx={{ fontWeight: 700 }}>No registered drivers</Typography>
                        <Typography color="text.secondary" variant="body2">
                            Bootstrap a VFS or register a validated driver configuration.
                        </Typography>
                    </Paper>
                )}
            </Stack>
        </>
    );
}
