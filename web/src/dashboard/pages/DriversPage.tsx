import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutlineOutlined";
import PowerSettingsNewOutlinedIcon from "@mui/icons-material/PowerSettingsNewOutlined";
import WarningAmberOutlinedIcon from "@mui/icons-material/WarningAmberOutlined";
import {
    Alert,
    Box,
    Button,
    Chip,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Divider,
    Paper,
    Stack,
    Typography,
} from "@mui/material";
import { useMutation, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { useState } from "react";
import {
    applyDriverState,
    fetchManagementSnapshot,
    validateDriverState,
    type DriverStateValidation,
    type DriverView,
    type ManagementSnapshot,
} from "../../api/client";
import { ErrorState, LoadingState, PageHeading, formatBytes, formatDate } from "./shared";

interface DriversPageProps {
    readonly management: UseQueryResult<ManagementSnapshot>;
    readonly configurationEnabled: boolean;
    readonly onRequestConfiguration: () => void;
}

export function DriversPage({
    management,
    configurationEnabled,
    onRequestConfiguration,
}: DriversPageProps) {
    const queryClient = useQueryClient();
    const [selected, setSelected] = useState<DriverView | null>(null);
    const [validation, setValidation] = useState<DriverStateValidation | null>(null);
    const validationMutation = useMutation({
        mutationFn: (driver: DriverView) =>
            validateDriverState(driver.id, !driver.enabled, driver.revision),
        onSuccess: setValidation,
    });
    const applyMutation = useMutation({
        mutationFn: async (desired: DriverStateValidation) => {
            const receipt = await applyDriverState(desired);
            const refreshed = await queryClient.fetchQuery({
                queryKey: ["management-snapshot"],
                queryFn: fetchManagementSnapshot,
            });
            const effective = refreshed.drivers.find((driver) => driver.id === receipt.driver_id);
            if (
                effective?.revision !== receipt.final_revision ||
                effective.enabled !== receipt.enabled
            ) {
                throw new Error("Committed driver state did not match the re-read state.");
            }
            return receipt;
        },
        onSuccess: closeDialog,
    });

    function closeDialog() {
        setSelected(null);
        setValidation(null);
        validationMutation.reset();
        applyMutation.reset();
    }

    function openStateChange(driver: DriverView) {
        if (!configurationEnabled) {
            onRequestConfiguration();
            return;
        }
        setSelected(driver);
        setValidation(null);
        validationMutation.reset();
        applyMutation.reset();
    }

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
                                <Button
                                    size="small"
                                    variant="outlined"
                                    color={driver.enabled ? "warning" : "primary"}
                                    startIcon={<PowerSettingsNewOutlinedIcon />}
                                    onClick={() => openStateChange(driver)}
                                >
                                    {driver.enabled ? "Disable" : "Enable"}
                                </Button>
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

            <Dialog
                open={selected !== null}
                onClose={() => !applyMutation.isPending && closeDialog()}
                fullWidth
                maxWidth="sm"
            >
                <DialogTitle>{selected?.enabled ? "Disable driver" : "Enable driver"}</DialogTitle>
                <DialogContent>
                    <Alert severity={selected?.enabled ? "warning" : "info"} sx={{ mb: 2 }}>
                        The server will validate the stored driver configuration and sign the exact
                        state transition before it can be applied.
                    </Alert>
                    <Typography sx={{ fontWeight: 800 }}>{selected?.id}</Typography>
                    <Typography color="text.secondary" variant="body2">
                        {selected?.kind} · revision {String(selected?.revision ?? 0)}
                    </Typography>
                    {(validationMutation.isError || applyMutation.isError) && (
                        <Alert severity="error" sx={{ mt: 2 }}>
                            The server rejected the change or its committed state could not be
                            verified. Refresh before retrying.
                        </Alert>
                    )}
                    {validation !== null && (
                        <Paper variant="outlined" sx={{ mt: 3, p: 2 }}>
                            <Typography sx={{ fontWeight: 800 }}>
                                Server-validated change
                            </Typography>
                            <Typography color="text.secondary" variant="body2">
                                Revision {String(validation.expected_revision)} →{" "}
                                {String(validation.expected_revision + 1)} · validation expires{" "}
                                {formatDate(validation.validation_expires_at)}
                            </Typography>
                            <Divider sx={{ my: 2 }} />
                            <Typography variant="caption" color="text.secondary">
                                EFFECTIVE STATE
                            </Typography>
                            <Typography sx={{ fontWeight: 700 }}>
                                {validation.current_enabled ? "Enabled" : "Disabled"} →{" "}
                                {validation.enabled ? "Enabled" : "Disabled"}
                            </Typography>
                            <Stack
                                direction={{ xs: "column", sm: "row" }}
                                spacing={3}
                                sx={{ mt: 2 }}
                            >
                                <Box>
                                    <Typography variant="caption" color="text.secondary">
                                        COLLECTION PLACEMENTS
                                    </Typography>
                                    <Typography sx={{ fontWeight: 700 }}>
                                        {validation.placement_count.toLocaleString()}
                                    </Typography>
                                </Box>
                                <Box>
                                    <Typography variant="caption" color="text.secondary">
                                        AVAILABLE LOCATIONS
                                    </Typography>
                                    <Typography sx={{ fontWeight: 700 }}>
                                        {validation.available_location_count.toLocaleString()}
                                    </Typography>
                                </Box>
                            </Stack>
                            {validation.warnings.map((warning) => (
                                <Alert key={warning} severity="warning" sx={{ mt: 2 }}>
                                    {warning}
                                </Alert>
                            ))}
                        </Paper>
                    )}
                </DialogContent>
                <DialogActions>
                    <Button onClick={closeDialog} disabled={applyMutation.isPending}>
                        Cancel
                    </Button>
                    {validation === null ? (
                        <Button
                            variant="contained"
                            color={selected?.enabled ? "warning" : "primary"}
                            disabled={selected === null || validationMutation.isPending}
                            onClick={() => selected !== null && validationMutation.mutate(selected)}
                        >
                            Validate state change
                        </Button>
                    ) : (
                        <Button
                            variant="contained"
                            color="warning"
                            disabled={applyMutation.isPending}
                            onClick={() => applyMutation.mutate(validation)}
                        >
                            Apply validated change
                        </Button>
                    )}
                </DialogActions>
            </Dialog>
        </>
    );
}
