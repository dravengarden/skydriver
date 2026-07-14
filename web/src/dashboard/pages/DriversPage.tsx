import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutlineOutlined";
import AddOutlinedIcon from "@mui/icons-material/AddOutlined";
import KeyOutlinedIcon from "@mui/icons-material/KeyOutlined";
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
    TextField,
    Typography,
} from "@mui/material";
import { useMutation, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { useState } from "react";
import {
    applyDriverCredential,
    applyDriverRegistration,
    applyDriverState,
    fetchManagementSnapshot,
    validateDriverCredential,
    validateDriverRegistration,
    validateDriverState,
    type DriverCredentialValidation,
    type DriverRegistrationValidation,
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

const CREDENTIAL_EXPIRY_WARNING_SECONDS = 24 * 60 * 60;

function credentialStatus(driver: DriverView, observedAt: number) {
    if (!driver.credential_present) {
        return {
            color: driver.kind === "local-filesystem/v2" ? "default" : "warning",
            icon: <WarningAmberOutlinedIcon />,
            label: "No credential",
        } as const;
    }
    if (driver.kind !== "aliyundrive-open/v2") {
        return {
            color: "success",
            icon: <CheckCircleOutlineIcon />,
            label: "Credential sealed",
        } as const;
    }
    if (driver.credential_refresh_state === "reauth_required") {
        return {
            color: "error",
            icon: <WarningAmberOutlinedIcon />,
            label: "Reauthentication required",
        } as const;
    }
    if (driver.credential_refresh_state === "retry") {
        return {
            color: "warning",
            icon: <WarningAmberOutlinedIcon />,
            label: "Renewal retry scheduled",
        } as const;
    }
    if (driver.credential_expires_at === null) {
        return {
            color: "warning",
            icon: <WarningAmberOutlinedIcon />,
            label: "Credential expiry unknown",
        } as const;
    }
    if (driver.credential_expires_at <= observedAt) {
        return {
            color: "error",
            icon: <WarningAmberOutlinedIcon />,
            label: "Credential expired",
        } as const;
    }
    if (driver.credential_expires_at <= observedAt + CREDENTIAL_EXPIRY_WARNING_SECONDS) {
        return {
            color: "warning",
            icon: <WarningAmberOutlinedIcon />,
            label: `Expires ${formatDate(driver.credential_expires_at)}`,
        } as const;
    }
    return {
        color: "success",
        icon: <CheckCircleOutlineIcon />,
        label:
            driver.credential_refresh_state === null
                ? `Manual · expires ${formatDate(driver.credential_expires_at)}`
                : `Auto-renew · expires ${formatDate(driver.credential_expires_at)}`,
    } as const;
}

export function DriversPage({
    management,
    configurationEnabled,
    onRequestConfiguration,
}: DriversPageProps) {
    const queryClient = useQueryClient();
    const [selected, setSelected] = useState<DriverView | null>(null);
    const [validation, setValidation] = useState<DriverStateValidation | null>(null);
    const [credentialTarget, setCredentialTarget] = useState<DriverView | null>(null);
    const [accessToken, setAccessToken] = useState("");
    const [refreshToken, setRefreshToken] = useState("");
    const [credentialValidation, setCredentialValidation] =
        useState<DriverCredentialValidation | null>(null);
    const [registrationOpen, setRegistrationOpen] = useState(false);
    const [registrationId, setRegistrationId] = useState("");
    const [registrationValidation, setRegistrationValidation] =
        useState<DriverRegistrationValidation | null>(null);
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
    const credentialValidationMutation = useMutation({
        mutationFn: (driver: DriverView) =>
            validateDriverCredential(driver.id, accessToken, refreshToken, driver.revision),
        onSuccess: setCredentialValidation,
    });
    const credentialApplyMutation = useMutation({
        mutationFn: async (desired: DriverCredentialValidation) => {
            const receipt = await applyDriverCredential(desired, accessToken, refreshToken);
            const refreshed = await queryClient.fetchQuery({
                queryKey: ["management-snapshot"],
                queryFn: fetchManagementSnapshot,
            });
            const effective = refreshed.drivers.find((driver) => driver.id === receipt.driver_id);
            if (
                effective?.revision !== receipt.final_revision ||
                !effective.credential_present ||
                effective.credential_rotated_at !== receipt.rotated_at ||
                effective.credential_expires_at !== receipt.credential_expires_at
            ) {
                throw new Error("Committed driver credential did not match the re-read state.");
            }
            return receipt;
        },
        onSuccess: closeCredentialDialog,
    });
    const registrationValidationMutation = useMutation({
        mutationFn: () =>
            validateDriverRegistration(registrationId, "aliyundrive-open/v2", {
                api_base_url: "https://openapi.alipan.com",
                drive_type: "resource",
                root_folder_id: "root",
                upload_part_bytes: 20 * 1024 * 1024,
            }),
        onSuccess: setRegistrationValidation,
    });
    const registrationApplyMutation = useMutation({
        mutationFn: async (desired: DriverRegistrationValidation) => {
            const receipt = await applyDriverRegistration(desired);
            const refreshed = await queryClient.fetchQuery({
                queryKey: ["management-snapshot"],
                queryFn: fetchManagementSnapshot,
            });
            const effective = refreshed.drivers.find((driver) => driver.id === receipt.driver_id);
            if (
                effective?.revision !== receipt.final_revision ||
                effective.kind !== receipt.kind ||
                effective.enabled
            ) {
                throw new Error("Registered driver did not match the re-read state.");
            }
            return receipt;
        },
        onSuccess: closeRegistrationDialog,
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

    function closeCredentialDialog() {
        setCredentialTarget(null);
        setAccessToken("");
        setRefreshToken("");
        setCredentialValidation(null);
        credentialValidationMutation.reset();
        credentialApplyMutation.reset();
    }

    function openCredentialChange(driver: DriverView) {
        if (!configurationEnabled) {
            onRequestConfiguration();
            return;
        }
        setCredentialTarget(driver);
        setAccessToken("");
        setRefreshToken("");
        setCredentialValidation(null);
        credentialValidationMutation.reset();
        credentialApplyMutation.reset();
    }

    function closeRegistrationDialog() {
        setRegistrationOpen(false);
        setRegistrationId("");
        setRegistrationValidation(null);
        registrationValidationMutation.reset();
        registrationApplyMutation.reset();
    }

    function openRegistrationDialog() {
        if (!configurationEnabled) {
            onRequestConfiguration();
            return;
        }
        setRegistrationOpen(true);
    }

    if (management.isPending) {
        return <LoadingState />;
    }
    if (management.isError) {
        return <ErrorState message="Unable to load storage drivers." />;
    }

    return (
        <>
            <Stack direction="row" sx={{ justifyContent: "space-between", alignItems: "start" }}>
                <PageHeading
                    title="Drivers"
                    description="Storage identity, capability posture, complete objects, and redacted configuration."
                />
                <Button
                    variant="contained"
                    startIcon={<AddOutlinedIcon />}
                    onClick={openRegistrationDialog}
                >
                    Register driver
                </Button>
            </Stack>
            <Stack spacing={2}>
                {management.data.drivers.map((driver) => {
                    const status = credentialStatus(driver, management.data.observed_at);
                    return (
                        <Paper key={driver.id} variant="outlined" sx={{ p: 3 }}>
                            <Stack
                                direction={{ xs: "column", lg: "row" }}
                                sx={{ justifyContent: "space-between", gap: 2 }}
                            >
                                <Box>
                                    <Stack
                                        direction="row"
                                        spacing={1}
                                        sx={{ alignItems: "center" }}
                                    >
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
                                    <Typography
                                        color="text.secondary"
                                        variant="body2"
                                        sx={{ mt: 0.5 }}
                                    >
                                        Revision {driver.revision.toLocaleString()} · Updated{" "}
                                        {formatDate(driver.updated_at)}
                                    </Typography>
                                </Box>
                                <Stack
                                    direction="row"
                                    spacing={1}
                                    useFlexGap
                                    sx={{ alignItems: "center", flexWrap: "wrap" }}
                                >
                                    <Chip
                                        icon={status.icon}
                                        label={status.label}
                                        color={status.color}
                                        size="small"
                                    />
                                    {driver.kind === "aliyundrive-open/v2" && (
                                        <Button
                                            size="small"
                                            variant="outlined"
                                            startIcon={<KeyOutlinedIcon />}
                                            onClick={() => openCredentialChange(driver)}
                                        >
                                            {driver.credential_present
                                                ? "Rotate credential"
                                                : "Set credential"}
                                        </Button>
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
                                    gridTemplateColumns: {
                                        xs: "repeat(2, 1fr)",
                                        lg: "repeat(4, 1fr)",
                                    },
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
                                    [
                                        "Collection placements",
                                        driver.placement_count.toLocaleString(),
                                    ],
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
                    );
                })}
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
                open={registrationOpen}
                onClose={() => !registrationApplyMutation.isPending && closeRegistrationDialog()}
                fullWidth
                maxWidth="sm"
            >
                <DialogTitle>Register Aliyun Drive</DialogTitle>
                <DialogContent>
                    <Alert severity="info" sx={{ mb: 2 }}>
                        Registration creates a disabled driver with the conservative Aliyun Drive
                        defaults. Set its write-only credential and validate enablement afterward.
                    </Alert>
                    <TextField
                        autoFocus
                        fullWidth
                        label="Driver ID"
                        placeholder="aliyun-main"
                        value={registrationId}
                        disabled={registrationValidation !== null}
                        onChange={(event) => setRegistrationId(event.target.value)}
                    />
                    {(registrationValidationMutation.isError ||
                        registrationApplyMutation.isError) && (
                        <Alert severity="error" sx={{ mt: 2 }}>
                            The server rejected registration or the committed driver could not be
                            verified. Refresh before retrying.
                        </Alert>
                    )}
                    {registrationValidation !== null && (
                        <Paper variant="outlined" sx={{ mt: 3, p: 2 }}>
                            <Typography sx={{ fontWeight: 800 }}>
                                Server-normalized driver
                            </Typography>
                            <Typography color="text.secondary" variant="body2">
                                {registrationValidation.driver_id} · {registrationValidation.kind}
                                {" · "}revision 1 · disabled
                            </Typography>
                            <Box
                                component="pre"
                                sx={{
                                    m: 0,
                                    mt: 2,
                                    p: 1.5,
                                    bgcolor: "#f2f5f8",
                                    overflowX: "auto",
                                }}
                            >
                                {JSON.stringify(registrationValidation.config, null, 2)}
                            </Box>
                            {registrationValidation.warnings.map((warning) => (
                                <Alert key={warning} severity="warning" sx={{ mt: 2 }}>
                                    {warning}
                                </Alert>
                            ))}
                        </Paper>
                    )}
                </DialogContent>
                <DialogActions>
                    <Button
                        onClick={closeRegistrationDialog}
                        disabled={registrationApplyMutation.isPending}
                    >
                        Cancel
                    </Button>
                    {registrationValidation === null ? (
                        <Button
                            variant="contained"
                            disabled={
                                registrationId.trim() === "" ||
                                registrationValidationMutation.isPending
                            }
                            onClick={() => registrationValidationMutation.mutate()}
                        >
                            Validate registration
                        </Button>
                    ) : (
                        <Button
                            variant="contained"
                            disabled={registrationApplyMutation.isPending}
                            onClick={() => registrationApplyMutation.mutate(registrationValidation)}
                        >
                            Register disabled driver
                        </Button>
                    )}
                </DialogActions>
            </Dialog>

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

            <Dialog
                open={credentialTarget !== null}
                onClose={() => !credentialApplyMutation.isPending && closeCredentialDialog()}
                fullWidth
                maxWidth="sm"
            >
                <DialogTitle>
                    {credentialTarget?.credential_present ? "Rotate credential" : "Set credential"}
                </DialogTitle>
                <DialogContent>
                    <Alert severity="warning" sx={{ mb: 2 }}>
                        Both tokens are write-only. Carrack keeps refresh authority in the control
                        plane; filesystem SDKs receive only short-lived access tokens.
                    </Alert>
                    <Typography sx={{ fontWeight: 800 }}>{credentialTarget?.id}</Typography>
                    <Typography color="text.secondary" variant="body2" sx={{ mb: 2 }}>
                        {credentialTarget?.kind} · revision{" "}
                        {String(credentialTarget?.revision ?? 0)}
                    </Typography>
                    <TextField
                        autoFocus
                        fullWidth
                        label="Aliyun Drive access token"
                        type="password"
                        autoComplete="new-password"
                        value={accessToken}
                        disabled={credentialValidation !== null}
                        onChange={(event) => setAccessToken(event.target.value)}
                    />
                    <TextField
                        fullWidth
                        label="Aliyun Drive refresh token"
                        type="password"
                        autoComplete="new-password"
                        value={refreshToken}
                        disabled={credentialValidation !== null}
                        onChange={(event) => setRefreshToken(event.target.value)}
                        sx={{ mt: 2 }}
                        helperText="Obtained once through OpenList OAuth; control plane renews it thereafter."
                    />
                    {(credentialValidationMutation.isError || credentialApplyMutation.isError) && (
                        <Alert severity="error" sx={{ mt: 2 }}>
                            The server rejected the credential change or its committed state could
                            not be verified. Close this dialog before retrying.
                        </Alert>
                    )}
                    {credentialValidation !== null && (
                        <Paper variant="outlined" sx={{ mt: 3, p: 2 }}>
                            <Typography sx={{ fontWeight: 800 }}>
                                Server-validated write-only change
                            </Typography>
                            <Typography color="text.secondary" variant="body2">
                                Driver revision {String(credentialValidation.expected_revision)} →{" "}
                                {String(credentialValidation.expected_revision + 1)} · credential
                                revision {String(credentialValidation.credential_revision)} ·
                                expires {formatDate(credentialValidation.credential_expires_at)}
                            </Typography>
                            {credentialValidation.warnings.map((warning) => (
                                <Alert key={warning} severity="warning" sx={{ mt: 2 }}>
                                    {warning}
                                </Alert>
                            ))}
                        </Paper>
                    )}
                </DialogContent>
                <DialogActions>
                    <Button
                        onClick={closeCredentialDialog}
                        disabled={credentialApplyMutation.isPending}
                    >
                        Cancel
                    </Button>
                    {credentialValidation === null ? (
                        <Button
                            variant="contained"
                            disabled={
                                credentialTarget === null ||
                                accessToken.length === 0 ||
                                refreshToken.length === 0 ||
                                credentialValidationMutation.isPending
                            }
                            onClick={() =>
                                credentialTarget !== null &&
                                credentialValidationMutation.mutate(credentialTarget)
                            }
                        >
                            Validate credential
                        </Button>
                    ) : (
                        <Button
                            variant="contained"
                            color="warning"
                            disabled={credentialApplyMutation.isPending}
                            onClick={() => credentialApplyMutation.mutate(credentialValidation)}
                        >
                            Encrypt and apply
                        </Button>
                    )}
                </DialogActions>
            </Dialog>
        </>
    );
}
