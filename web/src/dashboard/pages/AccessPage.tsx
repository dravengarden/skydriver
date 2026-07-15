import EditOutlinedIcon from "@mui/icons-material/EditOutlined";
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
    applyTokenAnnotation,
    fetchManagementSnapshot,
    validateTokenAnnotation,
    type ManagementSnapshot,
    type TokenAnnotationValidation,
    type TokenView,
} from "../../api/client";
import { ErrorState, LoadingState, PageHeading, TransferPerformance, formatDate } from "./shared";

function tokenState(
    token: TokenView,
    now: number,
): { label: string; color: "success" | "error" | "default" } {
    if (token.revoked_at !== null) {
        return { label: "REVOKED", color: "error" };
    }
    if (token.expires_at <= now) {
        return { label: "EXPIRED", color: "default" };
    }
    return { label: "ACTIVE", color: "success" };
}

interface AccessPageProps {
    readonly management: UseQueryResult<ManagementSnapshot>;
    readonly configurationEnabled: boolean;
    readonly onRequestConfiguration: () => void;
}

interface AnnotationDraft {
    readonly token: TokenView;
    readonly label: string;
    readonly note: string;
}

export function AccessPage({
    management,
    configurationEnabled,
    onRequestConfiguration,
}: AccessPageProps) {
    const queryClient = useQueryClient();
    const [draft, setDraft] = useState<AnnotationDraft | null>(null);
    const [performanceTokenId, setPerformanceTokenId] = useState<string | null>(null);
    const [validation, setValidation] = useState<TokenAnnotationValidation | null>(null);
    const validationMutation = useMutation({
        mutationFn: (value: AnnotationDraft) =>
            validateTokenAnnotation(
                value.token.id,
                value.label,
                value.note,
                value.token.metadata_revision,
            ),
        onSuccess: setValidation,
    });
    const applyMutation = useMutation({
        mutationFn: async (desired: TokenAnnotationValidation) => {
            const receipt = await applyTokenAnnotation(desired);
            const refreshed = await queryClient.fetchQuery({
                queryKey: ["management-snapshot"],
                queryFn: fetchManagementSnapshot,
            });
            const effective = refreshed.tokens.find((token) => token.id === receipt.token_id);
            if (
                effective?.metadata_revision !== receipt.final_revision ||
                effective.label !== receipt.label ||
                effective.note !== receipt.note
            ) {
                throw new Error("Committed token annotation did not match the re-read state.");
            }
            return receipt;
        },
        onSuccess: () => {
            setDraft(null);
            setValidation(null);
        },
    });

    if (management.isPending) {
        return <LoadingState />;
    }
    if (management.isError) {
        return <ErrorState message="Unable to load token authorities." />;
    }

    const openEditor = (token: TokenView) => {
        if (!configurationEnabled) {
            onRequestConfiguration();
            return;
        }
        setDraft({ token, label: token.label, note: token.note });
        setValidation(null);
        validationMutation.reset();
        applyMutation.reset();
    };
    const updateDraft = (change: Partial<Pick<AnnotationDraft, "label" | "note">>) => {
        setDraft((current) => (current === null ? null : { ...current, ...change }));
        setValidation(null);
        validationMutation.reset();
        applyMutation.reset();
    };

    return (
        <>
            <PageHeading
                title="Access"
                description="Explicit token authority, directory boundaries, driver restrictions, and expiry."
            />
            <Stack spacing={2}>
                {management.data.tokens.map((token) => {
                    const state = tokenState(token, management.data.observed_at);
                    return (
                        <Paper key={token.id} variant="outlined" sx={{ p: 3 }}>
                            <Stack
                                direction={{ xs: "column", md: "row" }}
                                sx={{ justifyContent: "space-between", gap: 2 }}
                            >
                                <Box sx={{ minWidth: 0 }}>
                                    <Stack
                                        direction="row"
                                        spacing={1}
                                        sx={{
                                            alignItems: "center",
                                            flexWrap: "wrap",
                                        }}
                                    >
                                        <Typography variant="h6" sx={{ fontWeight: 800 }}>
                                            {token.label}
                                        </Typography>
                                        <Chip
                                            label={state.label}
                                            color={state.color}
                                            size="small"
                                        />
                                        <Chip
                                            label={`METADATA REV ${String(token.metadata_revision)}`}
                                            size="small"
                                            variant="outlined"
                                        />
                                    </Stack>
                                    <Typography
                                        color="text.secondary"
                                        variant="body2"
                                        sx={{ mt: 0.5 }}
                                    >
                                        {token.principal_name} · root{" "}
                                        {token.root_directory_name || "/"}
                                    </Typography>
                                    <Typography
                                        color="text.secondary"
                                        variant="caption"
                                        sx={{ fontFamily: "monospace" }}
                                    >
                                        {token.id}
                                    </Typography>
                                </Box>
                                <Stack
                                    sx={{
                                        minWidth: 220,
                                        alignItems: { md: "flex-end" },
                                    }}
                                >
                                    <Typography color="text.secondary" variant="caption">
                                        Expires
                                    </Typography>
                                    <Typography variant="body2" sx={{ fontWeight: 700 }}>
                                        {formatDate(token.expires_at)}
                                    </Typography>
                                    <Typography color="text.secondary" variant="caption">
                                        Last used {formatDate(token.last_used_at)}
                                    </Typography>
                                    <Button
                                        size="small"
                                        startIcon={<EditOutlinedIcon />}
                                        onClick={() => openEditor(token)}
                                        sx={{ mt: 1 }}
                                    >
                                        Edit annotation
                                    </Button>
                                    <Button
                                        size="small"
                                        onClick={() =>
                                            setPerformanceTokenId((current) =>
                                                current === token.id ? null : token.id,
                                            )
                                        }
                                    >
                                        {performanceTokenId === token.id
                                            ? "Hide performance"
                                            : "View performance"}
                                    </Button>
                                </Stack>
                            </Stack>
                            {token.note.length > 0 && (
                                <Typography sx={{ mt: 2 }}>{token.note}</Typography>
                            )}
                            <Box sx={{ mt: 2 }}>
                                <Typography color="text.secondary" variant="caption">
                                    Explicit actions
                                </Typography>
                                <Stack
                                    direction="row"
                                    useFlexGap
                                    spacing={0.75}
                                    sx={{ mt: 0.75, flexWrap: "wrap" }}
                                >
                                    {token.actions.map((action) => (
                                        <Chip
                                            key={action}
                                            label={action}
                                            size="small"
                                            variant="outlined"
                                        />
                                    ))}
                                </Stack>
                            </Box>
                            <Box sx={{ mt: 2 }}>
                                <Typography color="text.secondary" variant="caption">
                                    Driver scope
                                </Typography>
                                <Typography variant="body2" sx={{ mt: 0.4 }}>
                                    {token.driver_ids.length === 0
                                        ? "Unrestricted by driver"
                                        : token.driver_ids.join(", ")}
                                </Typography>
                            </Box>
                            {performanceTokenId === token.id && (
                                <TransferPerformance scope="token" scopeId={token.id} />
                            )}
                        </Paper>
                    );
                })}
                {management.data.tokens.length === 0 && (
                    <Paper variant="outlined" sx={{ p: 4 }}>
                        <Typography sx={{ fontWeight: 700 }}>No token authorities</Typography>
                    </Paper>
                )}
            </Stack>

            <Dialog
                open={draft !== null}
                onClose={() => !applyMutation.isPending && setDraft(null)}
                fullWidth
                maxWidth="sm"
            >
                <DialogTitle>Edit token annotation</DialogTitle>
                <DialogContent>
                    <Alert severity="info" sx={{ mb: 2 }}>
                        This changes descriptive metadata only. Token authority and bearer material
                        are not modified.
                    </Alert>
                    <Stack spacing={2}>
                        <TextField
                            autoFocus
                            label="Label"
                            value={draft?.label ?? ""}
                            slotProps={{ htmlInput: { maxLength: 128 } }}
                            onChange={(event) => updateDraft({ label: event.target.value })}
                        />
                        <TextField
                            label="Operator note"
                            value={draft?.note ?? ""}
                            slotProps={{ htmlInput: { maxLength: 2048 } }}
                            minRows={4}
                            multiline
                            onChange={(event) => updateDraft({ note: event.target.value })}
                        />
                    </Stack>
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
                                Metadata revision {String(validation.expected_revision)} →{" "}
                                {String(validation.expected_revision + 1)} · validation expires{" "}
                                {formatDate(validation.validation_expires_at)}
                            </Typography>
                            <Divider sx={{ my: 2 }} />
                            <Typography variant="caption" color="text.secondary">
                                LABEL
                            </Typography>
                            <Typography sx={{ overflowWrap: "anywhere" }}>
                                {validation.current_label} → {validation.label}
                            </Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ mt: 2 }}>
                                NOTE
                            </Typography>
                            <Typography
                                sx={{
                                    whiteSpace: "pre-wrap",
                                    overflowWrap: "anywhere",
                                }}
                            >
                                {validation.current_note || "(empty)"} →{" "}
                                {validation.note || "(empty)"}
                            </Typography>
                            {validation.warnings.map((warning) => (
                                <Alert key={warning} severity="warning" sx={{ mt: 2 }}>
                                    {warning}
                                </Alert>
                            ))}
                        </Paper>
                    )}
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => setDraft(null)} disabled={applyMutation.isPending}>
                        Cancel
                    </Button>
                    {validation === null ? (
                        <Button
                            variant="contained"
                            disabled={
                                draft === null ||
                                draft.label.trim().length === 0 ||
                                validationMutation.isPending
                            }
                            onClick={() => draft !== null && validationMutation.mutate(draft)}
                        >
                            Validate changes
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
