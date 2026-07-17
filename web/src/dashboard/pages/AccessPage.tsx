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
    MenuItem,
    Paper,
    Stack,
    TextField,
    Typography,
} from "@mui/material";
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { useState } from "react";
import {
    applyTokenAnnotation,
    applyAccessMutation,
    fetchManagementAccess,
    fetchManagementSnapshot,
    validateAccessMutation,
    validateTokenAnnotation,
    type AccessMutationDesired,
    type AccessMutationValidation,
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

interface AccessDraft {
    readonly title: string;
    readonly desired: AccessMutationDesired;
}

export function AccessPage({
    management,
    configurationEnabled,
    onRequestConfiguration,
}: AccessPageProps) {
    const queryClient = useQueryClient();
    const access = useQuery({
        queryKey: ["management-access"],
        queryFn: fetchManagementAccess,
    });
    const [draft, setDraft] = useState<AnnotationDraft | null>(null);
    const [accessDraft, setAccessDraft] = useState<AccessDraft | null>(null);
    const [accessValidation, setAccessValidation] = useState<AccessMutationValidation | null>(null);
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
    const accessValidationMutation = useMutation({
        mutationFn: (value: AccessDraft) => validateAccessMutation(value.desired),
        onSuccess: setAccessValidation,
    });
    const accessApplyMutation = useMutation({
        mutationFn: async (desired: AccessMutationValidation) => {
            const receipt = await applyAccessMutation(desired);
            await queryClient.fetchQuery({
                queryKey: ["management-access"],
                queryFn: fetchManagementAccess,
            });
            return receipt;
        },
        onSuccess: () => {
            setAccessDraft(null);
            setAccessValidation(null);
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
    const openAccessDraft = (value: AccessDraft) => {
        if (!configurationEnabled) {
            onRequestConfiguration();
            return;
        }
        setAccessDraft(value);
        setAccessValidation(null);
        accessValidationMutation.reset();
        accessApplyMutation.reset();
    };
    const updateAccessDesired = (change: Partial<AccessMutationDesired>) => {
        setAccessDraft((current) =>
            current === null ? null : { ...current, desired: { ...current.desired, ...change } },
        );
        setAccessValidation(null);
        accessValidationMutation.reset();
        accessApplyMutation.reset();
    };

    return (
        <>
            <PageHeading
                title="Access"
                description="Principals, groups, explicit token authority, and revocable directory boundaries."
            />
            <Stack spacing={2}>
                <Stack direction={{ xs: "column", md: "row" }} spacing={2}>
                    <Paper variant="outlined" sx={{ p: 3, flex: 1 }}>
                        <Stack direction="row" sx={{ justifyContent: "space-between", gap: 2 }}>
                            <Box>
                                <Typography variant="h6" sx={{ fontWeight: 800 }}>
                                    Principals
                                </Typography>
                                <Typography color="text.secondary" variant="body2">
                                    Human and service identities. Disabling one rejects every token
                                    immediately.
                                </Typography>
                            </Box>
                            <Button
                                onClick={() =>
                                    openAccessDraft({
                                        title: "Create principal",
                                        desired: {
                                            operation: "principal.create",
                                            resource_id: null,
                                            filesystem_id: null,
                                            principal_id: null,
                                            group_id: null,
                                            kind: "service",
                                            display_name: "",
                                            state: "active",
                                            name: null,
                                            expected_revision: 0,
                                        },
                                    })
                                }
                            >
                                New principal
                            </Button>
                        </Stack>
                        <Divider sx={{ my: 2 }} />
                        {access.isPending && <LoadingState />}
                        {access.isError && <ErrorState message="Unable to load principals." />}
                        <Stack spacing={1.5}>
                            {access.data?.principals.map((principal) => (
                                <Stack
                                    key={principal.id}
                                    direction="row"
                                    sx={{
                                        justifyContent: "space-between",
                                        gap: 2,
                                    }}
                                >
                                    <Box sx={{ minWidth: 0 }}>
                                        <Typography sx={{ fontWeight: 700 }}>
                                            {principal.display_name}
                                        </Typography>
                                        <Typography color="text.secondary" variant="caption">
                                            {principal.kind} · rev {String(principal.revision)} ·{" "}
                                            {principal.id}
                                        </Typography>
                                    </Box>
                                    <Stack
                                        direction="row"
                                        spacing={1}
                                        sx={{ alignItems: "center" }}
                                    >
                                        <Chip
                                            label={principal.state.toUpperCase()}
                                            color={
                                                principal.state === "active" ? "success" : "default"
                                            }
                                            size="small"
                                        />
                                        <Button
                                            size="small"
                                            onClick={() =>
                                                openAccessDraft({
                                                    title:
                                                        principal.state === "active"
                                                            ? "Disable principal"
                                                            : "Enable principal",
                                                    desired: {
                                                        operation: "principal.update",
                                                        resource_id: principal.id,
                                                        filesystem_id: null,
                                                        principal_id: null,
                                                        group_id: null,
                                                        kind: principal.kind,
                                                        display_name: principal.display_name,
                                                        state:
                                                            principal.state === "active"
                                                                ? "disabled"
                                                                : "active",
                                                        name: null,
                                                        expected_revision: principal.revision,
                                                    },
                                                })
                                            }
                                        >
                                            {principal.state === "active" ? "Disable" : "Enable"}
                                        </Button>
                                    </Stack>
                                </Stack>
                            ))}
                        </Stack>
                    </Paper>
                    <Paper variant="outlined" sx={{ p: 3, flex: 1 }}>
                        <Stack direction="row" sx={{ justifyContent: "space-between", gap: 2 }}>
                            <Box>
                                <Typography variant="h6" sx={{ fontWeight: 800 }}>
                                    Groups
                                </Typography>
                                <Typography color="text.secondary" variant="body2">
                                    Filesystem-scoped ACL subjects with revisioned membership.
                                </Typography>
                            </Box>
                            <Button
                                disabled={management.data.filesystems.length === 0}
                                onClick={() => {
                                    const filesystem = management.data.filesystems[0];
                                    if (filesystem !== undefined) {
                                        openAccessDraft({
                                            title: "Create group",
                                            desired: {
                                                operation: "group.create",
                                                resource_id: null,
                                                filesystem_id: filesystem.id,
                                                principal_id: null,
                                                group_id: null,
                                                kind: null,
                                                display_name: null,
                                                state: null,
                                                name: "",
                                                expected_revision: 0,
                                            },
                                        });
                                    }
                                }}
                            >
                                New group
                            </Button>
                        </Stack>
                        <Divider sx={{ my: 2 }} />
                        <Stack spacing={2}>
                            {access.data?.groups.map((group) => {
                                const members = access.data.memberships.filter(
                                    (membership) => membership.group_id === group.id,
                                );
                                return (
                                    <Box key={group.id}>
                                        <Stack
                                            direction="row"
                                            sx={{
                                                justifyContent: "space-between",
                                                gap: 2,
                                            }}
                                        >
                                            <Box>
                                                <Typography sx={{ fontWeight: 700 }}>
                                                    {group.name}
                                                </Typography>
                                                <Typography
                                                    color="text.secondary"
                                                    variant="caption"
                                                >
                                                    rev {String(group.revision)} ·{" "}
                                                    {String(members.length)} members
                                                </Typography>
                                            </Box>
                                            <Stack direction="row" spacing={1}>
                                                <Button
                                                    size="small"
                                                    disabled={
                                                        access.data.principals.filter(
                                                            (principal) =>
                                                                principal.state === "active" &&
                                                                !members.some(
                                                                    (membership) =>
                                                                        membership.principal_id ===
                                                                        principal.id,
                                                                ),
                                                        ).length === 0
                                                    }
                                                    onClick={() =>
                                                        openAccessDraft({
                                                            title: "Add group member",
                                                            desired: {
                                                                operation: "membership.add",
                                                                resource_id: group.id,
                                                                filesystem_id: group.filesystem_id,
                                                                principal_id: null,
                                                                group_id: group.id,
                                                                kind: null,
                                                                display_name: null,
                                                                state: null,
                                                                name: null,
                                                                expected_revision: group.revision,
                                                            },
                                                        })
                                                    }
                                                >
                                                    Add member
                                                </Button>
                                                <Button
                                                    size="small"
                                                    color="error"
                                                    onClick={() =>
                                                        openAccessDraft({
                                                            title: "Delete group",
                                                            desired: {
                                                                operation: "group.delete",
                                                                resource_id: group.id,
                                                                filesystem_id: group.filesystem_id,
                                                                principal_id: null,
                                                                group_id: null,
                                                                kind: null,
                                                                display_name: null,
                                                                state: null,
                                                                name: null,
                                                                expected_revision: group.revision,
                                                            },
                                                        })
                                                    }
                                                >
                                                    Delete
                                                </Button>
                                            </Stack>
                                        </Stack>
                                        <Stack
                                            direction="row"
                                            useFlexGap
                                            sx={{ mt: 1, flexWrap: "wrap" }}
                                        >
                                            {members.map((membership) => {
                                                const principal = access.data.principals.find(
                                                    (candidate) =>
                                                        candidate.id === membership.principal_id,
                                                );
                                                return (
                                                    <Chip
                                                        key={membership.principal_id}
                                                        label={
                                                            principal?.display_name ??
                                                            membership.principal_id
                                                        }
                                                        onDelete={() =>
                                                            openAccessDraft({
                                                                title: "Remove group member",
                                                                desired: {
                                                                    operation: "membership.remove",
                                                                    resource_id: group.id,
                                                                    filesystem_id:
                                                                        group.filesystem_id,
                                                                    principal_id:
                                                                        membership.principal_id,
                                                                    group_id: group.id,
                                                                    kind: null,
                                                                    display_name: null,
                                                                    state: null,
                                                                    name: null,
                                                                    expected_revision:
                                                                        group.revision,
                                                                },
                                                            })
                                                        }
                                                        size="small"
                                                    />
                                                );
                                            })}
                                        </Stack>
                                    </Box>
                                );
                            })}
                            {access.data?.groups.length === 0 && (
                                <Typography color="text.secondary">
                                    No groups configured.
                                </Typography>
                            )}
                        </Stack>
                    </Paper>
                </Stack>
                <Typography variant="h5" sx={{ fontWeight: 800, pt: 2 }}>
                    Tokens
                </Typography>
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
                open={accessDraft !== null}
                onClose={() => !accessApplyMutation.isPending && setAccessDraft(null)}
                fullWidth
                maxWidth="sm"
            >
                <DialogTitle>{accessDraft?.title ?? "Access change"}</DialogTitle>
                <DialogContent>
                    <Alert severity="info" sx={{ mb: 2 }}>
                        The server validates this exact desired state and its observed revision
                        before configuration reauthentication can apply it.
                    </Alert>
                    {accessDraft?.desired.operation === "principal.create" && (
                        <Stack spacing={2}>
                            <TextField
                                select
                                label="Principal kind"
                                value={accessDraft.desired.kind ?? "service"}
                                onChange={(event) =>
                                    updateAccessDesired({
                                        kind: event.target.value,
                                    })
                                }
                            >
                                <MenuItem value="human">Human</MenuItem>
                                <MenuItem value="service">Service / agent</MenuItem>
                            </TextField>
                            <TextField
                                autoFocus
                                label="Display name"
                                value={accessDraft.desired.display_name ?? ""}
                                slotProps={{ htmlInput: { maxLength: 256 } }}
                                onChange={(event) =>
                                    updateAccessDesired({
                                        display_name: event.target.value,
                                    })
                                }
                            />
                        </Stack>
                    )}
                    {accessDraft?.desired.operation === "group.create" && (
                        <Stack spacing={2}>
                            <TextField
                                select
                                label="Filesystem"
                                value={accessDraft.desired.filesystem_id ?? ""}
                                onChange={(event) =>
                                    updateAccessDesired({
                                        filesystem_id: event.target.value,
                                    })
                                }
                            >
                                {management.data.filesystems.map((filesystem) => (
                                    <MenuItem key={filesystem.id} value={filesystem.id}>
                                        {filesystem.name}
                                    </MenuItem>
                                ))}
                            </TextField>
                            <TextField
                                autoFocus
                                label="Group name"
                                value={accessDraft.desired.name ?? ""}
                                slotProps={{ htmlInput: { maxLength: 256 } }}
                                onChange={(event) =>
                                    updateAccessDesired({
                                        name: event.target.value,
                                    })
                                }
                            />
                        </Stack>
                    )}
                    {accessDraft?.desired.operation === "membership.add" && (
                        <TextField
                            select
                            fullWidth
                            label="Active principal"
                            value={accessDraft.desired.principal_id ?? ""}
                            onChange={(event) =>
                                updateAccessDesired({
                                    principal_id: event.target.value,
                                })
                            }
                        >
                            {access.data?.principals
                                .filter((principal) => principal.state === "active")
                                .map((principal) => (
                                    <MenuItem key={principal.id} value={principal.id}>
                                        {principal.display_name} · {principal.kind}
                                    </MenuItem>
                                ))}
                        </TextField>
                    )}
                    {accessDraft !== null &&
                        !["principal.create", "group.create", "membership.add"].includes(
                            accessDraft.desired.operation,
                        ) && (
                            <Typography>
                                {accessDraft.desired.operation} · revision{" "}
                                {String(accessDraft.desired.expected_revision)} →{" "}
                                {String(accessDraft.desired.expected_revision + 1)}
                            </Typography>
                        )}
                    {(accessValidationMutation.isError || accessApplyMutation.isError) && (
                        <Alert severity="error" sx={{ mt: 2 }}>
                            The server rejected this access change or the committed state could not
                            be re-read. Refresh before retrying.
                        </Alert>
                    )}
                    {accessValidation !== null && (
                        <Paper variant="outlined" sx={{ p: 2, mt: 2 }}>
                            <Typography sx={{ fontWeight: 800 }}>
                                Server-validated change
                            </Typography>
                            <Typography color="text.secondary" variant="body2">
                                {accessValidation.desired.operation} · expires{" "}
                                {formatDate(accessValidation.validation_expires_at)}
                            </Typography>
                            {accessValidation.warnings.map((warning) => (
                                <Alert key={warning} severity="warning" sx={{ mt: 2 }}>
                                    {warning}
                                </Alert>
                            ))}
                        </Paper>
                    )}
                </DialogContent>
                <DialogActions>
                    <Button
                        onClick={() => setAccessDraft(null)}
                        disabled={accessApplyMutation.isPending}
                    >
                        Cancel
                    </Button>
                    {accessValidation === null ? (
                        <Button
                            variant="contained"
                            disabled={
                                accessDraft === null ||
                                accessValidationMutation.isPending ||
                                (accessDraft.desired.operation === "principal.create" &&
                                    (accessDraft.desired.display_name?.trim().length ?? 0) === 0) ||
                                (accessDraft.desired.operation === "group.create" &&
                                    (accessDraft.desired.name?.trim().length ?? 0) === 0) ||
                                (accessDraft.desired.operation === "membership.add" &&
                                    accessDraft.desired.principal_id === null)
                            }
                            onClick={() =>
                                accessDraft !== null && accessValidationMutation.mutate(accessDraft)
                            }
                        >
                            Validate changes
                        </Button>
                    ) : (
                        <Button
                            variant="contained"
                            color="warning"
                            disabled={accessApplyMutation.isPending}
                            onClick={() => accessApplyMutation.mutate(accessValidation)}
                        >
                            Apply validated change
                        </Button>
                    )}
                </DialogActions>
            </Dialog>

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
                            label="Purpose / label"
                            value={draft?.label ?? ""}
                            slotProps={{ htmlInput: { maxLength: 128 } }}
                            helperText="A short human name, for example Dev driver speed test."
                            onChange={(event) => updateDraft({ label: event.target.value })}
                        />
                        <TextField
                            label="Device or workload details"
                            value={draft?.note ?? ""}
                            slotProps={{ htmlInput: { maxLength: 2048 } }}
                            helperText="Record the device, agent, service, owner, and intended use. This metadata never grants authority."
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
