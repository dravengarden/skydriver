import {
    Alert,
    Button,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Stack,
    TextField,
    Typography,
} from "@mui/material";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { applyQuota, validateQuota } from "../../api/client";
import type { QuotaLimits, QuotaValidation } from "../../api/client";
import { formatDate } from "./shared";

interface Props {
    readonly open: boolean;
    readonly scope: "directory" | "driver";
    readonly resourceId: string;
    readonly resourceName: string;
    readonly revision: number;
    readonly limits: QuotaLimits;
    readonly configurationEnabled: boolean;
    readonly onClose: () => void;
    readonly onRequestConfiguration: () => void;
}

const unlimited = "";

function inputValue(value: number | null): string {
    return value === null ? unlimited : String(value);
}

function parsed(value: string): number | null {
    if (value.trim() === "") {
        return null;
    }
    const number = Number(value);
    return Number.isSafeInteger(number) && number > 0 ? number : Number.NaN;
}

function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : "The server rejected this quota policy.";
}

export function QuotaDialog({
    open,
    scope,
    resourceId,
    resourceName,
    revision,
    limits,
    configurationEnabled,
    onClose,
    onRequestConfiguration,
}: Props) {
    const queryClient = useQueryClient();
    const [maxFileBytes, setMaxFileBytes] = useState(unlimited);
    const [maxLogicalBytes, setMaxLogicalBytes] = useState(unlimited);
    const [maxFileCount, setMaxFileCount] = useState(unlimited);
    const [maxPhysicalBytes, setMaxPhysicalBytes] = useState(unlimited);
    const [maxObjectCount, setMaxObjectCount] = useState(unlimited);
    const [validation, setValidation] = useState<QuotaValidation | null>(null);

    useEffect(() => {
        if (!open) return;
        setMaxFileBytes(inputValue(limits.max_file_bytes));
        setMaxLogicalBytes(inputValue(limits.max_logical_bytes));
        setMaxFileCount(inputValue(limits.max_file_count));
        setMaxPhysicalBytes(inputValue(limits.max_physical_bytes));
        setMaxObjectCount(inputValue(limits.max_object_count));
        setValidation(null);
    }, [limits, open]);

    const desired: QuotaLimits = {
        max_file_bytes: scope === "directory" ? parsed(maxFileBytes) : null,
        max_logical_bytes: scope === "directory" ? parsed(maxLogicalBytes) : null,
        max_file_count: scope === "directory" ? parsed(maxFileCount) : null,
        max_physical_bytes: scope === "driver" ? parsed(maxPhysicalBytes) : null,
        max_object_count: scope === "driver" ? parsed(maxObjectCount) : null,
    };
    const valid = Object.values(desired).every(
        (value) => value === null || (Number.isSafeInteger(value) && value > 0),
    );
    const validateMutation = useMutation({
        mutationFn: () => validateQuota(scope, resourceId, desired, revision),
        onSuccess: setValidation,
    });
    const applyMutation = useMutation({
        mutationFn: () => {
            if (validation === null) throw new Error("Validate the policy first.");
            return applyQuota(validation);
        },
        onSuccess: async () => {
            await queryClient.invalidateQueries({ queryKey: ["management-snapshot"] });
            await queryClient.invalidateQueries({ queryKey: ["management-directory"] });
            onClose();
        },
    });

    return (
        <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
            <DialogTitle>Configure hard limits</DialogTitle>
            <DialogContent>
                <Typography sx={{ fontWeight: 750 }}>{resourceName}</Typography>
                <Typography color="text.secondary" variant="body2" sx={{ mb: 2 }}>
                    {scope === "directory"
                        ? "Limits apply to this complete directory subtree, across every storage driver."
                        : "Limits count physical objects retained by this driver, including recoverable and reserved data."}
                </Typography>
                {!configurationEnabled && (
                    <Alert severity="info" sx={{ mb: 2 }}>
                        Configuration is read-only. Enable a short configuration session before
                        applying changes.
                    </Alert>
                )}
                <Stack spacing={2}>
                    {scope === "directory" ? (
                        <>
                            <TextField
                                label="Maximum logical bytes"
                                value={maxLogicalBytes}
                                disabled={validation !== null}
                                onChange={(event) => setMaxLogicalBytes(event.target.value)}
                                helperText="Blank means unlimited. Counts active plaintext bytes in the subtree."
                                inputMode="numeric"
                            />
                            <TextField
                                label="Maximum file count"
                                value={maxFileCount}
                                disabled={validation !== null}
                                onChange={(event) => setMaxFileCount(event.target.value)}
                                helperText="Blank means unlimited. Concurrent uploads reserve file slots."
                                inputMode="numeric"
                            />
                            <TextField
                                label="Maximum bytes per file"
                                value={maxFileBytes}
                                disabled={validation !== null}
                                onChange={(event) => setMaxFileBytes(event.target.value)}
                                helperText="Blank means unlimited. The strictest inherited limit wins."
                                inputMode="numeric"
                            />
                        </>
                    ) : (
                        <>
                            <TextField
                                label="Maximum physical bytes"
                                value={maxPhysicalBytes}
                                disabled={validation !== null}
                                onChange={(event) => setMaxPhysicalBytes(event.target.value)}
                                helperText="Blank means unlimited. Includes encryption overhead and data awaiting GC."
                                inputMode="numeric"
                            />
                            <TextField
                                label="Maximum physical objects"
                                value={maxObjectCount}
                                disabled={validation !== null}
                                onChange={(event) => setMaxObjectCount(event.target.value)}
                                helperText="Blank means unlimited. Prepared uploads reserve one object."
                                inputMode="numeric"
                            />
                        </>
                    )}
                </Stack>
                {(validateMutation.isError || applyMutation.isError) && (
                    <Alert severity="error" sx={{ mt: 2 }}>
                        {errorMessage(validateMutation.error ?? applyMutation.error)}
                    </Alert>
                )}
                {validation !== null && (
                    <Alert severity="warning" sx={{ mt: 2 }}>
                        Validated until {formatDate(validation.validation_expires_at)}. Lowering a
                        limit never deletes existing data.
                    </Alert>
                )}
            </DialogContent>
            <DialogActions>
                <Button onClick={onClose}>Cancel</Button>
                {!configurationEnabled ? (
                    <Button onClick={onRequestConfiguration}>Enable changes</Button>
                ) : validation === null ? (
                    <Button
                        variant="contained"
                        disabled={!valid || validateMutation.isPending}
                        onClick={() => validateMutation.mutate()}
                    >
                        Validate policy
                    </Button>
                ) : (
                    <Button
                        color="warning"
                        variant="contained"
                        disabled={applyMutation.isPending}
                        onClick={() => applyMutation.mutate()}
                    >
                        Apply validated limits
                    </Button>
                )}
            </DialogActions>
        </Dialog>
    );
}
