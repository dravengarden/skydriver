import LockOpenOutlinedIcon from "@mui/icons-material/LockOpenOutlined";
import LockOutlinedIcon from "@mui/icons-material/LockOutlined";
import { Alert, Button, Paper, Stack, Typography } from "@mui/material";
import type { ConfigurationSession } from "../../api/client";
import { PageHeading, formatDate } from "./shared";

export function SettingsPage({
    configuration,
    onEnable,
    onDisable,
}: {
    configuration: ConfigurationSession | undefined;
    onEnable: () => void;
    onDisable: () => void;
}) {
    const enabled = configuration?.enabled === true;
    return (
        <>
            <PageHeading
                title="Settings"
                description="Review effective configuration before entering a short-lived mutation session."
            />
            <Alert severity={enabled ? "warning" : "info"} sx={{ mb: 2 }}>
                {enabled
                    ? `Configuration changes are enabled until ${formatDate(configuration.expires_at)}.`
                    : "Carrack is read-only in this browser. Viewing metadata never enables mutations."}
            </Alert>
            <Paper variant="outlined" sx={{ p: 3 }}>
                <Stack
                    direction={{ xs: "column", sm: "row" }}
                    sx={{ alignItems: { sm: "center" }, justifyContent: "space-between", gap: 2 }}
                >
                    <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }}>
                        {enabled ? <LockOpenOutlinedIcon color="warning" /> : <LockOutlinedIcon />}
                        <div>
                            <Typography sx={{ fontWeight: 800 }}>
                                {enabled ? "Changes enabled" : "Read-only mode"}
                            </Typography>
                            <Typography color="text.secondary" variant="body2">
                                Reauthentication grants configuration authority, never file
                                plaintext access.
                            </Typography>
                        </div>
                    </Stack>
                    <Button
                        variant={enabled ? "outlined" : "contained"}
                        color={enabled ? "warning" : "primary"}
                        onClick={enabled ? onDisable : onEnable}
                    >
                        {enabled ? "Return to read only" : "Enable changes"}
                    </Button>
                </Stack>
            </Paper>
            <Paper variant="outlined" sx={{ p: 3, mt: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 800 }}>
                    Safe configuration workflow
                </Typography>
                <Typography color="text.secondary" variant="body2" sx={{ mt: 1 }}>
                    Edits remain local drafts until server validation returns a normalized diff and
                    validation digest. Apply revalidates the exact desired state against its
                    observed revision in one transaction. The CLI uses the same protocol.
                </Typography>
            </Paper>
        </>
    );
}
