import LockOutlinedIcon from "@mui/icons-material/LockOutlined";
import {
    Alert,
    Box,
    Button,
    Chip,
    CircularProgress,
    Paper,
    Stack,
    TextField,
    Typography,
} from "@mui/material";
import { useState, type FormEvent } from "react";
import { SkydriverMark } from "../brand/SkydriverLogo";
import { SkyBackdrop } from "../brand/SkyBackdrop";

interface LoginPageProps {
    readonly environment: string;
    readonly operatorAccount: string;
    readonly pending: boolean;
    readonly error: boolean;
    readonly onLogin: (account: string, password: string) => void;
}

export function LoginPage({
    environment,
    operatorAccount,
    pending,
    error,
    onLogin,
}: LoginPageProps) {
    const [savedIdentity, setSavedIdentity] = useState(operatorAccount);
    const [identityError, setIdentityError] = useState(false);
    const [password, setPassword] = useState("");

    function submit(event: FormEvent<HTMLFormElement>) {
        event.preventDefault();
        if (savedIdentity !== operatorAccount) {
            setIdentityError(true);
        } else if (password !== "") {
            setIdentityError(false);
            onLogin(operatorAccount, password);
        }
    }

    return (
        <Box
            component="main"
            sx={{
                minHeight: "100dvh",
                display: "grid",
                placeItems: "center",
                px: 2,
                py: 4,
                position: "relative",
                overflow: "hidden",
            }}
        >
            <SkyBackdrop />
            <Paper
                component="form"
                autoComplete="on"
                name={`skydriver-${environment}-login`}
                onSubmit={submit}
                elevation={0}
                sx={{
                    width: "100%",
                    maxWidth: 448,
                    p: { xs: 3, sm: 4 },
                    position: "relative",
                    zIndex: 1,
                    overflow: "hidden",
                    color: "#071522",
                    bgcolor: "rgba(247, 251, 251, 0.9)",
                    border: "1px solid rgba(224, 243, 245, 0.7)",
                    borderRadius: 4,
                    boxShadow:
                        "0 36px 90px rgba(4, 20, 39, 0.32), 0 8px 28px rgba(4, 20, 39, 0.18)",
                    backdropFilter: "blur(24px) saturate(108%)",
                }}
            >
                <Stack spacing={2.75}>
                    <Box>
                        <Stack
                            direction="row"
                            sx={{ alignItems: "center", justifyContent: "space-between" }}
                        >
                            <Stack direction="row" spacing={1.25} sx={{ alignItems: "center" }}>
                                <SkydriverMark width={42} height={42} title="Skydriver" />
                                <Box>
                                    <Typography
                                        variant="overline"
                                        sx={{
                                            display: "block",
                                            color: "#0a3957",
                                            fontWeight: 900,
                                            letterSpacing: "0.16em",
                                            lineHeight: 1.1,
                                        }}
                                    >
                                        SKYDRIVER
                                    </Typography>
                                    <Typography
                                        variant="caption"
                                        sx={{ color: "#557181", letterSpacing: "0.04em" }}
                                    >
                                        VIRTUAL FILE SYSTEM
                                    </Typography>
                                </Box>
                            </Stack>
                            <Chip
                                label={environment.toUpperCase()}
                                color={environment === "prod" ? "error" : "info"}
                                size="small"
                                sx={{ fontWeight: 800 }}
                            />
                        </Stack>
                        <Typography
                            variant="h4"
                            sx={{ mt: 3.5, fontWeight: 850, letterSpacing: "-0.04em" }}
                        >
                            Control plane
                        </Typography>
                        <Typography sx={{ mt: 0.75, color: "#536d7b", lineHeight: 1.55 }}>
                            Enter the operator account and credential configured for this
                            environment.
                        </Typography>
                    </Box>

                    {error ? (
                        <Alert
                            severity="error"
                            sx={{ border: "1px solid rgba(198, 65, 65, 0.12)", borderRadius: 2.5 }}
                        >
                            Authentication was rejected. Try again.
                        </Alert>
                    ) : null}

                    <TextField
                        label="Operator account"
                        autoComplete={`section-skydriver-${environment} username`}
                        value={savedIdentity}
                        onChange={(event) => {
                            setSavedIdentity(event.target.value);
                            setIdentityError(false);
                        }}
                        required
                        fullWidth
                        autoFocus
                        error={identityError}
                        helperText={
                            identityError
                                ? `Use ${operatorAccount} for this environment.`
                                : "The account is configured by the deployment owner."
                        }
                        slotProps={{
                            htmlInput: {
                                id: `skydriver-${environment}-username`,
                                name: "username",
                                autoCapitalize: "none",
                                spellCheck: false,
                            },
                        }}
                    />

                    <TextField
                        label="Operator credential"
                        type="password"
                        autoComplete={`section-skydriver-${environment} current-password`}
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        required
                        fullWidth
                        slotProps={{
                            htmlInput: {
                                id: `skydriver-${environment}-password`,
                                name: "password",
                            },
                        }}
                        sx={{
                            "& .MuiInputLabel-root": { color: "#58717e" },
                            "& .MuiOutlinedInput-root": {
                                bgcolor: "rgba(255, 255, 255, 0.72)",
                                "& fieldset": { borderColor: "rgba(38, 82, 104, 0.27)" },
                                "&:hover fieldset": { borderColor: "rgba(20, 127, 161, 0.62)" },
                            },
                        }}
                    />

                    <Button
                        type="submit"
                        variant="contained"
                        size="large"
                        disabled={pending || savedIdentity === "" || password === ""}
                        startIcon={pending ? <CircularProgress size={18} /> : <LockOutlinedIcon />}
                        sx={{
                            minHeight: 48,
                            fontWeight: 850,
                            letterSpacing: "0.02em",
                            background: "linear-gradient(110deg, #087fa6, #256cf0)",
                            boxShadow: "0 10px 24px rgba(14, 104, 181, 0.27)",
                            "&:hover": {
                                background: "linear-gradient(110deg, #076f91, #1f5fd6)",
                                boxShadow: "0 12px 28px rgba(14, 104, 181, 0.36)",
                            },
                        }}
                    >
                        Enter control plane
                    </Button>

                    <Typography
                        variant="caption"
                        sx={{ color: "#68808c", textAlign: "center", letterSpacing: "0.02em" }}
                    >
                        Environment-scoped access · Revocable session
                    </Typography>
                </Stack>
            </Paper>
        </Box>
    );
}
