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
import { CarrackMark } from "../brand/CarrackLogo";
import { OceanBackdrop } from "../brand/OceanBackdrop";
import { passwordManagerIdentity, resolvePasswordManagerIdentity } from "./loginIdentity";

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
    const expectedIdentity = passwordManagerIdentity(operatorAccount, environment);
    const [savedIdentity, setSavedIdentity] = useState(expectedIdentity);
    const [identityError, setIdentityError] = useState(false);
    const [password, setPassword] = useState("");

    function submit(event: FormEvent<HTMLFormElement>) {
        event.preventDefault();
        const account = resolvePasswordManagerIdentity(savedIdentity, operatorAccount, environment);
        if (account === null) {
            setIdentityError(true);
        } else if (password !== "") {
            setIdentityError(false);
            onLogin(account, password);
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
            <OceanBackdrop />
            <Paper
                component="form"
                onSubmit={submit}
                elevation={0}
                sx={{
                    width: "100%",
                    maxWidth: 430,
                    p: { xs: 3, sm: 4.5 },
                    position: "relative",
                    zIndex: 1,
                    overflow: "hidden",
                    color: "#071522",
                    bgcolor: "rgba(250, 252, 253, 0.94)",
                    border: "1px solid rgba(219, 242, 248, 0.68)",
                    boxShadow: "0 30px 90px rgba(0, 7, 16, 0.46)",
                    backdropFilter: "blur(18px) saturate(118%)",
                }}
            >
                <Stack spacing={3}>
                    <Box>
                        <Stack
                            direction="row"
                            sx={{ alignItems: "center", justifyContent: "space-between" }}
                        >
                            <Stack direction="row" spacing={1.25} sx={{ alignItems: "center" }}>
                                <CarrackMark width={42} height={42} title="Carrack" />
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
                                        CARRACK
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
                            sx={{ mt: 3, fontWeight: 850, letterSpacing: "-0.035em" }}
                        >
                            Control plane
                        </Typography>
                        <Typography sx={{ mt: 0.75, color: "#536d7b" }}>
                            Enter this environment's operator account and credential.
                        </Typography>
                    </Box>

                    {error ? (
                        <Alert severity="error">Invalid account or operator credential.</Alert>
                    ) : null}

                    <TextField
                        label="Saved login"
                        autoComplete={`section-carrack-${environment} username`}
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
                                ? `Use ${expectedIdentity} for this environment.`
                                : `Carrack account ${operatorAccount}; qualified so Safari keeps environments separate.`
                        }
                        slotProps={{
                            htmlInput: { autoCapitalize: "none", spellCheck: false },
                        }}
                    />

                    <TextField
                        label="Operator credential"
                        type="password"
                        autoComplete={`section-carrack-${environment} current-password`}
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        required
                        fullWidth
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
