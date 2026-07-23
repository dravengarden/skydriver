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
import { useEffect, useState, type FormEvent } from "react";
import { SkydriverMark } from "../brand/SkydriverLogo";
import { SkyBackdrop } from "../brand/SkyBackdrop";
import { CardeaLoginForm } from "./CardeaLoginForm";
import type { CardeaLoginSubmitDetail } from "@dravengarden/cardea-consumer-ui";

interface LoginPageProps {
    readonly environment: string;
    readonly operatorAccount: string;
    readonly pending: boolean;
    readonly error: boolean;
    readonly onLogin: (account: string, password: string) => void;
}

const ERROR_RETRY_SECONDS = 60;

export function LoginPage({
    environment,
    operatorAccount,
    pending,
    error,
    onLogin,
}: LoginPageProps) {
    const cardeaEnabled = environment === "dev";
    const [savedIdentity, setSavedIdentity] = useState(operatorAccount);
    const [identityError, setIdentityError] = useState(false);
    const [password, setPassword] = useState("");
    const [cardeaState, setCardeaState] = useState<
        "idle" | "starting" | "waiting" | "expired" | "denied" | "cancelled" | "error"
    >("idle");
    const [cardeaExpiresAt, setCardeaExpiresAt] = useState<number | null>(null);
    const [cardeaRetryAt, setCardeaRetryAt] = useState<number | null>(null);
    const [clock, setClock] = useState(() => Date.now());

    const remainingApprovalSeconds =
        cardeaExpiresAt === null ? null : Math.max(0, Math.ceil((cardeaExpiresAt - clock) / 1_000));
    const remainingApprovalLabel =
        remainingApprovalSeconds === null
            ? null
            : `${Math.floor(remainingApprovalSeconds / 60)}:${String(remainingApprovalSeconds % 60).padStart(2, "0")}`;
    const retrySeconds =
        cardeaRetryAt === null ? 0 : Math.max(0, Math.ceil((cardeaRetryAt - clock) / 1_000));

    useEffect(() => {
        if (cardeaState !== "waiting" || cardeaExpiresAt === null) return;
        const updateClock = () => {
            const now = Date.now();
            setClock(now);
            if (now >= cardeaExpiresAt) setCardeaState("expired");
        };
        updateClock();
        const interval = globalThis.setInterval(updateClock, 1_000);
        globalThis.addEventListener("focus", updateClock);
        document.addEventListener("visibilitychange", updateClock);
        return () => {
            globalThis.clearInterval(interval);
            globalThis.removeEventListener("focus", updateClock);
            document.removeEventListener("visibilitychange", updateClock);
        };
    }, [cardeaExpiresAt, cardeaState]);

    useEffect(() => {
        if (cardeaRetryAt === null) return;
        const updateClock = () => setClock(Date.now());
        updateClock();
        const interval = globalThis.setInterval(updateClock, 1_000);
        return () => globalThis.clearInterval(interval);
    }, [cardeaRetryAt]);

    useEffect(() => {
        if (cardeaState !== "waiting") return;
        let active = true;
        let controller: AbortController | null = null;
        const poll = async () => {
            const requestController = new AbortController();
            controller = requestController;
            try {
                const response = await fetch("/api/auth/cardea/status", {
                    credentials: "same-origin",
                    headers: { Accept: "application/json" },
                    signal: requestController.signal,
                });
                if (!active) return;
                if (!response.ok) throw new Error("approval status unavailable");
                const result = (await response.json()) as {
                    authenticated?: boolean;
                    status?: string;
                    expires_at?: number;
                };
                if (typeof result.expires_at === "number") {
                    setCardeaExpiresAt(result.expires_at * 1_000);
                }
                if (result.authenticated === true) {
                    globalThis.location.reload();
                } else if (result.status === "expired") {
                    setCardeaState("expired");
                } else if (result.status === "denied") {
                    setCardeaState("denied");
                } else if (result.status === "cancelled") {
                    setCardeaState("cancelled");
                } else if (result.status !== "pending") {
                    setCardeaRetryAt(Date.now() + ERROR_RETRY_SECONDS * 1_000);
                    setCardeaState("error");
                } else {
                    void poll();
                }
            } catch {
                if (active && !requestController.signal.aborted) {
                    setCardeaRetryAt(Date.now() + ERROR_RETRY_SECONDS * 1_000);
                    setCardeaState("error");
                }
            }
        };
        void poll();
        return () => {
            active = false;
            controller?.abort();
        };
    }, [cardeaState]);

    async function beginCardeaLogin(detail: CardeaLoginSubmitDetail) {
        if (cardeaState === "starting" || cardeaState === "waiting" || retrySeconds > 0) {
            return;
        }
        setCardeaState("starting");
        setCardeaExpiresAt(null);
        try {
            const response = await fetch("/api/auth/cardea/start", {
                method: "POST",
                credentials: "same-origin",
                headers: { Accept: "application/json", "Content-Type": "application/json" },
                body: JSON.stringify({ email: detail.email, deviceId: detail.deviceId }),
            });
            if (!response.ok) {
                const retryAfter = Number.parseInt(response.headers.get("Retry-After") ?? "", 10);
                setCardeaRetryAt(
                    Date.now() +
                        (Number.isFinite(retryAfter) && retryAfter > 0
                            ? retryAfter
                            : ERROR_RETRY_SECONDS) *
                            1_000,
                );
                throw new Error("approval start unavailable");
            }
            const result = (await response.json()) as { expires_at?: number };
            if (typeof result.expires_at !== "number" || !Number.isFinite(result.expires_at)) {
                throw new Error("approval expiry unavailable");
            }
            setClock(Date.now());
            setCardeaRetryAt(null);
            setCardeaExpiresAt(result.expires_at * 1_000);
            setCardeaState("waiting");
        } catch {
            setCardeaRetryAt((current) => current ?? Date.now() + ERROR_RETRY_SECONDS * 1_000);
            setCardeaState("error");
        }
    }

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
                data-cardea-consumer-ui="v1"
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
                            {cardeaEnabled
                                ? "Use Cardea to prove your identity. Skydriver keeps its own authorization and session."
                                : "Enter this environment's operator account and credential."}
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
                    {cardeaEnabled ? null : (
                        <TextField
                            label="Saved login"
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
                                    : "This environment-scoped account keeps saved credentials separate."
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
                    )}

                    {cardeaEnabled ? null : (
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
                    )}
                    {cardeaEnabled ? (
                        <CardeaLoginForm
                            state={cardeaState}
                            retrySeconds={retrySeconds}
                            remainingLabel={remainingApprovalLabel}
                            onSubmit={(detail) => void beginCardeaLogin(detail)}
                        />
                    ) : (
                        <Button
                            type="submit"
                            variant="contained"
                            size="large"
                            disabled={pending || savedIdentity === "" || password === ""}
                            startIcon={
                                pending ? <CircularProgress size={18} /> : <LockOutlinedIcon />
                            }
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
                    )}
                    <Typography
                        variant="caption"
                        sx={{ color: "#68808c", textAlign: "center", letterSpacing: "0.02em" }}
                    >
                        {cardeaEnabled
                            ? "Cardea identity · Skydriver authorization · Revocable session"
                            : "Environment-scoped access · Revocable session"}
                    </Typography>
                </Stack>
            </Paper>
        </Box>
    );
}
