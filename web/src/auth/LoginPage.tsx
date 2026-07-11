import LockOutlinedIcon from "@mui/icons-material/LockOutlined";
import {
    Alert,
    Box,
    Button,
    CircularProgress,
    Paper,
    Stack,
    TextField,
    Typography,
} from "@mui/material";
import { useState, type FormEvent } from "react";

interface LoginPageProps {
    readonly pending: boolean;
    readonly error: boolean;
    readonly onLogin: (username: string, password: string) => void;
}

export function LoginPage({ pending, error, onLogin }: LoginPageProps) {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");

    function submit(event: FormEvent<HTMLFormElement>) {
        event.preventDefault();
        onLogin(username, password);
    }

    return (
        <Box
            component="main"
            sx={{
                minHeight: "100dvh",
                display: "grid",
                placeItems: "center",
                px: 2,
                background:
                    "radial-gradient(circle at 20% 10%, rgba(27, 104, 255, 0.22), transparent 36%), #08111f",
            }}
        >
            <Paper
                component="form"
                onSubmit={submit}
                elevation={0}
                sx={{ width: "100%", maxWidth: 420, p: { xs: 3, sm: 5 }, border: "1px solid" }}
            >
                <Stack spacing={3}>
                    <Box>
                        <Typography
                            variant="overline"
                            color="primary.main"
                            sx={{ fontWeight: 800 }}
                        >
                            CARRACK
                        </Typography>
                        <Typography variant="h4" sx={{ fontWeight: 800 }}>
                            Control plane
                        </Typography>
                        <Typography color="text.secondary" sx={{ mt: 1 }}>
                            Sign in with the preset operator account.
                        </Typography>
                    </Box>

                    {error ? <Alert severity="error">Invalid username or password.</Alert> : null}

                    <TextField
                        label="Username"
                        autoComplete="username"
                        value={username}
                        onChange={(event) => setUsername(event.target.value)}
                        required
                        fullWidth
                    />
                    <TextField
                        label="Password"
                        type="password"
                        autoComplete="current-password"
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        required
                        fullWidth
                    />
                    <Button
                        type="submit"
                        variant="contained"
                        size="large"
                        disabled={pending}
                        startIcon={pending ? <CircularProgress size={18} /> : <LockOutlinedIcon />}
                    >
                        Sign in
                    </Button>
                </Stack>
            </Paper>
        </Box>
    );
}
