import { Box, CircularProgress, CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Suspense, lazy } from "react";
import { fetchHealth, fetchSession, login, logout } from "./api/client";
import { LoginPage } from "./auth/LoginPage";

const Dashboard = lazy(() =>
    import("./dashboard/Dashboard").then(({ Dashboard: component }) => ({ default: component })),
);

const theme = createTheme({
    colorSchemes: { dark: true },
    cssVariables: true,
    palette: { primary: { main: "#3b82f6" } },
    shape: { borderRadius: 12 },
    typography: {
        fontFamily:
            'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    },
});

export function App() {
    const queryClient = useQueryClient();
    const health = useQuery({ queryKey: ["health"], queryFn: fetchHealth });
    const session = useQuery({ queryKey: ["session"], queryFn: fetchSession });
    const environment = health.data?.environment ?? "unknown";
    const loginMutation = useMutation({
        mutationFn: login,
        onSuccess: (value) => queryClient.setQueryData(["session"], value),
    });
    const logoutMutation = useMutation({
        mutationFn: logout,
        onSuccess: (value) => {
            queryClient.setQueryData(["session"], value);
            queryClient.removeQueries({ queryKey: ["management-activity"] });
        },
    });

    let content;
    if (session.data?.authenticated) {
        content = (
            <Suspense
                fallback={
                    <Box
                        role="status"
                        aria-label="Loading control plane"
                        sx={{
                            minHeight: "100dvh",
                            display: "grid",
                            placeItems: "center",
                            bgcolor: "#f6f8fb",
                        }}
                    >
                        <CircularProgress size={30} />
                    </Box>
                }
            >
                <Dashboard environment={environment} onLogout={() => logoutMutation.mutate()} />
            </Suspense>
        );
    } else {
        content = (
            <LoginPage
                environment={environment}
                pending={loginMutation.isPending}
                error={loginMutation.isError}
                onLogin={(password) => loginMutation.mutate(password)}
            />
        );
    }

    return (
        <ThemeProvider theme={theme} defaultMode="dark">
            <CssBaseline />
            {content}
        </ThemeProvider>
    );
}
