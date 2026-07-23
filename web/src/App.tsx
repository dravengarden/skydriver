import { Box, CircularProgress, CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Suspense, lazy } from "react";
import { fetchHealth, fetchSession, login, logout } from "./api/client";
import { LoginPage } from "./auth/LoginPage";

const Dashboard = lazy(() =>
    import("./dashboard/Dashboard").then(({ Dashboard: component }) => ({ default: component })),
);

const theme = createTheme({
    cssVariables: true,
    palette: {
        mode: "light",
        primary: { main: "#3b82f6" },
        background: { default: "#f6f8fb" },
    },
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
    const operatorAccount = health.data?.operator_account ?? "";
    const loginMutation = useMutation({
        mutationFn: login,
        onSuccess: (value) => queryClient.setQueryData(["session"], value),
    });
    const logoutMutation = useMutation({
        mutationFn: logout,
        onSuccess: (value) => {
            queryClient.setQueryData(["session"], value);
            queryClient.removeQueries({
                predicate: (query) => {
                    const scope = query.queryKey[0];
                    return (
                        typeof scope === "string" &&
                        (scope.startsWith("management-") ||
                            scope.startsWith("transfer-") ||
                            scope === "configuration-session")
                    );
                },
            });
        },
    });

    let content;
    if (health.isPending || session.isPending) {
        content = (
            <Box
                role="status"
                aria-label="Loading control plane"
                sx={{ minHeight: "100dvh", display: "grid", placeItems: "center" }}
            >
                <CircularProgress size={30} />
            </Box>
        );
    } else if (health.isError || session.isError) {
        content = (
            <Box
                role="alert"
                sx={{ minHeight: "100dvh", display: "grid", placeItems: "center", px: 3 }}
            >
                Control plane status is unavailable. Try refreshing the page.
            </Box>
        );
    } else if (session.data?.authenticated) {
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
                            bgcolor: "background.default",
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
                key={`${environment}:${operatorAccount}`}
                environment={environment}
                operatorAccount={operatorAccount}
                pending={loginMutation.isPending}
                error={loginMutation.isError}
                onLogin={(account, password) => loginMutation.mutate({ account, password })}
            />
        );
    }

    return (
        <ThemeProvider theme={theme}>
            <CssBaseline />
            {content}
        </ThemeProvider>
    );
}
