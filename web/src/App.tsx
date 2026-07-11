import { CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchSession, login, logout } from "./api/client";
import { LoginPage } from "./auth/LoginPage";
import { Dashboard } from "./dashboard/Dashboard";

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
    const session = useQuery({ queryKey: ["session"], queryFn: fetchSession });
    const loginMutation = useMutation({
        mutationFn: ({
            username,
            password,
        }: {
            readonly username: string;
            readonly password: string;
        }) => login(username, password),
        onSuccess: (value) => queryClient.setQueryData(["session"], value),
    });
    const logoutMutation = useMutation({
        mutationFn: logout,
        onSuccess: (value) => {
            queryClient.setQueryData(["session"], value);
            queryClient.removeQueries({ queryKey: ["summary"] });
            queryClient.removeQueries({ queryKey: ["live-components"] });
        },
    });

    let content;
    if (session.data?.authenticated && session.data.username !== null) {
        content = (
            <Dashboard username={session.data.username} onLogout={() => logoutMutation.mutate()} />
        );
    } else {
        content = (
            <LoginPage
                pending={loginMutation.isPending}
                error={loginMutation.isError}
                onLogin={(username, password) => loginMutation.mutate({ username, password })}
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
