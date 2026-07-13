import AdminPanelSettingsOutlinedIcon from "@mui/icons-material/AdminPanelSettingsOutlined";
import DashboardOutlinedIcon from "@mui/icons-material/DashboardOutlined";
import FolderOutlinedIcon from "@mui/icons-material/FolderOutlined";
import KeyOutlinedIcon from "@mui/icons-material/KeyOutlined";
import LogoutOutlinedIcon from "@mui/icons-material/LogoutOutlined";
import SettingsOutlinedIcon from "@mui/icons-material/SettingsOutlined";
import StorageOutlinedIcon from "@mui/icons-material/StorageOutlined";
import TimelineOutlinedIcon from "@mui/icons-material/TimelineOutlined";
import {
    Alert,
    AppBar,
    Box,
    Button,
    Chip,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Divider,
    List,
    ListItemButton,
    ListItemIcon,
    ListItemText,
    Snackbar,
    Stack,
    TextField,
    Toolbar,
    Typography,
} from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import {
    disableConfiguration,
    enableConfiguration,
    fetchConfigurationSession,
    fetchManagementEventCursor,
    fetchManagementSnapshot,
} from "../api/client";
import { CarrackMark } from "../brand/CarrackLogo";
import { AccessPage } from "./pages/AccessPage";
import { ActivityPage } from "./pages/ActivityPage";
import { DriversPage } from "./pages/DriversPage";
import { FilesPage } from "./pages/FilesPage";
import { OverviewPage } from "./pages/OverviewPage";
import { SettingsPage } from "./pages/SettingsPage";

interface DashboardProps {
    readonly environment: string;
    readonly onLogout: () => void;
}

type Page = "overview" | "files" | "drivers" | "access" | "activity" | "settings";

const navigation: ReadonlyArray<{
    readonly id: Page;
    readonly label: string;
    readonly icon: React.ReactNode;
}> = [
    { id: "overview", label: "Overview", icon: <DashboardOutlinedIcon /> },
    { id: "files", label: "Files", icon: <FolderOutlinedIcon /> },
    { id: "drivers", label: "Drivers", icon: <StorageOutlinedIcon /> },
    { id: "access", label: "Access", icon: <KeyOutlinedIcon /> },
    { id: "activity", label: "Activity", icon: <TimelineOutlinedIcon /> },
    { id: "settings", label: "Settings", icon: <SettingsOutlinedIcon /> },
];

export function Dashboard({ environment, onLogout }: DashboardProps) {
    const queryClient = useQueryClient();
    const [page, setPage] = useState<Page>("overview");
    const [configurationDialogOpen, setConfigurationDialogOpen] = useState(false);
    const [credential, setCredential] = useState("");
    const [changeNoticeOpen, setChangeNoticeOpen] = useState(false);
    const previousCursor = useRef<number | null>(null);
    const management = useQuery({
        queryKey: ["management-snapshot"],
        queryFn: fetchManagementSnapshot,
        staleTime: Number.POSITIVE_INFINITY,
    });
    const eventCursor = useQuery({
        queryKey: ["management-event-cursor"],
        queryFn: fetchManagementEventCursor,
        refetchInterval: 3_000,
    });
    const configuration = useQuery({
        queryKey: ["configuration-session"],
        queryFn: fetchConfigurationSession,
        refetchInterval: 30_000,
    });
    const enableMutation = useMutation({
        mutationFn: enableConfiguration,
        onSuccess: (value) => {
            queryClient.setQueryData(["configuration-session"], value);
            setCredential("");
            setConfigurationDialogOpen(false);
        },
    });
    const disableMutation = useMutation({
        mutationFn: disableConfiguration,
        onSuccess: (value) => queryClient.setQueryData(["configuration-session"], value),
    });

    useEffect(() => {
        const cursor = eventCursor.data?.event_cursor;
        if (cursor === undefined) {
            return;
        }
        if (previousCursor.current !== null && previousCursor.current !== cursor) {
            setChangeNoticeOpen(true);
            void queryClient.invalidateQueries({
                queryKey: ["management-snapshot"],
            });
            void queryClient.invalidateQueries({
                queryKey: ["management-directory"],
            });
        }
        previousCursor.current = cursor;
    }, [eventCursor.data?.event_cursor, queryClient]);

    const configurationEnabled = configuration.data?.enabled === true;
    const content = (() => {
        switch (page) {
            case "overview":
                return <OverviewPage management={management} onNavigate={setPage} />;
            case "files":
                return <FilesPage management={management} />;
            case "drivers":
                return (
                    <DriversPage
                        management={management}
                        configurationEnabled={configurationEnabled}
                        onRequestConfiguration={() => setConfigurationDialogOpen(true)}
                    />
                );
            case "access":
                return (
                    <AccessPage
                        management={management}
                        configurationEnabled={configurationEnabled}
                        onRequestConfiguration={() => setConfigurationDialogOpen(true)}
                    />
                );
            case "activity":
                return <ActivityPage />;
            case "settings":
                return (
                    <SettingsPage
                        configuration={configuration.data}
                        onEnable={() => setConfigurationDialogOpen(true)}
                        onDisable={() => disableMutation.mutate()}
                    />
                );
        }
    })();

    return (
        <Box component="main" sx={{ minHeight: "100dvh", bgcolor: "#f6f8fb" }}>
            <AppBar position="sticky" color="inherit" elevation={0}>
                <Toolbar
                    sx={{
                        borderBottom: "1px solid",
                        borderColor: "divider",
                        gap: { xs: 1, sm: 2 },
                        px: { xs: 1.5, sm: 3 },
                    }}
                >
                    <Stack
                        direction="row"
                        spacing={1.2}
                        sx={{
                            alignItems: "center",
                            minWidth: { xs: 0, sm: 210 },
                        }}
                    >
                        <CarrackMark width={32} height={32} title="Carrack" />
                        <Box>
                            <Typography
                                sx={{
                                    fontWeight: 900,
                                    letterSpacing: "0.12em",
                                    lineHeight: 1,
                                }}
                            >
                                CARRACK
                            </Typography>
                            <Typography
                                color="text.secondary"
                                variant="caption"
                                sx={{ display: { xs: "none", sm: "block" } }}
                            >
                                Control plane
                            </Typography>
                        </Box>
                    </Stack>
                    <Stack
                        direction="row"
                        spacing={1}
                        sx={{ ml: "auto", alignItems: "center", minWidth: 0 }}
                    >
                        <Chip
                            label={environment.toUpperCase()}
                            color={environment === "prod" ? "error" : "info"}
                            size="small"
                        />
                        <Chip
                            icon={<AdminPanelSettingsOutlinedIcon />}
                            label={configurationEnabled ? "CHANGES ENABLED" : "READ ONLY"}
                            color={configurationEnabled ? "warning" : "default"}
                            size="small"
                            aria-label={
                                configurationEnabled
                                    ? "Configuration changes enabled"
                                    : "Read-only configuration"
                            }
                            onClick={
                                configurationEnabled
                                    ? () => setPage("settings")
                                    : () => setConfigurationDialogOpen(true)
                            }
                            sx={{
                                width: { xs: 34, sm: "auto" },
                                "& .MuiChip-label": {
                                    display: { xs: "none", sm: "block" },
                                },
                                "& .MuiChip-icon": {
                                    mx: { xs: "auto", sm: undefined },
                                },
                            }}
                        />
                        <Button
                            color="inherit"
                            startIcon={<LogoutOutlinedIcon />}
                            onClick={onLogout}
                            sx={{ display: { xs: "none", sm: "inline-flex" } }}
                        >
                            Logout
                        </Button>
                    </Stack>
                </Toolbar>
            </AppBar>

            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: {
                        xs: "minmax(0, 1fr)",
                        md: "240px minmax(0, 1fr)",
                    },
                }}
            >
                <Box
                    component="nav"
                    sx={{
                        minHeight: { md: "calc(100dvh - 65px)" },
                        borderRight: { md: "1px solid" },
                        borderBottom: { xs: "1px solid", md: 0 },
                        borderColor: "divider",
                        bgcolor: "background.paper",
                        p: { xs: 1, md: 2 },
                        minWidth: 0,
                        maxWidth: { xs: "100vw", md: "none" },
                        overflow: "hidden",
                    }}
                >
                    <List
                        disablePadding
                        sx={{
                            display: { xs: "flex", md: "block" },
                            gap: 0.5,
                            overflowX: "auto",
                            width: "100%",
                            minWidth: 0,
                        }}
                    >
                        {navigation.map((item) => (
                            <ListItemButton
                                key={item.id}
                                selected={page === item.id}
                                onClick={() => setPage(item.id)}
                                sx={{
                                    borderRadius: 2,
                                    minWidth: { xs: "max-content", md: 0 },
                                }}
                            >
                                <ListItemIcon sx={{ minWidth: 36 }}>{item.icon}</ListItemIcon>
                                <ListItemText primary={item.label} />
                            </ListItemButton>
                        ))}
                    </List>
                    <Divider sx={{ my: 2, display: { xs: "none", md: "block" } }} />
                    <Box sx={{ px: 1, display: { xs: "none", md: "block" } }}>
                        <Typography color="text.secondary" variant="caption">
                            Payload bytes move directly between clients and storage drivers.
                        </Typography>
                    </Box>
                </Box>
                <Box sx={{ minWidth: 0, p: { xs: 2, sm: 3, lg: 5 } }}>{content}</Box>
            </Box>

            <Dialog
                open={configurationDialogOpen}
                onClose={() => !enableMutation.isPending && setConfigurationDialogOpen(false)}
                fullWidth
                maxWidth="xs"
            >
                <DialogTitle>Enable configuration changes</DialogTitle>
                <DialogContent>
                    <Typography color="text.secondary" variant="body2" sx={{ mb: 2 }}>
                        Re-enter the operator credential. The server grants a separate 15-minute
                        configuration session; file-content access is not granted.
                    </Typography>
                    {enableMutation.isError && (
                        <Alert severity="error" sx={{ mb: 2 }}>
                            The server rejected this credential.
                        </Alert>
                    )}
                    <TextField
                        autoFocus
                        fullWidth
                        label="Operator credential"
                        type="password"
                        value={credential}
                        onChange={(event) => setCredential(event.target.value)}
                        onKeyDown={(event) => {
                            if (event.key === "Enter" && credential.length > 0) {
                                enableMutation.mutate(credential);
                            }
                        }}
                    />
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => setConfigurationDialogOpen(false)}>Cancel</Button>
                    <Button
                        variant="contained"
                        disabled={credential.length === 0 || enableMutation.isPending}
                        onClick={() => enableMutation.mutate(credential)}
                    >
                        Enable for 15 minutes
                    </Button>
                </DialogActions>
            </Dialog>

            <Snackbar
                open={changeNoticeOpen}
                autoHideDuration={6_000}
                onClose={() => setChangeNoticeOpen(false)}
                message="Carrack state changed. The latest server state is now loaded."
            />
        </Box>
    );
}
