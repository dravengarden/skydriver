import AccountCircleOutlinedIcon from "@mui/icons-material/AccountCircleOutlined";
import AdminPanelSettingsOutlinedIcon from "@mui/icons-material/AdminPanelSettingsOutlined";
import DashboardOutlinedIcon from "@mui/icons-material/DashboardOutlined";
import FolderOutlinedIcon from "@mui/icons-material/FolderOutlined";
import KeyOutlinedIcon from "@mui/icons-material/KeyOutlined";
import InsightsOutlinedIcon from "@mui/icons-material/InsightsOutlined";
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
    IconButton,
    List,
    ListItemButton,
    ListItemIcon,
    ListItemText,
    Menu,
    MenuItem,
    Snackbar,
    Stack,
    TextField,
    Toolbar,
    Typography,
} from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Suspense, lazy, useEffect, useRef, useState } from "react";
import {
    disableConfiguration,
    enableConfiguration,
    fetchConfigurationSession,
    fetchManagementEventCursor,
    fetchManagementSnapshot,
} from "../api/client";
import { SkydriverMark } from "../brand/SkydriverLogo";
import { OverviewPage } from "./pages/OverviewPage";

interface DashboardProps {
    readonly environment: string;
    readonly onLogout: () => void;
}

type Page = "overview" | "files" | "drivers" | "access" | "analytics" | "activity" | "settings";

const pageLoaders = {
    files: () => import("./pages/FilesPage"),
    drivers: () => import("./pages/DriversPage"),
    access: () => import("./pages/AccessPage"),
    analytics: () => import("./pages/AnalyticsPage"),
    activity: () => import("./pages/ActivityPage"),
    settings: () => import("./pages/SettingsPage"),
};

const FilesPage = lazy(() =>
    pageLoaders.files().then(({ FilesPage: component }) => ({ default: component })),
);
const DriversPage = lazy(() =>
    pageLoaders.drivers().then(({ DriversPage: component }) => ({ default: component })),
);
const AccessPage = lazy(() =>
    pageLoaders.access().then(({ AccessPage: component }) => ({ default: component })),
);
const AnalyticsPage = lazy(() =>
    pageLoaders.analytics().then(({ AnalyticsPage: component }) => ({ default: component })),
);
const ActivityPage = lazy(() =>
    pageLoaders.activity().then(({ ActivityPage: component }) => ({ default: component })),
);
const SettingsPage = lazy(() =>
    pageLoaders.settings().then(({ SettingsPage: component }) => ({ default: component })),
);

function preloadPage(page: Page) {
    if (page !== "overview") {
        void pageLoaders[page]();
    }
}

const navigation: ReadonlyArray<{
    readonly id: Page;
    readonly label: string;
    readonly icon: React.ReactNode;
}> = [
    { id: "overview", label: "Overview", icon: <DashboardOutlinedIcon /> },
    { id: "files", label: "Files", icon: <FolderOutlinedIcon /> },
    { id: "drivers", label: "Drivers", icon: <StorageOutlinedIcon /> },
    { id: "access", label: "Access", icon: <KeyOutlinedIcon /> },
    { id: "analytics", label: "Analytics", icon: <InsightsOutlinedIcon /> },
    { id: "activity", label: "Activity", icon: <TimelineOutlinedIcon /> },
    { id: "settings", label: "Settings", icon: <SettingsOutlinedIcon /> },
];

export function Dashboard({ environment, onLogout }: DashboardProps) {
    const queryClient = useQueryClient();
    const [page, setPage] = useState<Page>("overview");
    const [configurationDialogOpen, setConfigurationDialogOpen] = useState(false);
    const [mobileSessionMenuAnchor, setMobileSessionMenuAnchor] = useState<HTMLElement | null>(
        null,
    );
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
        refetchInterval: () => (document.visibilityState === "visible" ? 15_000 : false),
        refetchIntervalInBackground: false,
        refetchOnWindowFocus: true,
    });
    const configuration = useQuery({
        queryKey: ["configuration-session"],
        queryFn: fetchConfigurationSession,
        refetchInterval: (query) => (query.state.data?.enabled === true ? 30_000 : 120_000),
        refetchIntervalInBackground: false,
        refetchOnWindowFocus: true,
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
                return (
                    <FilesPage
                        management={management}
                        configurationEnabled={configurationEnabled}
                        onRequestConfiguration={() => setConfigurationDialogOpen(true)}
                    />
                );
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
            case "analytics":
                return <AnalyticsPage />;
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
        <Box component="main" sx={{ minHeight: "100dvh", bgcolor: "background.default" }}>
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
                        <SkydriverMark width={32} height={32} title="Skydriver" />
                        <Box>
                            <Typography
                                sx={{
                                    fontWeight: 900,
                                    letterSpacing: "0.12em",
                                    lineHeight: 1,
                                }}
                            >
                                SKYDRIVER
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
                                display: { xs: "none", sm: "inline-flex" },
                            }}
                        />
                        <IconButton
                            aria-controls={
                                mobileSessionMenuAnchor === null ? undefined : "mobile-session-menu"
                            }
                            aria-expanded={mobileSessionMenuAnchor === null ? undefined : true}
                            aria-haspopup="menu"
                            aria-label="Open account menu"
                            color="inherit"
                            onClick={(event) => setMobileSessionMenuAnchor(event.currentTarget)}
                            sx={{
                                display: { xs: "inline-flex", sm: "none" },
                                bgcolor: "action.hover",
                            }}
                        >
                            <AccountCircleOutlinedIcon />
                        </IconButton>
                        <Menu
                            id="mobile-session-menu"
                            anchorEl={mobileSessionMenuAnchor}
                            open={mobileSessionMenuAnchor !== null}
                            onClose={() => setMobileSessionMenuAnchor(null)}
                        >
                            <MenuItem
                                onClick={() => {
                                    setMobileSessionMenuAnchor(null);
                                    if (configurationEnabled) {
                                        setPage("settings");
                                    } else {
                                        setConfigurationDialogOpen(true);
                                    }
                                }}
                            >
                                <ListItemIcon>
                                    <AdminPanelSettingsOutlinedIcon fontSize="small" />
                                </ListItemIcon>
                                <ListItemText
                                    primary="Configuration"
                                    secondary={
                                        configurationEnabled ? "Changes enabled" : "Read only"
                                    }
                                />
                            </MenuItem>
                            <Divider />
                            <MenuItem
                                onClick={() => {
                                    setMobileSessionMenuAnchor(null);
                                    onLogout();
                                }}
                            >
                                <ListItemIcon>
                                    <LogoutOutlinedIcon fontSize="small" />
                                </ListItemIcon>
                                <ListItemText primary="Logout" />
                            </MenuItem>
                        </Menu>
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
                                onFocus={() => preloadPage(item.id)}
                                onPointerEnter={() => preloadPage(item.id)}
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
                <Box sx={{ minWidth: 0, p: { xs: 2, sm: 3, lg: 5 } }}>
                    <Suspense
                        fallback={
                            <Box
                                role="status"
                                aria-label="Loading page"
                                sx={{ minHeight: 240, display: "grid", placeItems: "center" }}
                            >
                                <Typography color="text.secondary">Loading…</Typography>
                            </Box>
                        }
                    >
                        {content}
                    </Suspense>
                </Box>
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
                message="Skydriver state changed. The latest server state is now loaded."
            />
        </Box>
    );
}
