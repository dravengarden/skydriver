import CloudDoneOutlinedIcon from "@mui/icons-material/CloudDoneOutlined";
import DatasetOutlinedIcon from "@mui/icons-material/DatasetOutlined";
import Inventory2OutlinedIcon from "@mui/icons-material/Inventory2Outlined";
import LogoutOutlinedIcon from "@mui/icons-material/LogoutOutlined";
import RouteOutlinedIcon from "@mui/icons-material/RouteOutlined";
import {
    AppBar,
    Box,
    Button,
    Chip,
    CircularProgress,
    Container,
    Paper,
    Stack,
    Toolbar,
    Typography,
} from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { fetchSummary } from "../api/client";

interface DashboardProps {
    readonly username: string;
    readonly onLogout: () => void;
}

interface MetricProps {
    readonly label: string;
    readonly value: number;
    readonly icon: ReactNode;
}

function Metric({ label, value, icon }: MetricProps) {
    return (
        <Paper sx={{ p: 3, border: "1px solid", borderColor: "divider" }} elevation={0}>
            <Stack direction="row" sx={{ justifyContent: "space-between", alignItems: "center" }}>
                <Box>
                    <Typography color="text.secondary" variant="body2">
                        {label}
                    </Typography>
                    <Typography variant="h4" sx={{ mt: 0.5, fontWeight: 800 }}>
                        {value.toLocaleString()}
                    </Typography>
                </Box>
                <Box sx={{ color: "primary.main" }}>{icon}</Box>
            </Stack>
        </Paper>
    );
}

export function Dashboard({ username, onLogout }: DashboardProps) {
    const summary = useQuery({ queryKey: ["summary"], queryFn: fetchSummary });

    return (
        <Box component="main" sx={{ minHeight: "100dvh", bgcolor: "background.default" }}>
            <AppBar position="static" color="transparent" elevation={0}>
                <Toolbar sx={{ borderBottom: "1px solid", borderColor: "divider" }}>
                    <Typography variant="h6" sx={{ flexGrow: 1, fontWeight: 900 }}>
                        CARRACK
                    </Typography>
                    <Chip label="DIRECT TRANSFER" color="success" size="small" sx={{ mr: 2 }} />
                    <Typography color="text.secondary" sx={{ mr: 2 }}>
                        {username}
                    </Typography>
                    <Button color="inherit" startIcon={<LogoutOutlinedIcon />} onClick={onLogout}>
                        Logout
                    </Button>
                </Toolbar>
            </AppBar>

            <Container maxWidth="lg" sx={{ py: { xs: 4, md: 7 } }}>
                <Typography variant="h3" sx={{ fontWeight: 850 }}>
                    Archive overview
                </Typography>
                <Typography color="text.secondary" sx={{ mt: 1, mb: 4 }}>
                    Index and agent state. Payload bytes bypass this Worker.
                </Typography>

                {summary.isPending ? (
                    <CircularProgress />
                ) : summary.isError ? (
                    <Paper sx={{ p: 3 }}>
                        <Typography color="error">Unable to load the D1 summary.</Typography>
                    </Paper>
                ) : (
                    <Box
                        sx={{
                            display: "grid",
                            gridTemplateColumns: {
                                xs: "1fr",
                                sm: "repeat(2, 1fr)",
                                lg: "repeat(4, 1fr)",
                            },
                            gap: 2,
                        }}
                    >
                        <Metric
                            label="Transfer jobs"
                            value={summary.data.jobs}
                            icon={<RouteOutlinedIcon />}
                        />
                        <Metric
                            label="Logical objects"
                            value={summary.data.objects}
                            icon={<DatasetOutlinedIcon />}
                        />
                        <Metric
                            label="Physical blocks"
                            value={summary.data.blocks}
                            icon={<Inventory2OutlinedIcon />}
                        />
                        <Metric
                            label="Verified replicas"
                            value={summary.data.replicas}
                            icon={<CloudDoneOutlinedIcon />}
                        />
                    </Box>
                )}
            </Container>
        </Box>
    );
}
