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
    LinearProgress,
    Paper,
    Stack,
    Toolbar,
    Typography,
} from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { fetchLiveComponents, fetchSummary } from "../api/client";
import type { LiveComponent } from "../api/client";
import { IntegrityFindings } from "./IntegrityFindings";

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

function formatRate(bytesPerSecond: number): string {
    const units = ["B/s", "KiB/s", "MiB/s", "GiB/s"] as const;
    let value = bytesPerSecond;
    let unit = 0;

    while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit += 1;
    }

    return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatBytes(bytes: number): string {
    return formatRate(bytes).replace("/s", "");
}

function formatLastSample(unixSeconds: number | null): string {
    if (unixSeconds === null) {
        return "not reporting";
    }

    return new Date(unixSeconds * 1_000).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
    });
}

function progress(component: LiveComponent): number | undefined {
    if (component.useful_bytes_total === null || component.useful_bytes_total === 0) {
        return undefined;
    }

    return Math.min(100, (100 * component.useful_bytes_verified) / component.useful_bytes_total);
}

function statusColor(state: string): "success" | "warning" | "info" {
    if (state === "stalled") {
        return "warning";
    }

    return state === "running" ? "success" : "info";
}

function ComponentCard({ component }: { readonly component: LiveComponent }) {
    const percentage = progress(component);

    return (
        <Paper
            sx={{ p: { xs: 2, sm: 2.5 }, border: "1px solid", borderColor: "divider" }}
            elevation={0}
        >
            <Stack
                direction="row"
                sx={{ alignItems: "flex-start", justifyContent: "space-between", gap: 2 }}
            >
                <Box sx={{ minWidth: 0 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 800 }} noWrap>
                        {component.component_kind}
                    </Typography>
                    <Typography color="text.secondary" variant="body2" noWrap>
                        {component.operation_kind} · {component.operation_phase} ·{" "}
                        {component.client_name ?? "unassigned"}
                    </Typography>
                </Box>
                <Chip
                    label={component.component_state}
                    color={statusColor(component.component_state)}
                    size="small"
                />
            </Stack>

            <Box sx={{ mt: 2.5 }}>
                <Stack direction="row" sx={{ justifyContent: "space-between", mb: 0.75 }}>
                    <Typography color="text.secondary" variant="caption">
                        Verified progress
                    </Typography>
                    <Typography variant="caption" sx={{ fontWeight: 700 }}>
                        {percentage === undefined ? "unknown total" : `${percentage.toFixed(1)}%`}
                    </Typography>
                </Stack>
                <LinearProgress
                    variant={percentage === undefined ? "indeterminate" : "determinate"}
                    value={percentage}
                />
            </Box>

            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                    gap: 1.5,
                    mt: 2.5,
                }}
            >
                {[
                    ["1 minute", component.rate_1m_bps],
                    ["5 minutes", component.rate_5m_bps],
                    ["15 minutes", component.rate_15m_bps],
                    ["Active average", component.lifetime_active_bps],
                ].map(([label, value]) => (
                    <Box key={label}>
                        <Typography color="text.secondary" variant="caption">
                            {label}
                        </Typography>
                        <Typography sx={{ fontWeight: 750 }}>
                            {formatRate(Number(value))}
                        </Typography>
                    </Box>
                ))}
            </Box>

            <Typography color="text.secondary" variant="caption" sx={{ display: "block", mt: 2 }}>
                {formatBytes(component.wire_bytes_read + component.wire_bytes_written)} wire ·{" "}
                {component.retry_count.toLocaleString()} retries ·{" "}
                {component.throttle_count.toLocaleString()} throttles
            </Typography>
            <Typography color="text.secondary" variant="caption" sx={{ display: "block", mt: 0.5 }}>
                Last sample {formatLastSample(component.last_sample_at)}
            </Typography>
        </Paper>
    );
}

export function Dashboard({ username, onLogout }: DashboardProps) {
    const summary = useQuery({ queryKey: ["summary"], queryFn: fetchSummary });
    const liveComponents = useQuery({
        queryKey: ["live-components"],
        queryFn: fetchLiveComponents,
        refetchInterval: 5_000,
    });

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
                    Index and client state. Payload bytes bypass this Worker.
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
                            label="Operations"
                            value={summary.data.operations}
                            icon={<RouteOutlinedIcon />}
                        />
                        <Metric
                            label="Logical objects"
                            value={summary.data.objects}
                            icon={<DatasetOutlinedIcon />}
                        />
                        <Metric
                            label="Physical packs"
                            value={summary.data.packs}
                            icon={<Inventory2OutlinedIcon />}
                        />
                        <Metric
                            label="Verified locations"
                            value={summary.data.verified_locations}
                            icon={<CloudDoneOutlinedIcon />}
                        />
                    </Box>
                )}

                <IntegrityFindings />

                <Stack
                    direction="row"
                    sx={{ alignItems: "baseline", justifyContent: "space-between", mt: 6, mb: 2 }}
                >
                    <Box>
                        <Typography variant="h4" sx={{ fontWeight: 850 }}>
                            Live components
                        </Typography>
                        <Typography color="text.secondary" sx={{ mt: 0.5 }}>
                            Verified progress and active-transfer throughput.
                        </Typography>
                    </Box>
                    {liveComponents.data !== undefined && (
                        <Typography color="text.secondary" variant="caption">
                            {liveComponents.data.components.length} active
                        </Typography>
                    )}
                </Stack>

                {liveComponents.isPending ? (
                    <CircularProgress />
                ) : liveComponents.isError ? (
                    <Paper sx={{ p: 3 }}>
                        <Typography color="error">Unable to load live component state.</Typography>
                    </Paper>
                ) : liveComponents.data.components.length === 0 ? (
                    <Paper sx={{ p: 3, border: "1px solid", borderColor: "divider" }} elevation={0}>
                        <Typography sx={{ fontWeight: 700 }}>No active components</Typography>
                        <Typography color="text.secondary" variant="body2" sx={{ mt: 0.5 }}>
                            Running imports, copies, moves, restores, and maintenance stages appear
                            here.
                        </Typography>
                    </Paper>
                ) : (
                    <Box
                        sx={{
                            display: "grid",
                            gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 340px), 1fr))",
                            gap: 2,
                        }}
                    >
                        {liveComponents.data.components.map((component) => (
                            <ComponentCard key={component.component_id} component={component} />
                        ))}
                    </Box>
                )}
            </Container>
        </Box>
    );
}
