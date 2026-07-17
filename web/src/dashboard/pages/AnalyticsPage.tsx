import BarChartOutlinedIcon from "@mui/icons-material/BarChartOutlined";
import RefreshOutlinedIcon from "@mui/icons-material/RefreshOutlined";
import {
    Alert,
    Box,
    Button,
    Checkbox,
    CircularProgress,
    FormControlLabel,
    MenuItem,
    Paper,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    TextField,
    Typography,
} from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import {
    fetchManagementSnapshot,
    fetchTransferAnalytics,
    type DirectoryOption,
    type TokenView,
    type TransferAnalyticsRow,
} from "../../api/client";
import { DirectoryPicker, TokenPicker } from "../components/ResourcePickers";
import { PageHeading, formatBytes } from "./shared";

const DAY_SECONDS = 86_400;
const SPEED_BUCKETS = 12;

function formatRate(bytesPerSecond: number | null): string {
    return bytesPerSecond === null ? "—" : `${formatBytes(bytesPerSecond)}/s`;
}

function rate(rows: readonly TransferAnalyticsRow[]): number | null {
    const bytes = rows.reduce((sum, row) => sum + row.weighted_bytes, 0);
    const milliseconds = rows.reduce((sum, row) => sum + row.weighted_provider_ms, 0);
    return milliseconds === 0 ? null : (bytes * 1_000) / milliseconds;
}

function percentileRate(rows: readonly TransferAnalyticsRow[], percentile: number): number | null {
    const histogram = Array.from({ length: SPEED_BUCKETS }, (_, index) =>
        rows.reduce(
            (sum, row) =>
                sum +
                [
                    row.speed_b0,
                    row.speed_b1,
                    row.speed_b2,
                    row.speed_b3,
                    row.speed_b4,
                    row.speed_b5,
                    row.speed_b6,
                    row.speed_b7,
                    row.speed_b8,
                    row.speed_b9,
                    row.speed_b10,
                    row.speed_b11,
                ][index]!,
            0,
        ),
    );
    const total = histogram.reduce((sum, count) => sum + count, 0);
    if (total === 0) return null;
    const target = total * percentile;
    let cumulative = 0;
    for (const [index, count] of histogram.entries()) {
        cumulative += count;
        if (cumulative >= target) return 128 * 1024 * 2 ** index;
    }
    return null;
}

function ThroughputChart({ rows }: { readonly rows: readonly TransferAnalyticsRow[] }) {
    const buckets = [...new Set(rows.map((row) => row.bucket))].sort((left, right) => left - right);
    if (buckets.length === 0) {
        return (
            <Box sx={{ py: 8, textAlign: "center", color: "text.secondary" }}>
                No sampled transfers match these filters.
            </Box>
        );
    }
    const width = 900;
    const height = 280;
    const inset = 28;
    const series = (["upload", "download"] as const).map((direction) => ({
        direction,
        values: buckets.map((bucket) =>
            rate(rows.filter((row) => row.bucket === bucket && row.direction === direction)),
        ),
    }));
    const maximum = Math.max(
        1,
        ...series.flatMap((item) => item.values.map((value) => value ?? 0)),
    );
    const points = (values: readonly (number | null)[]) =>
        values
            .map((value, index) => {
                const x =
                    buckets.length === 1
                        ? width / 2
                        : inset + (index / (buckets.length - 1)) * (width - inset * 2);
                const y = height - inset - ((value ?? 0) / maximum) * (height - inset * 2);
                return `${x},${y}`;
            })
            .join(" ");
    return (
        <Box>
            <Box
                component="svg"
                role="img"
                aria-label="Estimated provider throughput over time"
                viewBox={`0 0 ${width} ${height}`}
                sx={{ width: "100%", height: { xs: 220, md: 300 }, display: "block" }}
            >
                {[0.25, 0.5, 0.75, 1].map((fraction) => (
                    <line
                        key={fraction}
                        x1={inset}
                        x2={width - inset}
                        y1={height - inset - fraction * (height - inset * 2)}
                        y2={height - inset - fraction * (height - inset * 2)}
                        stroke="#dce4ec"
                        strokeWidth="1"
                    />
                ))}
                <polyline
                    points={points(series[0]!.values)}
                    fill="none"
                    stroke="#1689a7"
                    strokeWidth="4"
                    strokeLinejoin="round"
                />
                <polyline
                    points={points(series[1]!.values)}
                    fill="none"
                    stroke="#2f6fed"
                    strokeWidth="4"
                    strokeLinejoin="round"
                />
            </Box>
            <Stack direction="row" spacing={3} sx={{ justifyContent: "center" }}>
                <Typography variant="caption" sx={{ color: "#1689a7", fontWeight: 800 }}>
                    ● Upload
                </Typography>
                <Typography variant="caption" sx={{ color: "#2f6fed", fontWeight: 800 }}>
                    ● Download
                </Typography>
                <Typography color="text.secondary" variant="caption">
                    Peak scale {formatRate(maximum)}
                </Typography>
            </Stack>
        </Box>
    );
}

interface Breakdown {
    readonly id: string;
    readonly rows: readonly TransferAnalyticsRow[];
}

export function AnalyticsPage() {
    const [days, setDays] = useState(30);
    const [driverId, setDriverId] = useState("");
    const [token, setToken] = useState<TokenView | null>(null);
    const [directory, setDirectory] = useState<DirectoryOption | null>(null);
    const [includeDescendants, setIncludeDescendants] = useState(false);
    const [direction, setDirection] = useState<"both" | "upload" | "download">("both");
    const [groupBy, setGroupBy] = useState<"none" | "driver" | "token" | "directory">("driver");
    const [queryEnd, setQueryEnd] = useState(() => Math.floor(Date.now() / 1_000));
    const snapshot = useQuery({
        queryKey: ["management-snapshot"],
        queryFn: fetchManagementSnapshot,
        staleTime: Number.POSITIVE_INFINITY,
    });
    const query = {
        from: queryEnd - days * DAY_SECONDS,
        to: queryEnd,
        interval: "auto" as const,
        groupBy,
        direction,
        ...(driverId === "" ? {} : { driverId }),
        ...(token === null ? {} : { tokenId: token.id }),
        ...(directory === null ? {} : { directoryId: directory.id, includeDescendants }),
    };
    const analytics = useQuery({
        queryKey: ["transfer-analytics", query],
        queryFn: () => fetchTransferAnalytics(query),
        staleTime: 60_000,
    });
    const rows = analytics.data?.rows ?? [];
    const bytes = rows.reduce((sum, row) => sum + row.weighted_bytes, 0);
    const transfers = rows.reduce((sum, row) => sum + row.weighted_transfers, 0);
    const retries = rows.reduce((sum, row) => sum + row.weighted_retries, 0);
    const breakdowns: Breakdown[] = [...new Set(rows.map((row) => row.group_id))]
        .map((id) => ({ id, rows: rows.filter((row) => row.group_id === id) }))
        .sort(
            (left, right) =>
                right.rows.reduce((sum, row) => sum + row.weighted_bytes, 0) -
                left.rows.reduce((sum, row) => sum + row.weighted_bytes, 0),
        );
    const names = new Map<string, string>();
    for (const driver of snapshot.data?.drivers ?? []) names.set(driver.id, driver.id);
    for (const token of snapshot.data?.tokens ?? [])
        names.set(token.id, token.label === "" ? token.id : token.label);
    if (token !== null) names.set(token.id, token.label);
    for (const filesystem of snapshot.data?.filesystems ?? [])
        names.set(filesystem.root_directory_id, `${filesystem.name} /`);
    if (directory !== null) names.set(directory.id, directory.path);
    const summaries: ReadonlyArray<readonly [string, string]> = [
        ["Estimated bytes", formatBytes(bytes)],
        ["Transfers", `≈ ${transfers.toLocaleString()}`],
        ["Provider rate", formatRate(rate(rows))],
        ["Estimated P95", formatRate(percentileRate(rows, 0.95))],
        ["Avg retries", transfers === 0 ? "—" : `${(retries / transfers).toFixed(2)} / transfer`],
    ];

    return (
        <>
            <PageHeading
                title="Analytics"
                description="Low-overhead sampled transfer performance across drivers, tokens, and directories."
            />
            <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
                <Box
                    sx={{
                        display: "grid",
                        gridTemplateColumns: {
                            xs: "1fr",
                            sm: "repeat(2, minmax(0, 1fr))",
                            lg: "repeat(6, minmax(130px, 1fr))",
                        },
                        gap: 1.5,
                    }}
                >
                    <TextField
                        select
                        label="Time range"
                        value={days}
                        onChange={(event) => setDays(Number(event.target.value))}
                        size="small"
                    >
                        {[1, 7, 30, 90, 400].map((value) => (
                            <MenuItem key={value} value={value}>
                                {value === 1 ? "Last 24 hours" : `Last ${value} days`}
                            </MenuItem>
                        ))}
                    </TextField>
                    <TextField
                        select
                        label="Driver"
                        value={driverId}
                        onChange={(event) => setDriverId(event.target.value)}
                        size="small"
                    >
                        <MenuItem value="">All drivers</MenuItem>
                        {(snapshot.data?.drivers ?? []).map((driver) => (
                            <MenuItem key={driver.id} value={driver.id}>
                                {driver.id}
                            </MenuItem>
                        ))}
                    </TextField>
                    <TokenPicker value={token} onChange={setToken} />
                    <DirectoryPicker value={directory} onChange={setDirectory} />
                    <TextField
                        select
                        label="Direction"
                        value={direction}
                        onChange={(event) =>
                            setDirection(event.target.value as "both" | "upload" | "download")
                        }
                        size="small"
                    >
                        <MenuItem value="both">Upload + download</MenuItem>
                        <MenuItem value="upload">Upload</MenuItem>
                        <MenuItem value="download">Download</MenuItem>
                    </TextField>
                    <TextField
                        select
                        label="Group by"
                        value={groupBy}
                        onChange={(event) =>
                            setGroupBy(
                                event.target.value as "none" | "driver" | "token" | "directory",
                            )
                        }
                        size="small"
                    >
                        <MenuItem value="none">No breakdown</MenuItem>
                        <MenuItem value="driver">Driver</MenuItem>
                        <MenuItem value="token">Token</MenuItem>
                        <MenuItem value="directory">Directory</MenuItem>
                    </TextField>
                </Box>
                <Stack
                    direction={{ xs: "column", sm: "row" }}
                    sx={{ mt: 1.5, alignItems: { sm: "center" }, gap: 1 }}
                >
                    <FormControlLabel
                        control={
                            <Checkbox
                                checked={includeDescendants}
                                disabled={directory === null}
                                onChange={(event) => setIncludeDescendants(event.target.checked)}
                                size="small"
                            />
                        }
                        label="Include current descendants"
                    />
                    <Button
                        startIcon={<RefreshOutlinedIcon />}
                        onClick={() => setQueryEnd(Math.floor(Date.now() / 1_000))}
                        sx={{ ml: { sm: "auto" } }}
                    >
                        Refresh
                    </Button>
                </Stack>
            </Paper>

            {analytics.isError ? (
                <Alert severity="error">Unable to load transfer analytics.</Alert>
            ) : analytics.isPending ? (
                <CircularProgress />
            ) : (
                <Stack spacing={3}>
                    <Box
                        sx={{
                            display: "grid",
                            gridTemplateColumns: { xs: "1fr 1fr", lg: "repeat(5, 1fr)" },
                            gap: 1.5,
                        }}
                    >
                        {summaries.map(([label, value]) => (
                            <Paper key={label} variant="outlined" sx={{ p: 2 }}>
                                <Typography color="text.secondary" variant="caption">
                                    {label.toUpperCase()}
                                </Typography>
                                <Typography variant="h6" sx={{ fontWeight: 850 }}>
                                    {value}
                                </Typography>
                            </Paper>
                        ))}
                    </Box>
                    <Paper variant="outlined" sx={{ p: { xs: 1.5, md: 2.5 } }}>
                        <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                            <BarChartOutlinedIcon color="primary" />
                            <Box>
                                <Typography variant="h6" sx={{ fontWeight: 850 }}>
                                    Provider throughput
                                </Typography>
                                <Typography color="text.secondary" variant="caption">
                                    {analytics.data.interval === "hour" ? "Hourly" : "Daily"} ·
                                    sampled estimate · payload bypasses the control plane
                                </Typography>
                            </Box>
                        </Stack>
                        <ThroughputChart rows={rows} />
                    </Paper>
                    <Paper variant="outlined">
                        <Box sx={{ px: 2, py: 1.5 }}>
                            <Typography variant="h6" sx={{ fontWeight: 850 }}>
                                Breakdown
                            </Typography>
                        </Box>
                        <TableContainer>
                            <Table size="small">
                                <TableHead>
                                    <TableRow>
                                        <TableCell>
                                            {groupBy === "none" ? "Scope" : groupBy}
                                        </TableCell>
                                        <TableCell align="right">Bytes</TableCell>
                                        <TableCell align="right">Provider rate</TableCell>
                                        <TableCell align="right">P95</TableCell>
                                        <TableCell align="right">Transfers</TableCell>
                                        <TableCell align="right">Retries / transfer</TableCell>
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    {breakdowns.map((breakdown) => {
                                        const groupTransfers = breakdown.rows.reduce(
                                            (sum, row) => sum + row.weighted_transfers,
                                            0,
                                        );
                                        const groupRetries = breakdown.rows.reduce(
                                            (sum, row) => sum + row.weighted_retries,
                                            0,
                                        );
                                        return (
                                            <TableRow key={breakdown.id} hover>
                                                <TableCell sx={{ fontWeight: 750 }}>
                                                    {names.get(breakdown.id) ?? breakdown.id}
                                                </TableCell>
                                                <TableCell align="right">
                                                    {formatBytes(
                                                        breakdown.rows.reduce(
                                                            (sum, row) => sum + row.weighted_bytes,
                                                            0,
                                                        ),
                                                    )}
                                                </TableCell>
                                                <TableCell align="right">
                                                    {formatRate(rate(breakdown.rows))}
                                                </TableCell>
                                                <TableCell align="right">
                                                    {formatRate(
                                                        percentileRate(breakdown.rows, 0.95),
                                                    )}
                                                </TableCell>
                                                <TableCell align="right">
                                                    ≈ {groupTransfers.toLocaleString()}
                                                </TableCell>
                                                <TableCell align="right">
                                                    {groupTransfers === 0
                                                        ? "—"
                                                        : (groupRetries / groupTransfers).toFixed(
                                                              2,
                                                          )}
                                                </TableCell>
                                            </TableRow>
                                        );
                                    })}
                                </TableBody>
                            </Table>
                        </TableContainer>
                    </Paper>
                    <Alert severity="info">
                        Small successful transfers are deterministically sampled 1/
                        {analytics.data.small_transfer_sample_modulus}; transfers at least{" "}
                        {formatBytes(analytics.data.large_transfer_bytes)} are retained. Values are
                        operational estimates, not billing records.
                    </Alert>
                </Stack>
            )}
        </>
    );
}
