import SpeedOutlinedIcon from "@mui/icons-material/SpeedOutlined";
import RefreshOutlinedIcon from "@mui/icons-material/RefreshOutlined";
import { Box, CircularProgress, IconButton, Paper, Stack, Typography } from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { fetchTransferMetrics, type TransferMetricScope } from "../../api/client";

export function formatBytes(bytes: number): string {
    const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"] as const;
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit += 1;
    }
    return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

export function formatDate(unixSeconds: number | null): string {
    if (unixSeconds === null) {
        return "Never";
    }
    return new Date(unixSeconds * 1_000).toLocaleString();
}

function formatRate(bytesPerSecond: number): string {
    return `${formatBytes(bytesPerSecond)}/s`;
}

export function TransferPerformance({
    scope,
    scopeId,
    title = "Transfer performance",
}: {
    scope: TransferMetricScope;
    scopeId: string;
    title?: string;
}) {
    const metrics = useQuery({
        queryKey: ["transfer-metrics", scope, scopeId],
        queryFn: () => fetchTransferMetrics(scope, scopeId),
        staleTime: 60_000,
    });
    const since = Math.floor(Date.now() / 1_000) - 30 * 86_400;
    const recent = metrics.data?.rows.filter((row) => row.day >= since) ?? [];
    const summarize = (direction: "upload" | "download") => {
        const rows = recent.filter((row) => row.direction === direction);
        const bytes = rows.reduce((sum, row) => sum + row.weighted_bytes, 0);
        const providerMs = rows.reduce((sum, row) => sum + row.weighted_provider_ms, 0);
        const transfers = rows.reduce((sum, row) => sum + row.weighted_transfers, 0);
        const latestDay = rows.reduce((latest, row) => Math.max(latest, row.day), 0);
        const latest = rows.filter((row) => row.day === latestDay);
        const latestBytes = latest.reduce((sum, row) => sum + row.weighted_bytes, 0);
        const latestProviderMs = latest.reduce((sum, row) => sum + row.weighted_provider_ms, 0);
        return {
            averageRate: providerMs === 0 ? null : (bytes * 1_000) / providerMs,
            latestRate: latestProviderMs === 0 ? null : (latestBytes * 1_000) / latestProviderMs,
            bytes,
            transfers,
        };
    };
    const upload = summarize("upload");
    const download = summarize("download");

    return (
        <Box sx={{ mt: 2, p: 2, borderRadius: 1.5, bgcolor: "#f5f8fb" }}>
            <Stack direction="row" spacing={1} sx={{ alignItems: "center", mb: 1.25 }}>
                <SpeedOutlinedIcon color="primary" fontSize="small" />
                <Typography sx={{ fontWeight: 800 }}>{title}</Typography>
                <Typography color="text.secondary" variant="caption">
                    30-day sampled estimate
                </Typography>
                <IconButton
                    aria-label={`Refresh ${title.toLowerCase()}`}
                    disabled={metrics.isFetching}
                    onClick={() => void metrics.refetch()}
                    size="small"
                    sx={{ ml: "auto" }}
                >
                    <RefreshOutlinedIcon fontSize="small" />
                </IconButton>
            </Stack>
            {metrics.isError ? (
                <Typography color="text.secondary" variant="body2">
                    Performance metrics are temporarily unavailable.
                </Typography>
            ) : metrics.isPending ? (
                <Typography color="text.secondary" variant="body2">
                    Loading transfer performance…
                </Typography>
            ) : upload.transfers + download.transfers === 0 ? (
                <Typography color="text.secondary" variant="body2">
                    No completed sampled transfers in the last 30 days.
                </Typography>
            ) : (
                <Box
                    sx={{
                        display: "grid",
                        gridTemplateColumns: { xs: "1fr", sm: "repeat(2, 1fr)" },
                        gap: 2,
                    }}
                >
                    {(
                        [
                            ["Upload", upload],
                            ["Download", download],
                        ] as const
                    ).map(([label, summary]) => (
                        <Box key={label}>
                            <Typography color="text.secondary" variant="caption">
                                {label.toUpperCase()} RECENT PROVIDER RATE
                            </Typography>
                            <Typography sx={{ fontWeight: 800 }}>
                                {summary.latestRate === null
                                    ? "No data"
                                    : formatRate(summary.latestRate)}
                            </Typography>
                            <Typography color="text.secondary" variant="caption">
                                30-day avg{" "}
                                {summary.averageRate === null
                                    ? "—"
                                    : formatRate(summary.averageRate)}{" "}
                                · {formatBytes(summary.bytes)} · about{" "}
                                {summary.transfers.toLocaleString()} transfers
                            </Typography>
                        </Box>
                    ))}
                </Box>
            )}
        </Box>
    );
}

export function PageHeading({ title, description }: { title: string; description: string }) {
    return (
        <Box sx={{ mb: 3 }}>
            <Typography variant="h4" sx={{ fontWeight: 850 }}>
                {title}
            </Typography>
            <Typography color="text.secondary" sx={{ mt: 0.5 }}>
                {description}
            </Typography>
        </Box>
    );
}

export function LoadingState() {
    return (
        <Paper variant="outlined" sx={{ p: 5, textAlign: "center" }}>
            <CircularProgress size={28} />
        </Paper>
    );
}

export function ErrorState({ message }: { message: string }) {
    return (
        <Paper variant="outlined" sx={{ p: 3 }}>
            <Typography color="error">{message}</Typography>
        </Paper>
    );
}

export function StatCard({
    label,
    value,
    detail,
    icon,
}: {
    label: string;
    value: string;
    detail: string;
    icon: ReactNode;
}) {
    return (
        <Paper variant="outlined" sx={{ p: 2.5 }}>
            <Stack direction="row" sx={{ justifyContent: "space-between", gap: 2 }}>
                <Box>
                    <Typography color="text.secondary" variant="body2">
                        {label}
                    </Typography>
                    <Typography variant="h4" sx={{ mt: 0.5, fontWeight: 850 }}>
                        {value}
                    </Typography>
                    <Typography color="text.secondary" variant="caption">
                        {detail}
                    </Typography>
                </Box>
                <Box sx={{ color: "primary.main" }}>{icon}</Box>
            </Stack>
        </Paper>
    );
}
