import { Box, CircularProgress, Paper, Stack, Typography } from "@mui/material";
import type { ReactNode } from "react";

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
