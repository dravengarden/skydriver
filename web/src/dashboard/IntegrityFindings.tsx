import { Box, Button, Chip, CircularProgress, Paper, Stack, Typography } from "@mui/material";
import { useInfiniteQuery } from "@tanstack/react-query";
import { fetchIntegrityFindings } from "../api/client";
import type { IntegrityFinding } from "../api/client";

function formatTimestamp(unixSeconds: number | null): string {
    if (unixSeconds === null) {
        return "never";
    }

    return new Date(unixSeconds * 1_000).toLocaleString([], {
        dateStyle: "medium",
        timeStyle: "medium",
    });
}

function shortIdentity(value: string): string {
    return value.length <= 24 ? value : `${value.slice(0, 12)}…${value.slice(-8)}`;
}

function conditionColor(condition: string): "error" | "warning" | "info" {
    if (condition === "corrupt" || condition === "unrecoverable") {
        return "error";
    }

    if (condition === "missing" || condition === "degraded") {
        return "warning";
    }

    return "info";
}

function FindingCard({ finding }: { readonly finding: IntegrityFinding }) {
    const context: Array<readonly [string, string]> = [
        ["Namespace", finding.namespace_name ?? finding.namespace_id ?? "unassigned"],
        ["Subject", `${finding.subject_kind} · ${shortIdentity(finding.subject_id)}`],
        [
            "Manifest",
            finding.manifest_sha256 === null ? "unknown" : shortIdentity(finding.manifest_sha256),
        ],
        ["Root version", finding.root_version === null ? "unknown" : String(finding.root_version)],
        ["Driver", finding.driver_id ?? "not location-scoped"],
        ["Location state", finding.location_state ?? "not location-scoped"],
        ["Repair sources", finding.available_repair_sources.toLocaleString()],
        ["Last verified", formatTimestamp(finding.last_verified_at)],
    ];

    if (finding.quarantine_revision !== null) {
        context.push(
            ["Quarantine revision", finding.quarantine_revision.toLocaleString()],
            ["Quarantine until", formatTimestamp(finding.quarantine_until)],
            ["Acknowledged", formatTimestamp(finding.acknowledged_at)],
            ["Tombstoned", formatTimestamp(finding.tombstoned_at)],
            ["Delete after", formatTimestamp(finding.delete_after)],
        );
    }

    return (
        <Paper
            sx={{
                p: { xs: 2, sm: 2.5 },
                border: "1px solid",
                borderColor: finding.condition === "corrupt" ? "error.main" : "divider",
            }}
            elevation={0}
        >
            <Stack direction="row" sx={{ alignItems: "flex-start", gap: 1.5 }}>
                <Box sx={{ flexGrow: 1, minWidth: 0 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 850 }}>
                        {finding.condition.replaceAll("_", " ")}
                    </Typography>
                    <Typography color="text.secondary" variant="caption">
                        Last observed {formatTimestamp(finding.last_observed_at)} · revision{" "}
                        {finding.revision}
                    </Typography>
                </Box>
                {finding.repairable && <Chip label="REPAIRABLE" color="success" size="small" />}
                <Chip
                    label={finding.state.toUpperCase()}
                    color={conditionColor(finding.condition)}
                    size="small"
                />
            </Stack>

            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: { xs: "1fr", sm: "repeat(2, minmax(0, 1fr))" },
                    gap: 1.25,
                    mt: 2.5,
                }}
            >
                {context.map(([label, value]) => (
                    <Box key={label} sx={{ minWidth: 0 }}>
                        <Typography color="text.secondary" variant="caption">
                            {label}
                        </Typography>
                        <Typography
                            variant="body2"
                            sx={{ fontWeight: 700, overflowWrap: "anywhere" }}
                        >
                            {value}
                        </Typography>
                    </Box>
                ))}
            </Box>

            {finding.storage_key !== null && (
                <Box sx={{ mt: 2 }}>
                    <Typography color="text.secondary" variant="caption">
                        Storage key
                    </Typography>
                    <Typography
                        variant="body2"
                        sx={{ fontFamily: "monospace", overflowWrap: "anywhere" }}
                    >
                        {finding.storage_key}
                    </Typography>
                </Box>
            )}

            <Box sx={{ mt: 2.5, p: 1.5, bgcolor: "action.hover", borderRadius: 1.5 }}>
                <Typography variant="caption" color="text.secondary">
                    Required action
                </Typography>
                <Typography variant="body2" sx={{ mt: 0.25, fontWeight: 700 }}>
                    {finding.required_action}
                </Typography>
            </Box>

            <Box
                component="pre"
                sx={{
                    m: 0,
                    mt: 2,
                    p: 1.5,
                    maxHeight: 160,
                    overflow: "auto",
                    bgcolor: "background.default",
                    borderRadius: 1.5,
                    fontSize: "0.72rem",
                    whiteSpace: "pre-wrap",
                    overflowWrap: "anywhere",
                }}
            >
                {JSON.stringify(finding.evidence, null, 2)}
            </Box>
        </Paper>
    );
}

export function IntegrityFindings() {
    const query = useInfiniteQuery({
        queryKey: ["integrity-findings", "open"],
        queryFn: ({ pageParam }) => fetchIntegrityFindings(pageParam),
        initialPageParam: null as string | null,
        getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
        refetchInterval: 15_000,
    });
    const findings = query.data?.pages.flatMap((page) => page.findings) ?? [];

    return (
        <Box sx={{ mt: 6 }}>
            <Stack
                direction="row"
                sx={{ alignItems: "baseline", justifyContent: "space-between", mb: 2 }}
            >
                <Box>
                    <Typography variant="h4" sx={{ fontWeight: 850 }}>
                        Integrity alerts
                    </Typography>
                    <Typography color="text.secondary" sx={{ mt: 0.5 }}>
                        Open findings, supporting evidence, and conservative operator actions.
                    </Typography>
                </Box>
                {query.data !== undefined && (
                    <Typography color="text.secondary" variant="caption">
                        {findings.length} loaded
                    </Typography>
                )}
            </Stack>

            {query.isPending ? (
                <CircularProgress />
            ) : query.isError ? (
                <Paper sx={{ p: 3 }}>
                    <Typography color="error">Unable to load integrity findings.</Typography>
                </Paper>
            ) : findings.length === 0 ? (
                <Paper sx={{ p: 3, border: "1px solid", borderColor: "divider" }} elevation={0}>
                    <Typography sx={{ fontWeight: 750 }}>No open integrity findings</Typography>
                    <Typography color="text.secondary" variant="body2" sx={{ mt: 0.5 }}>
                        Verification and reconciliation alerts will appear here.
                    </Typography>
                </Paper>
            ) : (
                <Stack spacing={2}>
                    {findings.map((finding) => (
                        <FindingCard key={finding.id} finding={finding} />
                    ))}
                </Stack>
            )}

            {query.hasNextPage && (
                <Button
                    variant="outlined"
                    sx={{ mt: 2 }}
                    disabled={query.isFetchingNextPage}
                    onClick={() => void query.fetchNextPage()}
                >
                    {query.isFetchingNextPage ? "Loading…" : "Load older findings"}
                </Button>
            )}
        </Box>
    );
}
