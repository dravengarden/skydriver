import FolderOutlinedIcon from "@mui/icons-material/FolderOutlined";
import KeyOutlinedIcon from "@mui/icons-material/KeyOutlined";
import StorageOutlinedIcon from "@mui/icons-material/StorageOutlined";
import VerifiedOutlinedIcon from "@mui/icons-material/VerifiedOutlined";
import { Box, Button, Chip, Paper, Stack, Typography } from "@mui/material";
import type { UseQueryResult } from "@tanstack/react-query";
import type { ManagementSnapshot } from "../../api/client";
import {
    ErrorState,
    LoadingState,
    PageHeading,
    StatCard,
    TransferPerformance,
    formatBytes,
} from "./shared";

interface OverviewPageProps {
    readonly management: UseQueryResult<ManagementSnapshot>;
    readonly onNavigate: (page: "files" | "drivers" | "access") => void;
}

export function OverviewPage({ management, onNavigate }: OverviewPageProps) {
    if (management.isPending) {
        return <LoadingState />;
    }
    if (management.isError) {
        return <ErrorState message="Unable to load the Carrack management snapshot." />;
    }

    const snapshot = management.data;
    const logicalBytes = snapshot.filesystems.reduce((sum, item) => sum + item.logical_bytes, 0);
    const files = snapshot.filesystems.reduce((sum, item) => sum + item.file_count, 0);
    const availableLocations = snapshot.filesystems.reduce(
        (sum, item) => sum + item.available_location_count,
        0,
    );
    const activeTokens = snapshot.tokens.filter(
        (token) => token.revoked_at === null && token.expires_at > snapshot.observed_at,
    ).length;

    return (
        <>
            <PageHeading
                title="Overview"
                description="The current VFS, storage, and access posture at a glance."
            />
            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: { xs: "1fr", sm: "repeat(2, 1fr)", xl: "repeat(4, 1fr)" },
                    gap: 2,
                }}
            >
                <StatCard
                    label="Logical data"
                    value={formatBytes(logicalBytes)}
                    detail={`${files.toLocaleString()} complete files`}
                    icon={<FolderOutlinedIcon />}
                />
                <StatCard
                    label="Storage drivers"
                    value={snapshot.drivers.filter((driver) => driver.enabled).length.toString()}
                    detail={`${snapshot.drivers.length.toLocaleString()} registered`}
                    icon={<StorageOutlinedIcon />}
                />
                <StatCard
                    label="Verified locations"
                    value={availableLocations.toLocaleString()}
                    detail="Complete encoded objects"
                    icon={<VerifiedOutlinedIcon />}
                />
                <StatCard
                    label="Active tokens"
                    value={activeTokens.toLocaleString()}
                    detail={`${snapshot.tokens.length.toLocaleString()} total authorities`}
                    icon={<KeyOutlinedIcon />}
                />
            </Box>

            <TransferPerformance scope="global" scopeId="all" title="VFS transfer performance" />

            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: { xs: "1fr", xl: "1.35fr 1fr" },
                    gap: 2,
                    mt: 3,
                }}
            >
                <Paper variant="outlined" sx={{ p: 3 }}>
                    <Stack direction="row" sx={{ justifyContent: "space-between", mb: 2 }}>
                        <Box>
                            <Typography variant="h6" sx={{ fontWeight: 800 }}>
                                Virtual filesystems
                            </Typography>
                            <Typography color="text.secondary" variant="body2">
                                Logical collections remain independent from provider paths.
                            </Typography>
                        </Box>
                        <Button onClick={() => onNavigate("files")}>Browse files</Button>
                    </Stack>
                    <Stack spacing={1.5}>
                        {snapshot.filesystems.length === 0 ? (
                            <Typography color="text.secondary">
                                No VFS has been bootstrapped.
                            </Typography>
                        ) : (
                            snapshot.filesystems.map((filesystem) => (
                                <Stack
                                    key={filesystem.id}
                                    direction="row"
                                    sx={{
                                        alignItems: "center",
                                        justifyContent: "space-between",
                                        gap: 2,
                                    }}
                                >
                                    <Box sx={{ minWidth: 0 }}>
                                        <Typography sx={{ fontWeight: 700 }} noWrap>
                                            {filesystem.name}
                                        </Typography>
                                        <Typography color="text.secondary" variant="caption">
                                            {filesystem.directory_count.toLocaleString()}{" "}
                                            collections · {filesystem.file_count.toLocaleString()}{" "}
                                            files · {formatBytes(filesystem.logical_bytes)}
                                        </Typography>
                                    </Box>
                                    <Chip label={filesystem.state} color="success" size="small" />
                                </Stack>
                            ))
                        )}
                    </Stack>
                </Paper>

                <Paper variant="outlined" sx={{ p: 3 }}>
                    <Stack direction="row" sx={{ justifyContent: "space-between", mb: 2 }}>
                        <Box>
                            <Typography variant="h6" sx={{ fontWeight: 800 }}>
                                Access posture
                            </Typography>
                            <Typography color="text.secondary" variant="body2">
                                Explicit scopes; administrative roles do not imply content read.
                            </Typography>
                        </Box>
                        <Button onClick={() => onNavigate("access")}>Review access</Button>
                    </Stack>
                    <Stack spacing={1.2}>
                        {snapshot.tokens.slice(0, 4).map((token) => (
                            <Box key={token.id}>
                                <Typography sx={{ fontWeight: 700 }}>{token.label}</Typography>
                                <Typography color="text.secondary" variant="caption">
                                    {token.principal_name} · {token.actions.length} actions ·{" "}
                                    {token.root_directory_name || "/"}
                                </Typography>
                            </Box>
                        ))}
                        {snapshot.tokens.length === 0 && (
                            <Typography color="text.secondary">No VFS tokens exist.</Typography>
                        )}
                    </Stack>
                </Paper>
            </Box>
        </>
    );
}
