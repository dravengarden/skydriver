import DescriptionOutlinedIcon from "@mui/icons-material/DescriptionOutlined";
import FolderOutlinedIcon from "@mui/icons-material/FolderOutlined";
import TuneOutlinedIcon from "@mui/icons-material/TuneOutlined";
import { Box, Breadcrumbs, Button, Chip, Link, Paper, Stack, Typography } from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import type { UseQueryResult } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { fetchManagementDirectory } from "../../api/client";
import type { ManagementSnapshot } from "../../api/client";
import { ErrorState, LoadingState, PageHeading, formatBytes, formatDate } from "./shared";
import { QuotaDialog } from "./QuotaDialog";

export function FilesPage({
    management,
    configurationEnabled,
    onRequestConfiguration,
}: {
    management: UseQueryResult<ManagementSnapshot>;
    configurationEnabled: boolean;
    onRequestConfiguration: () => void;
}) {
    const [directoryId, setDirectoryId] = useState<string | null>(null);
    const [quotaOpen, setQuotaOpen] = useState(false);
    const firstRoot = management.data?.filesystems[0]?.root_directory_id;
    useEffect(() => {
        if (directoryId === null && firstRoot !== undefined) {
            setDirectoryId(firstRoot);
        }
    }, [directoryId, firstRoot]);
    const directory = useQuery({
        queryKey: ["management-directory", directoryId],
        queryFn: () => fetchManagementDirectory(directoryId ?? ""),
        enabled: directoryId !== null,
    });

    if (management.isPending) {
        return <LoadingState />;
    }
    if (management.isError) {
        return <ErrorState message="Unable to load virtual filesystems." />;
    }

    return (
        <>
            <PageHeading
                title="Files"
                description="Complete logical files, Merkle-linked collections, and their storage placements."
            />
            <Stack direction="row" useFlexGap spacing={1} sx={{ mb: 2, flexWrap: "wrap" }}>
                {management.data.filesystems.map((filesystem) => (
                    <Button
                        key={filesystem.id}
                        variant={
                            directoryId === filesystem.root_directory_id ? "contained" : "outlined"
                        }
                        startIcon={<FolderOutlinedIcon />}
                        onClick={() => setDirectoryId(filesystem.root_directory_id)}
                    >
                        {filesystem.name}
                    </Button>
                ))}
            </Stack>
            {management.data.filesystems.length === 0 ? (
                <Paper variant="outlined" sx={{ p: 4 }}>
                    <Typography sx={{ fontWeight: 700 }}>No VFS has been bootstrapped</Typography>
                    <Typography color="text.secondary" variant="body2">
                        Files will appear here after the first validated bootstrap.
                    </Typography>
                </Paper>
            ) : directory.isPending ? (
                <LoadingState />
            ) : directory.isError ? (
                <ErrorState message="Unable to load this collection." />
            ) : (
                <>
                    <Paper variant="outlined" sx={{ p: 3, mb: 2 }}>
                        <Breadcrumbs sx={{ mb: 2 }}>
                            {directory.data.breadcrumbs.map((item) => (
                                <Link
                                    key={item.id}
                                    component="button"
                                    underline="hover"
                                    onClick={() => setDirectoryId(item.id)}
                                >
                                    {item.name}
                                </Link>
                            ))}
                        </Breadcrumbs>
                        <Stack direction="row" sx={{ justifyContent: "space-between", mb: 2 }}>
                            <Typography variant="h6" sx={{ fontWeight: 800 }}>
                                {directory.data.breadcrumbs.at(-1)?.name ?? "Directory"}
                            </Typography>
                            <Button
                                size="small"
                                variant="outlined"
                                startIcon={<TuneOutlinedIcon />}
                                onClick={() => setQuotaOpen(true)}
                            >
                                Limits
                            </Button>
                        </Stack>
                        <Box
                            sx={{
                                display: "grid",
                                gridTemplateColumns: { xs: "repeat(2, 1fr)", lg: "repeat(5, 1fr)" },
                                gap: 2,
                            }}
                        >
                            {[
                                [
                                    "Logical size",
                                    formatBytes(directory.data.directory.recursive_logical_bytes),
                                ],
                                [
                                    "Files",
                                    directory.data.directory.recursive_file_count.toLocaleString(),
                                ],
                                [
                                    "Child collections",
                                    directory.data.directory.recursive_directory_count.toLocaleString(),
                                ],
                                [
                                    "Key epoch",
                                    directory.data.directory.active_key_epoch.toLocaleString(),
                                ],
                                [
                                    "ACL",
                                    directory.data.directory.acl_inherits
                                        ? "Inherited"
                                        : "Boundary",
                                ],
                                [
                                    "Logical limit",
                                    directory.data.directory.max_logical_bytes === null
                                        ? "Inherited / unlimited"
                                        : formatBytes(directory.data.directory.max_logical_bytes),
                                ],
                            ].map(([label, value]) => (
                                <Box key={label}>
                                    <Typography color="text.secondary" variant="caption">
                                        {label}
                                    </Typography>
                                    <Typography sx={{ fontWeight: 750 }}>{value}</Typography>
                                </Box>
                            ))}
                        </Box>
                        <Stack
                            direction="row"
                            useFlexGap
                            spacing={0.75}
                            sx={{ mt: 2, flexWrap: "wrap" }}
                        >
                            {directory.data.placements.map((placement) => (
                                <Chip key={placement} label={placement} size="small" color="info" />
                            ))}
                            <Chip
                                label={directory.data.directory.crypto_suite}
                                size="small"
                                variant="outlined"
                            />
                        </Stack>
                        <Typography
                            color="text.secondary"
                            variant="caption"
                            sx={{ display: "block", mt: 2, fontFamily: "monospace" }}
                        >
                            Merkle root {directory.data.directory.data_root}
                        </Typography>
                    </Paper>

                    <Paper variant="outlined" sx={{ overflow: "hidden" }}>
                        <Box
                            sx={{
                                display: { xs: "none", md: "grid" },
                                gridTemplateColumns: "minmax(220px, 2fr) 1fr 1fr 1.25fr",
                                gap: 2,
                                px: 2.5,
                                py: 1.5,
                                bgcolor: "#f2f5f8",
                            }}
                        >
                            {["Name", "Size", "Drivers", "Updated"].map((label) => (
                                <Typography
                                    key={label}
                                    color="text.secondary"
                                    variant="caption"
                                    sx={{ fontWeight: 750 }}
                                >
                                    {label}
                                </Typography>
                            ))}
                        </Box>
                        {directory.data.entries.map((entry) => (
                            <Box
                                key={entry.name}
                                sx={{
                                    display: "grid",
                                    gridTemplateColumns: {
                                        xs: "1fr",
                                        md: "minmax(220px, 2fr) 1fr 1fr 1.25fr",
                                    },
                                    gap: { xs: 0.75, md: 2 },
                                    alignItems: "center",
                                    px: 2.5,
                                    py: 1.8,
                                    borderTop: "1px solid",
                                    borderColor: "divider",
                                }}
                            >
                                <Stack
                                    direction="row"
                                    spacing={1.2}
                                    sx={{ alignItems: "center", minWidth: 0 }}
                                >
                                    {entry.kind === "directory" ? (
                                        <FolderOutlinedIcon color="primary" />
                                    ) : (
                                        <DescriptionOutlinedIcon color="action" />
                                    )}
                                    {entry.kind === "directory" &&
                                    entry.child_directory_id !== null ? (
                                        <Link
                                            component="button"
                                            underline="hover"
                                            onClick={() => setDirectoryId(entry.child_directory_id)}
                                            sx={{ fontWeight: 700 }}
                                        >
                                            {entry.name}
                                        </Link>
                                    ) : (
                                        <Typography sx={{ fontWeight: 700 }} noWrap>
                                            {entry.name}
                                        </Typography>
                                    )}
                                </Stack>
                                <Typography variant="body2">
                                    {entry.kind === "file"
                                        ? formatBytes(entry.size_bytes)
                                        : "Collection"}
                                </Typography>
                                <Typography color="text.secondary" variant="body2">
                                    {entry.driver_ids.length === 0
                                        ? "—"
                                        : entry.driver_ids.join(", ")}
                                </Typography>
                                <Typography color="text.secondary" variant="body2">
                                    {formatDate(entry.updated_at)}
                                </Typography>
                            </Box>
                        ))}
                        {directory.data.entries.length === 0 && (
                            <Box sx={{ p: 4 }}>
                                <Typography sx={{ fontWeight: 700 }}>Empty collection</Typography>
                                <Typography color="text.secondary" variant="body2">
                                    No files or child collections are published here.
                                </Typography>
                            </Box>
                        )}
                    </Paper>
                    <QuotaDialog
                        open={quotaOpen}
                        scope="directory"
                        resourceId={directory.data.directory.id}
                        resourceName={directory.data.breadcrumbs.at(-1)?.name ?? "Directory"}
                        revision={directory.data.directory.quota_revision}
                        limits={{
                            max_file_bytes: directory.data.directory.max_file_bytes,
                            max_logical_bytes: directory.data.directory.max_logical_bytes,
                            max_file_count: directory.data.directory.max_file_count,
                            max_physical_bytes: null,
                            max_object_count: null,
                        }}
                        configurationEnabled={configurationEnabled}
                        onRequestConfiguration={onRequestConfiguration}
                        onClose={() => setQuotaOpen(false)}
                    />
                </>
            )}
        </>
    );
}
