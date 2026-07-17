import DescriptionOutlinedIcon from "@mui/icons-material/DescriptionOutlined";
import FolderOutlinedIcon from "@mui/icons-material/FolderOutlined";
import GridViewOutlinedIcon from "@mui/icons-material/GridViewOutlined";
import RefreshOutlinedIcon from "@mui/icons-material/RefreshOutlined";
import SearchOutlinedIcon from "@mui/icons-material/SearchOutlined";
import TuneOutlinedIcon from "@mui/icons-material/TuneOutlined";
import ViewListOutlinedIcon from "@mui/icons-material/ViewListOutlined";
import {
    Alert,
    Box,
    Breadcrumbs,
    Button,
    Chip,
    IconButton,
    InputAdornment,
    Link,
    Paper,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    TextField,
    ToggleButton,
    ToggleButtonGroup,
    Tooltip,
    Typography,
} from "@mui/material";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import type { UseQueryResult } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import {
    fetchManagementDirectory,
    fetchManagementDirectoryEntries,
    type ManagementDirectoryEntry,
    type ManagementSnapshot,
} from "../../api/client";
import { ErrorState, LoadingState, PageHeading, formatBytes, formatDate } from "./shared";
import { QuotaDialog } from "./QuotaDialog";

const ENTRY_PAGE_SIZE = 100;

function EntryIcon({ kind }: { readonly kind: ManagementDirectoryEntry["kind"] }) {
    return kind === "directory" ? (
        <FolderOutlinedIcon sx={{ color: "#e6a23c" }} />
    ) : (
        <DescriptionOutlinedIcon color="action" />
    );
}

function EntryDetails({ entry }: { readonly entry: ManagementDirectoryEntry }) {
    return (
        <Paper variant="outlined" sx={{ p: 2.5, position: { lg: "sticky" }, top: { lg: 76 } }}>
            <Stack direction="row" spacing={1.25} sx={{ alignItems: "center", mb: 2 }}>
                <EntryIcon kind={entry.kind} />
                <Box sx={{ minWidth: 0 }}>
                    <Typography sx={{ fontWeight: 850 }} noWrap>
                        {entry.name}
                    </Typography>
                    <Typography color="text.secondary" variant="caption">
                        {entry.kind === "directory" ? "Directory" : "Complete logical file"}
                    </Typography>
                </Box>
            </Stack>
            <Stack spacing={1.5}>
                {(
                    [
                        ["Size", entry.kind === "file" ? formatBytes(entry.size_bytes) : "—"],
                        ["Updated", formatDate(entry.updated_at)],
                        ["Revision", entry.revision.toLocaleString()],
                        [
                            "Drivers",
                            entry.driver_ids.length === 0 ? "—" : entry.driver_ids.join(", "),
                        ],
                        ["Version", entry.version_id ?? "—"],
                        ["Data root", entry.data_root],
                        ["Metadata root", entry.metadata_root ?? "—"],
                    ] as const
                ).map(([label, value]) => (
                    <Box key={label}>
                        <Typography color="text.secondary" variant="caption">
                            {label}
                        </Typography>
                        <Typography
                            variant="body2"
                            sx={{
                                fontFamily:
                                    label.includes("root") || label === "Version"
                                        ? "monospace"
                                        : undefined,
                                overflowWrap: "anywhere",
                            }}
                        >
                            {value}
                        </Typography>
                    </Box>
                ))}
            </Stack>
        </Paper>
    );
}

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
    const [prefix, setPrefix] = useState("");
    const [effectivePrefix, setEffectivePrefix] = useState("");
    const [view, setView] = useState<"list" | "grid">("list");
    const [selected, setSelected] = useState<ManagementDirectoryEntry | null>(null);
    const [quotaOpen, setQuotaOpen] = useState(false);
    const [refreshGeneration, setRefreshGeneration] = useState(0);
    const firstRoot = management.data?.filesystems[0]?.root_directory_id;
    useEffect(() => {
        if (directoryId === null && firstRoot !== undefined) setDirectoryId(firstRoot);
    }, [directoryId, firstRoot]);
    useEffect(() => {
        setPrefix("");
        setEffectivePrefix("");
        setSelected(null);
    }, [directoryId]);
    useEffect(() => {
        const timeout = window.setTimeout(() => {
            setEffectivePrefix(prefix);
            setSelected(null);
        }, 250);
        return () => window.clearTimeout(timeout);
    }, [prefix]);

    const directory = useQuery({
        queryKey: ["management-directory", directoryId],
        queryFn: () => fetchManagementDirectory(directoryId ?? ""),
        enabled: directoryId !== null,
    });
    const revision = directory.data?.directory.revision ?? 0;
    const entryPages = useInfiniteQuery({
        queryKey: [
            "management-directory-entries",
            directoryId,
            revision,
            effectivePrefix,
            refreshGeneration,
        ],
        queryFn: ({ pageParam }) =>
            fetchManagementDirectoryEntries(
                directoryId ?? "",
                revision,
                effectivePrefix,
                pageParam.kind,
                pageParam.name,
                ENTRY_PAGE_SIZE,
            ),
        enabled: directoryId !== null && revision > 0,
        initialPageParam: { kind: "", name: "" },
        getNextPageParam: (page) =>
            page.has_more ? { kind: page.next_after_kind, name: page.next_after_name } : undefined,
    });
    const entries = useMemo(
        () => entryPages.data?.pages.flatMap((page) => page.entries) ?? [],
        [entryPages.data],
    );

    const openEntry = (entry: ManagementDirectoryEntry) => {
        if (entry.kind === "directory" && entry.child_directory_id !== null) {
            setDirectoryId(entry.child_directory_id);
        } else {
            setSelected(entry);
        }
    };

    if (management.isPending) return <LoadingState />;
    if (management.isError) return <ErrorState message="Unable to load virtual filesystems." />;

    return (
        <>
            <PageHeading
                title="Files"
                description="Browse the logical namespace. Provider objects and internal manifests stay hidden."
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
                <ErrorState message="Unable to load this directory." />
            ) : (
                <>
                    <Paper variant="outlined" sx={{ overflow: "hidden", mb: 2 }}>
                        <Box sx={{ px: { xs: 1.5, md: 2.5 }, pt: 2, pb: 1.5 }}>
                            <Breadcrumbs sx={{ mb: 1.5 }}>
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
                            <Stack
                                direction={{ xs: "column", md: "row" }}
                                spacing={1}
                                sx={{ alignItems: { md: "center" } }}
                            >
                                <TextField
                                    value={prefix}
                                    onChange={(event) => setPrefix(event.target.value)}
                                    placeholder="Filter this directory by name prefix"
                                    size="small"
                                    slotProps={{
                                        input: {
                                            startAdornment: (
                                                <InputAdornment position="start">
                                                    <SearchOutlinedIcon fontSize="small" />
                                                </InputAdornment>
                                            ),
                                        },
                                    }}
                                    sx={{ flex: 1, maxWidth: { md: 520 } }}
                                />
                                <Stack direction="row" spacing={0.75} sx={{ ml: { md: "auto" } }}>
                                    <Tooltip title="Refresh current revision">
                                        <IconButton
                                            onClick={() => {
                                                void directory.refetch().then(() => {
                                                    setRefreshGeneration(
                                                        (generation) => generation + 1,
                                                    );
                                                });
                                            }}
                                        >
                                            <RefreshOutlinedIcon />
                                        </IconButton>
                                    </Tooltip>
                                    <ToggleButtonGroup
                                        exclusive
                                        size="small"
                                        value={view}
                                        onChange={(_, next: "list" | "grid" | null) => {
                                            if (next !== null) setView(next);
                                        }}
                                        aria-label="File view"
                                    >
                                        <ToggleButton value="list" aria-label="List view">
                                            <ViewListOutlinedIcon fontSize="small" />
                                        </ToggleButton>
                                        <ToggleButton value="grid" aria-label="Grid view">
                                            <GridViewOutlinedIcon fontSize="small" />
                                        </ToggleButton>
                                    </ToggleButtonGroup>
                                    <Button
                                        size="small"
                                        variant="outlined"
                                        startIcon={<TuneOutlinedIcon />}
                                        onClick={() => setQuotaOpen(true)}
                                    >
                                        Limits
                                    </Button>
                                </Stack>
                            </Stack>
                        </Box>
                        <Box
                            sx={{
                                display: "grid",
                                gridTemplateColumns: { xs: "repeat(2, 1fr)", md: "repeat(4, 1fr)" },
                                gap: 1,
                                px: { xs: 1.5, md: 2.5 },
                                py: 1.5,
                                bgcolor: "action.hover",
                                borderTop: "1px solid",
                                borderColor: "divider",
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
                                    "Directories",
                                    directory.data.directory.recursive_directory_count.toLocaleString(),
                                ],
                                [
                                    "Access",
                                    directory.data.directory.acl_inherits
                                        ? "Inherited"
                                        : "Boundary",
                                ],
                            ].map(([label, value]) => (
                                <Box key={label}>
                                    <Typography color="text.secondary" variant="caption">
                                        {label}
                                    </Typography>
                                    <Typography sx={{ fontWeight: 800 }}>{value}</Typography>
                                </Box>
                            ))}
                        </Box>
                    </Paper>

                    <Box
                        sx={{
                            display: "grid",
                            gridTemplateColumns:
                                selected === null
                                    ? "minmax(0, 1fr)"
                                    : { xs: "1fr", lg: "minmax(0, 1fr) 320px" },
                            gap: 2,
                            alignItems: "start",
                        }}
                    >
                        <Paper variant="outlined" sx={{ overflow: "hidden" }}>
                            {entryPages.isPending ? (
                                <LoadingState />
                            ) : entryPages.isError ? (
                                <Alert severity="error" sx={{ m: 2 }}>
                                    This directory changed or its entries could not be loaded.
                                    Refresh to read one consistent revision.
                                </Alert>
                            ) : view === "list" ? (
                                <TableContainer>
                                    <Table size="small" stickyHeader>
                                        <TableHead>
                                            <TableRow>
                                                <TableCell>Name</TableCell>
                                                <TableCell align="right">Size</TableCell>
                                                <TableCell>Drivers</TableCell>
                                                <TableCell>Updated</TableCell>
                                            </TableRow>
                                        </TableHead>
                                        <TableBody>
                                            {entries.map((entry) => (
                                                <TableRow
                                                    key={`${entry.kind}:${entry.name}`}
                                                    hover
                                                    selected={
                                                        selected?.name === entry.name &&
                                                        selected.kind === entry.kind
                                                    }
                                                    onClick={() => openEntry(entry)}
                                                    sx={{ cursor: "pointer" }}
                                                >
                                                    <TableCell>
                                                        <Stack
                                                            direction="row"
                                                            spacing={1.25}
                                                            sx={{
                                                                alignItems: "center",
                                                                minWidth: 220,
                                                            }}
                                                        >
                                                            <EntryIcon kind={entry.kind} />
                                                            <Typography
                                                                sx={{ fontWeight: 750 }}
                                                                noWrap
                                                            >
                                                                {entry.name}
                                                            </Typography>
                                                        </Stack>
                                                    </TableCell>
                                                    <TableCell align="right">
                                                        {entry.kind === "file"
                                                            ? formatBytes(entry.size_bytes)
                                                            : "—"}
                                                    </TableCell>
                                                    <TableCell>
                                                        {entry.driver_ids.length === 0
                                                            ? "—"
                                                            : entry.driver_ids.join(", ")}
                                                    </TableCell>
                                                    <TableCell>
                                                        {formatDate(entry.updated_at)}
                                                    </TableCell>
                                                </TableRow>
                                            ))}
                                        </TableBody>
                                    </Table>
                                </TableContainer>
                            ) : (
                                <Box
                                    sx={{
                                        display: "grid",
                                        gridTemplateColumns: {
                                            xs: "repeat(2, minmax(0, 1fr))",
                                            sm: "repeat(3, minmax(0, 1fr))",
                                            xl: "repeat(5, minmax(0, 1fr))",
                                        },
                                        gap: 1,
                                        p: 1.5,
                                    }}
                                >
                                    {entries.map((entry) => (
                                        <Paper
                                            key={`${entry.kind}:${entry.name}`}
                                            component="button"
                                            variant="outlined"
                                            onClick={() => openEntry(entry)}
                                            sx={{
                                                p: 1.5,
                                                minWidth: 0,
                                                textAlign: "left",
                                                cursor: "pointer",
                                                bgcolor:
                                                    selected?.name === entry.name
                                                        ? "action.selected"
                                                        : "background.paper",
                                                borderColor:
                                                    selected?.name === entry.name
                                                        ? "primary.main"
                                                        : "divider",
                                            }}
                                        >
                                            <EntryIcon kind={entry.kind} />
                                            <Typography sx={{ mt: 1, fontWeight: 750 }} noWrap>
                                                {entry.name}
                                            </Typography>
                                            <Typography color="text.secondary" variant="caption">
                                                {entry.kind === "file"
                                                    ? formatBytes(entry.size_bytes)
                                                    : "Directory"}
                                            </Typography>
                                        </Paper>
                                    ))}
                                </Box>
                            )}
                            {!entryPages.isPending && entries.length === 0 && (
                                <Box sx={{ p: 5, textAlign: "center" }}>
                                    <FolderOutlinedIcon color="disabled" sx={{ fontSize: 44 }} />
                                    <Typography sx={{ mt: 1, fontWeight: 750 }}>
                                        {effectivePrefix === ""
                                            ? "Empty directory"
                                            : "No matching names"}
                                    </Typography>
                                    <Typography color="text.secondary" variant="body2">
                                        {effectivePrefix === ""
                                            ? "No files or child directories are published here."
                                            : "Try a shorter name prefix."}
                                    </Typography>
                                </Box>
                            )}
                            {entries.length > 0 && (
                                <Stack
                                    direction={{ xs: "column", sm: "row" }}
                                    spacing={1}
                                    sx={{
                                        px: 2,
                                        py: 1.5,
                                        alignItems: { sm: "center" },
                                        borderTop: "1px solid",
                                        borderColor: "divider",
                                    }}
                                >
                                    <Typography color="text.secondary" variant="caption">
                                        {entries.length.toLocaleString()} entries loaded from
                                        revision {revision.toLocaleString()}
                                    </Typography>
                                    {entryPages.hasNextPage && (
                                        <Button
                                            size="small"
                                            variant="outlined"
                                            disabled={entryPages.isFetchingNextPage}
                                            onClick={() => void entryPages.fetchNextPage()}
                                            sx={{ ml: { sm: "auto" } }}
                                        >
                                            {entryPages.isFetchingNextPage
                                                ? "Loading…"
                                                : `Load ${ENTRY_PAGE_SIZE} more`}
                                        </Button>
                                    )}
                                </Stack>
                            )}
                        </Paper>
                        {selected !== null && <EntryDetails entry={selected} />}
                    </Box>

                    <Stack
                        direction="row"
                        useFlexGap
                        spacing={0.75}
                        sx={{ mt: 2, flexWrap: "wrap" }}
                    >
                        <Chip
                            label={`${
                                directory.data.mount.relationship === "default"
                                    ? "Default"
                                    : directory.data.mount.relationship === "mount"
                                      ? "Mounted"
                                      : "Inherited"
                            }: ${directory.data.mount.effective_driver_id}`}
                            size="small"
                            color={
                                directory.data.mount.relationship === "mount" ? "primary" : "info"
                            }
                            variant={
                                directory.data.mount.relationship === "inherited"
                                    ? "outlined"
                                    : "filled"
                            }
                        />
                        <Chip
                            label={directory.data.directory.crypto_suite}
                            size="small"
                            variant="outlined"
                        />
                    </Stack>
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
