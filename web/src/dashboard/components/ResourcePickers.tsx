import { Autocomplete, Box, Chip, Stack, TextField, Typography } from "@mui/material";
import { useInfiniteQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
    fetchDirectoryOptions,
    fetchTokenOptions,
    type DirectoryOption,
    type TokenView,
} from "../../api/client";
import { formatDate } from "../pages/shared";

function useDebounced(value: string, delay: number): string {
    const [debounced, setDebounced] = useState(value);
    useEffect(() => {
        const timeout = window.setTimeout(() => setDebounced(value), delay);
        return () => window.clearTimeout(timeout);
    }, [delay, value]);
    return debounced;
}

function tokenState(token: TokenView, now: number): "ACTIVE" | "EXPIRED" | "REVOKED" {
    if (token.revoked_at !== null) return "REVOKED";
    if (token.expires_at <= now) return "EXPIRED";
    return "ACTIVE";
}

interface TokenPickerProps {
    readonly value: TokenView | null;
    readonly onChange: (value: TokenView | null) => void;
}

export function TokenPicker({ value, onChange }: TokenPickerProps) {
    const [input, setInput] = useState("");
    const debounced = useDebounced(input, 200);
    const query = useInfiniteQuery({
        queryKey: ["token-options", debounced],
        queryFn: ({ pageParam }) => fetchTokenOptions(debounced, pageParam.name, pageParam.id),
        initialPageParam: { name: "", id: "" },
        getNextPageParam: (page) =>
            page.has_more ? { name: page.next_after_label, id: page.next_after_id } : undefined,
        staleTime: 30_000,
    });
    const options = query.data?.pages.flatMap((page) => page.tokens) ?? [];
    const observedAt = query.data?.pages[0]?.observed_at ?? 0;
    return (
        <Autocomplete
            value={value}
            options={options}
            loading={query.isPending}
            filterOptions={(items) => items}
            getOptionKey={(option) => option.id}
            getOptionLabel={(option) => option.label}
            isOptionEqualToValue={(option, selected) => option.id === selected.id}
            onInputChange={(_event, next, reason) => reason !== "reset" && setInput(next)}
            onChange={(_event, next) => onChange(next)}
            slotProps={{
                listbox: {
                    onScroll: (event) => {
                        const target = event.currentTarget;
                        if (
                            target.scrollHeight - target.scrollTop - target.clientHeight < 80 &&
                            query.hasNextPage &&
                            !query.isFetchingNextPage
                        ) {
                            void query.fetchNextPage();
                        }
                    },
                },
            }}
            noOptionsText={input === "" ? "No tokens" : "No matching tokens"}
            renderInput={(parameters) => (
                <TextField {...parameters} label="Token" placeholder="All tokens" size="small" />
            )}
            renderOption={(properties, option) => {
                const state = tokenState(option, observedAt);
                return (
                    <Box component="li" {...properties} key={option.id} sx={{ py: 1 }}>
                        <Box sx={{ minWidth: 0, width: "100%" }}>
                            <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                                <Typography sx={{ fontWeight: 750 }} noWrap>
                                    {option.label}
                                </Typography>
                                <Chip
                                    label={state}
                                    color={state === "ACTIVE" ? "success" : "default"}
                                    size="small"
                                    variant="outlined"
                                />
                            </Stack>
                            <Typography
                                color="text.secondary"
                                variant="caption"
                                sx={{ display: "block" }}
                            >
                                {option.principal_name} · root {option.root_directory_name || "/"}
                            </Typography>
                            {option.note !== "" && (
                                <Typography
                                    color="text.secondary"
                                    variant="caption"
                                    noWrap
                                    sx={{ display: "block", maxWidth: 460 }}
                                >
                                    {option.note}
                                </Typography>
                            )}
                            <Typography
                                color="text.secondary"
                                variant="caption"
                                sx={{ display: "block" }}
                            >
                                {option.actions.join(", ")} · last used{" "}
                                {formatDate(option.last_used_at)} · …{option.id.slice(-8)}
                            </Typography>
                        </Box>
                    </Box>
                );
            }}
        />
    );
}

interface DirectoryPickerProps {
    readonly value: DirectoryOption | null;
    readonly onChange: (value: DirectoryOption | null) => void;
}

export function DirectoryPicker({ value, onChange }: DirectoryPickerProps) {
    const [input, setInput] = useState("");
    const debounced = useDebounced(input, 200);
    const query = useInfiniteQuery({
        queryKey: ["directory-options", debounced],
        queryFn: ({ pageParam }) => fetchDirectoryOptions(debounced, pageParam.name, pageParam.id),
        initialPageParam: { name: "", id: "" },
        getNextPageParam: (page) =>
            page.has_more ? { name: page.next_after_name, id: page.next_after_id } : undefined,
        staleTime: 30_000,
    });
    return (
        <Autocomplete
            value={value}
            options={query.data?.pages.flatMap((page) => page.directories) ?? []}
            loading={query.isPending}
            filterOptions={(items) => items}
            getOptionKey={(option) => option.id}
            getOptionLabel={(option) => option.path}
            isOptionEqualToValue={(option, selected) => option.id === selected.id}
            onInputChange={(_event, next, reason) => reason !== "reset" && setInput(next)}
            onChange={(_event, next) => onChange(next)}
            slotProps={{
                listbox: {
                    onScroll: (event) => {
                        const target = event.currentTarget;
                        if (
                            target.scrollHeight - target.scrollTop - target.clientHeight < 80 &&
                            query.hasNextPage &&
                            !query.isFetchingNextPage
                        ) {
                            void query.fetchNextPage();
                        }
                    },
                },
            }}
            noOptionsText={input === "" ? "No directories" : "No matching directories"}
            renderInput={(parameters) => (
                <TextField
                    {...parameters}
                    label="Directory"
                    placeholder="All directories"
                    size="small"
                />
            )}
            renderOption={(properties, option) => (
                <Box component="li" {...properties} key={option.id} sx={{ py: 1 }}>
                    <Box sx={{ minWidth: 0 }}>
                        <Typography sx={{ fontWeight: 750 }} noWrap>
                            {option.name === "" ? option.filesystem_name : option.name}
                        </Typography>
                        <Typography
                            color="text.secondary"
                            variant="caption"
                            sx={{ display: "block" }}
                        >
                            {option.path} · {option.filesystem_name}
                        </Typography>
                    </Box>
                </Box>
            )}
        />
    );
}
