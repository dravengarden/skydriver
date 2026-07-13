package sdk

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
)

const (
	vfsCatalogSyncSchema      = "carrack.vfs.catalog-sync.v1"
	defaultVFSCatalogPageSize = uint32(1_000)
	defaultVFSCatalogWorkers  = uint32(8)
	maximumVFSCatalogWorkers  = uint32(64)
)

// ErrVFSCatalogChanged indicates that the live recursive root changed while
// its verified local DAG closure was being synchronized.
var ErrVFSCatalogChanged = errors.New("carrack VFS catalog changed while synchronizing")

// VFSCatalogSyncOptions bounds metadata paging and independent child-directory
// fetches. Zero values select safe defaults.
type VFSCatalogSyncOptions struct {
	PageSize       uint32
	MaxConcurrency uint32
}

// VFSCatalogSyncResult reports one recursively complete, root-revalidated
// local namespace DAG. FetchedNodes required control-plane reads; ReusedNodes
// were verified from the private content-addressed cache.
type VFSCatalogSyncResult struct {
	Schema          string `json:"schema"`
	RootDirectoryID string `json:"root_directory_id"`
	RootDataRoot    string `json:"root_data_root"`
	RootRevision    uint64 `json:"root_revision"`
	CacheDirectory  string `json:"cache_directory"`
	Directories     uint64 `json:"directories"`
	Entries         uint64 `json:"entries"`
	FetchedNodes    uint64 `json:"fetched_nodes"`
	ReusedNodes     uint64 `json:"reused_nodes"`
}

type vfsCatalogNodeReference struct {
	directoryID string
	dataRoot    string
}

type vfsCatalogNodeResult struct {
	reference vfsCatalogNodeReference
	node      VFSCatalogNode
	fetched   bool
	err       error
}

type vfsCatalogSyncStats struct {
	directories uint64
	entries     uint64
	fetched     uint64
	reused      uint64
}

// SyncCatalog recursively synchronizes the live namespace beneath one root
// into a private Merkle-addressed store. It always observes and revalidates the
// online root, fetches only missing directory nodes, verifies every node root,
// and never stores the bearer token or payload bytes.
func (client *VFSControlClient) SyncCatalog(
	ctx context.Context,
	rootDirectoryID string,
	store *VFSCatalogStore,
	requested VFSCatalogSyncOptions,
) (VFSCatalogSyncResult, error) {
	pageSize, workers, err := validVFSCatalogSyncOptions(rootDirectoryID, store, requested)
	if err != nil {
		return VFSCatalogSyncResult{}, err
	}

	firstPage, err := client.ListDirectory(ctx, rootDirectoryID, "", pageSize)
	if err != nil {
		return VFSCatalogSyncResult{}, fmt.Errorf("read VFS catalog root: %w", err)
	}

	rootReference := vfsCatalogNodeReference{
		directoryID: rootDirectoryID,
		dataRoot:    firstPage.Directory.DataRoot,
	}

	rootResult := client.syncVFSCatalogNode(ctx, store, rootReference, pageSize, &firstPage)
	if rootResult.err != nil {
		return VFSCatalogSyncResult{}, rootResult.err
	}

	stats := vfsCatalogSyncStats{}
	if statsErr := stats.add(rootResult); statsErr != nil {
		return VFSCatalogSyncResult{}, statsErr
	}

	seenDirectories := map[string]string{rootDirectoryID: rootReference.dataRoot}

	children, err := newVFSCatalogReferences(rootResult.node, seenDirectories)
	if err != nil {
		return VFSCatalogSyncResult{}, err
	}

	descendantStats, err := client.syncVFSCatalogDescendants(
		ctx,
		store,
		children,
		seenDirectories,
		pageSize,
		workers,
	)
	if err != nil {
		return VFSCatalogSyncResult{}, err
	}

	if statsErr := stats.merge(descendantStats); statsErr != nil {
		return VFSCatalogSyncResult{}, statsErr
	}

	finalPage, err := client.ListDirectory(ctx, rootDirectoryID, "", 1)
	if err != nil {
		return VFSCatalogSyncResult{}, fmt.Errorf("revalidate VFS catalog root: %w", err)
	}

	if finalPage.Directory.FilesystemID != firstPage.Directory.FilesystemID ||
		finalPage.Directory.Revision != firstPage.Directory.Revision ||
		finalPage.Directory.DataRoot != firstPage.Directory.DataRoot {
		return VFSCatalogSyncResult{}, ErrVFSCatalogChanged
	}

	return VFSCatalogSyncResult{
		Schema:          vfsCatalogSyncSchema,
		RootDirectoryID: rootDirectoryID,
		RootDataRoot:    rootReference.dataRoot,
		RootRevision:    firstPage.Directory.Revision,
		CacheDirectory:  store.Directory(),
		Directories:     stats.directories,
		Entries:         stats.entries,
		FetchedNodes:    stats.fetched,
		ReusedNodes:     stats.reused,
	}, nil
}

func validVFSCatalogSyncOptions(
	rootDirectoryID string,
	store *VFSCatalogStore,
	requested VFSCatalogSyncOptions,
) (pageSize, workers uint32, returnErr error) {
	if !validIdentifier(rootDirectoryID) || store == nil || store.Directory() == "" {
		return 0, 0, fmt.Errorf("%w: invalid VFS catalog synchronization", ErrInvalidControlPlane)
	}

	pageSize = requested.PageSize
	if pageSize == 0 {
		pageSize = defaultVFSCatalogPageSize
	}

	if pageSize > maximumVFSListLimit {
		return 0, 0, fmt.Errorf("%w: invalid VFS catalog page size", ErrInvalidControlPlane)
	}

	workers = requested.MaxConcurrency
	if workers == 0 {
		workers = defaultVFSCatalogWorkers
	}

	if workers > maximumVFSCatalogWorkers {
		return 0, 0, fmt.Errorf("%w: invalid VFS catalog concurrency", ErrInvalidControlPlane)
	}

	return pageSize, workers, nil
}

func (client *VFSControlClient) syncVFSCatalogNode(
	ctx context.Context,
	store *VFSCatalogStore,
	reference vfsCatalogNodeReference,
	pageSize uint32,
	initialPage *VFSDirectoryPage,
) vfsCatalogNodeResult {
	node, err := store.Load(reference.directoryID, reference.dataRoot)
	if err == nil {
		return vfsCatalogNodeResult{reference: reference, node: node}
	}

	if !errors.Is(err, ErrVFSCatalogNodeNotFound) {
		return vfsCatalogNodeResult{reference: reference, err: err}
	}

	node, err = client.fetchVFSCatalogNode(ctx, reference, pageSize, initialPage)
	if err != nil {
		return vfsCatalogNodeResult{reference: reference, err: err}
	}

	if err := store.Save(node); err != nil {
		return vfsCatalogNodeResult{reference: reference, err: err}
	}

	return vfsCatalogNodeResult{reference: reference, node: node, fetched: true}
}

func (client *VFSControlClient) fetchVFSCatalogNode(
	ctx context.Context,
	reference vfsCatalogNodeReference,
	pageSize uint32,
	initialPage *VFSDirectoryPage,
) (VFSCatalogNode, error) {
	var page VFSDirectoryPage

	var err error
	if initialPage == nil {
		page, err = client.ListDirectory(ctx, reference.directoryID, "", pageSize)
		if err != nil {
			return VFSCatalogNode{}, fmt.Errorf("read VFS catalog directory: %w", err)
		}
	} else {
		page = *initialPage
	}

	if page.Directory.ID != reference.directoryID || page.Directory.DataRoot != reference.dataRoot {
		return VFSCatalogNode{}, ErrVFSCatalogChanged
	}

	identity := page.Directory
	entries := make([]VFSCatalogEntry, 0, len(page.Entries))
	entries = appendVFSCatalogEntries(entries, page.Entries)
	cursor := page.NextCursor
	seenCursors := make(map[string]struct{})

	for cursor != "" {
		if _, duplicate := seenCursors[cursor]; duplicate {
			return VFSCatalogNode{}, fmt.Errorf("%w: VFS catalog cursor repeated", ErrControlPlaneResponse)
		}

		seenCursors[cursor] = struct{}{}

		page, err = client.ListDirectory(ctx, reference.directoryID, cursor, pageSize)
		if err != nil {
			return VFSCatalogNode{}, fmt.Errorf("continue VFS catalog directory: %w", err)
		}

		if !sameVFSCatalogDirectory(identity, page.Directory) {
			return VFSCatalogNode{}, ErrVFSCatalogChanged
		}

		entries = appendVFSCatalogEntries(entries, page.Entries)
		cursor = page.NextCursor
	}

	node := VFSCatalogNode{
		Schema:      vfsCatalogNodeSchema,
		DirectoryID: reference.directoryID,
		DataRoot:    reference.dataRoot,
		Entries:     entries,
	}
	if err := validateVFSCatalogNode(node, reference.directoryID, reference.dataRoot); err != nil {
		return VFSCatalogNode{}, fmt.Errorf("%w: control-plane directory node: %w", ErrControlPlaneResponse, err)
	}

	return node, nil
}

func (client *VFSControlClient) syncVFSCatalogDescendants(
	ctx context.Context,
	store *VFSCatalogStore,
	initial []vfsCatalogNodeReference,
	seenDirectories map[string]string,
	pageSize,
	workers uint32,
) (vfsCatalogSyncStats, error) {
	workerContext, cancel := context.WithCancel(ctx)
	jobs := make(chan vfsCatalogNodeReference)
	results := make(chan vfsCatalogNodeResult, workers)

	var waitGroup sync.WaitGroup
	for range workers {
		waitGroup.Add(1)
		go client.runVFSCatalogWorker(workerContext, &waitGroup, jobs, results, store, pageSize)
	}

	pending := append([]vfsCatalogNodeReference(nil), initial...)
	inFlight := uint32(0)
	stats := vfsCatalogSyncStats{}

	cleanup := func() {
		cancel()
		close(jobs)
		waitGroup.Wait()
	}

	for len(pending) != 0 || inFlight != 0 {
		var dispatch chan<- vfsCatalogNodeReference

		var next vfsCatalogNodeReference

		if len(pending) != 0 && inFlight < workers {
			dispatch = jobs
			next = pending[0]
		}

		select {
		case <-ctx.Done():
			cleanup()

			return vfsCatalogSyncStats{}, fmt.Errorf("synchronize VFS catalog: %w", ctx.Err())
		case dispatch <- next:
			pending = pending[1:]
			inFlight++
		case result := <-results:
			inFlight--

			if result.err != nil {
				cleanup()

				return vfsCatalogSyncStats{}, result.err
			}

			if err := stats.add(result); err != nil {
				cleanup()

				return vfsCatalogSyncStats{}, err
			}

			children, err := newVFSCatalogReferences(result.node, seenDirectories)
			if err != nil {
				cleanup()

				return vfsCatalogSyncStats{}, err
			}

			pending = append(pending, children...)
		}
	}

	cleanup()

	return stats, nil
}

func (client *VFSControlClient) runVFSCatalogWorker(
	ctx context.Context,
	waitGroup *sync.WaitGroup,
	jobs <-chan vfsCatalogNodeReference,
	results chan<- vfsCatalogNodeResult,
	store *VFSCatalogStore,
	pageSize uint32,
) {
	defer waitGroup.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case reference, open := <-jobs:
			if !open {
				return
			}

			result := client.syncVFSCatalogNode(ctx, store, reference, pageSize, nil)
			select {
			case results <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

func newVFSCatalogReferences(
	node VFSCatalogNode,
	seenDirectories map[string]string,
) ([]vfsCatalogNodeReference, error) {
	references := make([]vfsCatalogNodeReference, 0)

	for _, entry := range node.Entries {
		if entry.Kind != vfsEntryKindDirectory || entry.ChildDirectoryID == nil {
			continue
		}

		if existingRoot, seen := seenDirectories[*entry.ChildDirectoryID]; seen {
			if existingRoot != entry.DataRoot {
				return nil, fmt.Errorf("%w: directory identity has two roots", ErrVFSCatalogCorrupt)
			}

			continue
		}

		seenDirectories[*entry.ChildDirectoryID] = entry.DataRoot
		references = append(references, vfsCatalogNodeReference{
			directoryID: *entry.ChildDirectoryID,
			dataRoot:    entry.DataRoot,
		})
	}

	return references, nil
}

func appendVFSCatalogEntries(
	destination []VFSCatalogEntry,
	entries []VFSDirectoryEntry,
) []VFSCatalogEntry {
	for _, entry := range entries {
		destination = append(destination, VFSCatalogEntry{
			Name:             entry.Name,
			Kind:             entry.Kind,
			FileID:           cloneStringPointer(entry.FileID),
			VersionID:        cloneStringPointer(entry.VersionID),
			ChildDirectoryID: cloneStringPointer(entry.ChildDirectoryID),
			SizeBytes:        entry.SizeBytes,
			DataRoot:         entry.DataRoot,
			MetadataRoot:     cloneStringPointer(entry.MetadataRoot),
		})
	}

	return destination
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}

	cloned := *value

	return &cloned
}

func sameVFSCatalogDirectory(left, right VFSDirectory) bool {
	return left.ID == right.ID && left.FilesystemID == right.FilesystemID &&
		left.DataRoot == right.DataRoot && left.Revision == right.Revision
}

func (stats *vfsCatalogSyncStats) add(result vfsCatalogNodeResult) error {
	if stats == nil {
		return fmt.Errorf("%w: catalog statistics are not initialized", ErrControlPlaneResponse)
	}

	entryCount := uint64(len(result.node.Entries))
	if stats.directories == math.MaxUint64 || stats.entries > math.MaxUint64-entryCount {
		return fmt.Errorf("%w: VFS catalog statistics overflow", ErrControlPlaneResponse)
	}

	stats.directories++

	stats.entries += entryCount
	if result.fetched {
		stats.fetched++
	} else {
		stats.reused++
	}

	return nil
}

func (stats *vfsCatalogSyncStats) merge(other vfsCatalogSyncStats) error {
	if stats == nil || stats.directories > math.MaxUint64-other.directories ||
		stats.entries > math.MaxUint64-other.entries || stats.fetched > math.MaxUint64-other.fetched ||
		stats.reused > math.MaxUint64-other.reused {
		return fmt.Errorf("%w: VFS catalog statistics overflow", ErrControlPlaneResponse)
	}

	stats.directories += other.directories
	stats.entries += other.entries
	stats.fetched += other.fetched
	stats.reused += other.reused

	return nil
}
