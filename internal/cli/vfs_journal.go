package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/driver"
	"github.com/dravengarden/carrack/transfer/journal"
)

const vfsJournalListSchema = "carrack.cli.vfs-journal-list.v1"

type vfsJournalListFlags struct {
	journalDirectory string
	outputFormat     string
}

type vfsJournalListResult struct {
	Schema   string              `json:"schema"`
	Journals []vfsJournalSummary `json:"journals"`
}

type vfsJournalSummary struct {
	JournalID        string            `json:"journal_id"`
	CreatedAt        int64             `json:"created_at"`
	Direction        journal.Direction `json:"direction"`
	Status           journal.Status    `json:"status"`
	Revision         uint64            `json:"revision"`
	DriverID         string            `json:"driver_id"`
	DriverKind       driver.Kind       `json:"driver_kind"`
	SourceReference  string            `json:"source_reference,omitempty"`
	Destination      string            `json:"destination,omitempty"`
	StorageKey       string            `json:"storage_key"`
	SizeBytes        uint64            `json:"size_bytes"`
	Checksum         string            `json:"checksum"`
	CompletedPieces  int               `json:"completed_pieces"`
	TotalPieces      int               `json:"total_pieces"`
	ProviderComplete bool              `json:"provider_complete"`
}

func newVFSJournalCommand(stdout io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "journal",
		Short: "Inspect private VFS transfer recovery journals",
	}
	command.AddCommand(newVFSJournalListCommand(stdout))

	return command
}

func newVFSJournalListCommand(stdout io.Writer) *cobra.Command {
	var flags vfsJournalListFlags

	command := &cobra.Command{
		Use:   "list",
		Short: "List validated VFS transfer journals",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			result, err := executeVFSJournalList(flags.journalDirectory, os.Getenv)
			if err != nil {
				return err
			}

			return writeVFSJournalList(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.journalDirectory, journalDirectoryFlag, "", "private durable transfer-journal directory")
	command.Flags().StringVar(&flags.outputFormat, "format", "table", "output format: table, json, or yaml")

	return command
}

func executeVFSJournalList(
	journalDirectory string,
	getenv func(string) string,
) (vfsJournalListResult, error) {
	journalPath, err := resolveVFSJournalDirectory(journalDirectory, getenv)
	if err != nil {
		return vfsJournalListResult{}, err
	}

	store, err := journal.NewStore(journalPath)
	if err != nil {
		return vfsJournalListResult{}, fmt.Errorf("open VFS journal store: %w", err)
	}

	snapshots, err := store.List()
	if err != nil {
		return vfsJournalListResult{}, fmt.Errorf("list VFS journals: %w", err)
	}

	result := vfsJournalListResult{
		Schema: vfsJournalListSchema, Journals: make([]vfsJournalSummary, 0, len(snapshots)),
	}
	for _, snapshot := range snapshots {
		result.Journals = append(result.Journals, summarizeVFSJournal(snapshot))
	}

	return result, nil
}

func summarizeVFSJournal(snapshot journal.Snapshot) vfsJournalSummary {
	summary := vfsJournalSummary{
		JournalID: snapshot.ID, CreatedAt: snapshot.CreatedAt, Direction: snapshot.Direction,
		Status: snapshot.Status, Revision: snapshot.Revision, ProviderComplete: snapshot.Object != nil,
	}

	if snapshot.Upload != nil {
		summary.DriverID = snapshot.Upload.Driver.ID
		summary.DriverKind = snapshot.Upload.Driver.Kind
		summary.SourceReference = snapshot.Upload.Source.Reference
		summary.StorageKey = snapshot.Upload.StorageKey
		summary.SizeBytes = snapshot.Upload.SizeBytes
		summary.Checksum = snapshot.Upload.Checksum
		summary.CompletedPieces = len(snapshot.CompletedParts)
		summary.TotalPieces = len(snapshot.Upload.Parts)
	}

	if snapshot.Download != nil {
		summary.DriverID = snapshot.Download.Driver.ID
		summary.DriverKind = snapshot.Download.Driver.Kind
		summary.Destination = snapshot.Download.Destination
		summary.StorageKey = snapshot.Download.Object.Locator.StorageKey
		summary.SizeBytes = snapshot.Download.Object.SizeBytes
		summary.Checksum = snapshot.Download.Checksum
		summary.CompletedPieces = len(snapshot.VerifiedBlocks)
		summary.TotalPieces = len(snapshot.Download.Blocks)
	}

	return summary
}

func resolveVFSJournalDirectory(journalDirectory string, getenv func(string) string) (string, error) {
	if getenv == nil {
		return "", errVFSEnvironment
	}

	if journalDirectory == "" {
		stateRoot := getenv("XDG_STATE_HOME")
		if stateRoot == "" {
			home := getenv("HOME")
			if home == "" {
				return "", errVFSStateHome
			}

			stateRoot = filepath.Join(home, ".local", "state")
		}

		journalDirectory = filepath.Join(stateRoot, "carrack", "vfs", "journals")
	}

	journalPath, err := filepath.Abs(journalDirectory)
	if err != nil {
		return "", fmt.Errorf("resolve VFS journal directory: %w", err)
	}

	return filepath.Clean(journalPath), nil
}

func writeVFSJournalList(writer io.Writer, outputFormat string, result vfsJournalListResult) error {
	if outputFormat != outputFormatTable {
		return writeValue(writer, outputFormat, result)
	}

	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(
		table,
		"JOURNAL ID\tCREATED AT\tSTATUS\tDRIVER\tBYTES\tPIECES\tSOURCE OR DESTINATION\tSTORAGE KEY",
	); err != nil {
		return fmt.Errorf("write VFS journal table header: %w", err)
	}

	for _, summary := range result.Journals {
		localPath := summary.SourceReference
		if localPath == "" {
			localPath = summary.Destination
		}

		if _, err := fmt.Fprintf(
			table,
			"%s\t%d\t%s\t%s\t%d\t%d/%d\t%s\t%s\n",
			summary.JournalID,
			summary.CreatedAt,
			summary.Status,
			summary.DriverID,
			summary.SizeBytes,
			summary.CompletedPieces,
			summary.TotalPieces,
			singleLineVFSJournalField(localPath),
			singleLineVFSJournalField(summary.StorageKey),
		); err != nil {
			return fmt.Errorf("write VFS journal table row: %w", err)
		}
	}

	if err := table.Flush(); err != nil {
		return fmt.Errorf("flush VFS journal table: %w", err)
	}

	return nil
}

func singleLineVFSJournalField(value string) string {
	return strings.NewReplacer("\\", "\\\\", "\t", "\\t", "\r", "\\r", "\n", "\\n").Replace(value)
}
