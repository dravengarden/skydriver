//! Shared command surface for the native Carrack binaries.

use carrack_client::{
    AdminClient, Client, EntryKind, GetOptions, OperatorCredential, Placement,
    ProtocolCompatibility, PutOptions, QuotaLimits, SyncOptions, VfsClient, VfsToken,
};
use clap::{Parser, Subcommand, ValueEnum, error::ErrorKind};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroize;

/// Stable CLI execution failures.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid non-help command-line arguments.
    #[error("invalid Carrack CLI arguments: {0}")]
    Arguments(String),
    /// Native client failure.
    #[error(transparent)]
    Client(#[from] carrack_client::Error),
    /// Structured output serialization failure.
    #[error("encode Carrack CLI output: {0}")]
    Serialize(#[from] serde_json::Error),
    /// Required private environment input is absent.
    #[error("missing private environment variable {0}")]
    MissingEnvironment(&'static str),
    /// Local input could not be read safely.
    #[error("invalid Carrack CLI input: {0}")]
    Input(String),
    /// A committed receipt did not match the effective state read back from the server.
    #[error("Carrack management verification failed: {0}")]
    Verification(String),
}

/// Selects the public filesystem or management binary identity.
#[derive(Clone, Copy, Debug)]
pub enum Surface {
    /// Simple filesystem client.
    Filesystem,
    /// Complete operator and AI-agent management client.
    Management,
}

#[derive(Debug, Parser)]
#[command(disable_help_subcommand = true)]
struct FilesystemArguments {
    /// Carrack control-plane base URL.
    #[arg(long, env = "CARRACK_CONTROL_URL", global = true)]
    control_url: Option<String>,
    #[command(subcommand)]
    command: FilesystemCommand,
}

#[derive(Debug, Parser)]
#[command(disable_help_subcommand = true)]
struct ManagementArguments {
    /// Carrack control-plane base URL.
    #[arg(long, env = "CARRACK_CONTROL_URL", global = true)]
    control_url: Option<String>,
    #[command(subcommand)]
    command: ManagementCommand,
}

#[derive(Debug, Subcommand)]
enum ManagementCommand {
    /// Print this native client version.
    Version {
        /// Output encoding.
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Verify protocol compatibility without authenticating.
    Compatibility {
        /// Output encoding.
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Read drivers, filesystems, tokens, and the audit cursor.
    Snapshot {
        /// Output encoding.
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Read one bounded audit-event page after a monotonic cursor.
    Watch {
        /// Last event ID already processed; zero starts at the retained beginning.
        #[arg(long, default_value_t = 0)]
        after: u64,
        /// Maximum events in this page.
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(1..=250))]
        limit: u64,
        /// Output encoding.
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Read one directory, its placements, entries, and recursive statistics.
    Directory {
        /// Stable directory identifier from a snapshot.
        id: String,
        /// Output encoding.
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Manage token metadata.
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Manage typed storage drivers.
    Driver {
        #[command(subcommand)]
        command: DriverCommand,
    },
    /// Validate or replace one directory or driver hard-quota policy.
    Quota {
        #[command(subcommand)]
        command: QuotaCommand,
    },
    /// Manage VFS ACLs, placements, and scoped access tokens with a root VFS token.
    Vfs {
        #[command(subcommand)]
        command: VfsManagementCommand,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum QuotaScope {
    Directory,
    Driver,
}

impl QuotaScope {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::Driver => "driver",
        }
    }
}

#[derive(Debug, Subcommand)]
enum QuotaCommand {
    /// Replace the complete hard-limit policy; omit a limit to leave it unlimited.
    Set {
        #[arg(value_enum)]
        scope: QuotaScope,
        resource_id: String,
        #[arg(long)]
        max_file_bytes: Option<u64>,
        #[arg(long)]
        max_logical_bytes: Option<u64>,
        #[arg(long)]
        max_file_count: Option<u64>,
        #[arg(long)]
        max_physical_bytes: Option<u64>,
        #[arg(long)]
        max_object_count: Option<u64>,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long)]
        check: bool,
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
}

#[derive(Debug, Subcommand)]
enum VfsManagementCommand {
    /// Read or replace one directory's direct ACL.
    Acl {
        #[command(subcommand)]
        command: VfsAclCommand,
    },
    /// Read or replace one directory's complete driver placement set.
    Placement {
        #[command(subcommand)]
        command: VfsPlacementCommand,
    },
    /// Issue or revoke a narrowed filesystem token.
    Token {
        #[command(subcommand)]
        command: VfsTokenCommand,
    },
}

#[derive(Debug, Subcommand)]
enum VfsAclCommand {
    /// Show the direct ACL and optimistic revision.
    Show {
        path: String,
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Replace all direct actions for one principal under an ACL CAS.
    Replace {
        path: String,
        #[arg(long)]
        principal_id: String,
        #[arg(long, value_delimiter = ',', num_args = 0..)]
        action: Vec<String>,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
}

#[derive(Debug, Subcommand)]
enum VfsPlacementCommand {
    /// Show the complete ordered placement policy and optimistic revision.
    Show {
        path: String,
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Replace the complete placement set using `DRIVER_ID:PRIORITY` values.
    Replace {
        path: String,
        #[arg(long = "placement", value_delimiter = ',', num_args = 1..)]
        placements: Vec<String>,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
}

#[derive(Debug, Subcommand)]
enum VfsTokenCommand {
    /// Issue one same-principal child token with strictly narrower authority.
    Issue {
        /// Directory path relative to the authenticated root token.
        root: String,
        #[arg(long, value_delimiter = ',', num_args = 1..)]
        action: Vec<String>,
        #[arg(long, value_delimiter = ',', num_args = 0..)]
        driver_id: Vec<String>,
        #[arg(long)]
        expires_at: u64,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Revoke one child token by stable ID.
    Revoke {
        token_id: String,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
}

#[derive(Debug, Subcommand)]
enum TokenCommand {
    /// Validate or apply a complete token annotation.
    Annotate {
        token_id: String,
        #[arg(long)]
        label: String,
        #[arg(long)]
        note: String,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long)]
        check: bool,
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
}

#[derive(Debug, Subcommand)]
enum DriverCommand {
    /// Enable a configured driver.
    Enable(DriverStateArguments),
    /// Disable a driver while retaining its metadata.
    Disable(DriverStateArguments),
    /// Register a new typed driver in the disabled state.
    Register {
        driver_id: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        config_file: std::path::PathBuf,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long)]
        check: bool,
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Rotate write-only driver credentials.
    Credential {
        #[command(subcommand)]
        command: DriverCredentialCommand,
    },
}

#[derive(Debug, clap::Args)]
struct DriverStateArguments {
    driver_id: String,
    #[arg(long)]
    expected_revision: u64,
    #[arg(long)]
    idempotency_key: Option<String>,
    #[arg(long)]
    check: bool,
    #[arg(long = "format", value_enum, default_value_t = Output::Json)]
    output: Output,
}

#[derive(Debug, Subcommand)]
enum DriverCredentialCommand {
    /// Validate or apply one write-only credential object.
    Set {
        driver_id: String,
        #[arg(long)]
        credential_file: std::path::PathBuf,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long)]
        check: bool,
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
}

#[derive(Debug, Subcommand)]
enum FilesystemCommand {
    /// Print this native client version.
    Version {
        /// Output encoding.
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Verify protocol compatibility without filesystem access.
    Compatibility {
        /// Output encoding.
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// List one VFS directory using a canonical absolute path.
    List {
        /// Absolute VFS path relative to the token root.
        #[arg(default_value = "/")]
        path: String,
        /// Output encoding.
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Inspect one VFS file or directory.
    Stat {
        /// Absolute VFS path relative to the token root.
        path: String,
        /// Output encoding.
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Create one empty VFS directory.
    Mkdir {
        /// Absolute VFS path relative to the token root.
        path: String,
        /// Stable identity for this exact creation request.
        #[arg(long)]
        idempotency_key: String,
        /// Output encoding.
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Upload one local file as a complete immutable VFS object.
    Put {
        /// Canonical local regular file.
        source: std::path::PathBuf,
        /// Absolute destination VFS path.
        destination: String,
        /// Expected current entry revision, or zero for creation.
        #[arg(long, default_value_t = 0)]
        expected_revision: u64,
        /// Preferred eligible driver placement.
        #[arg(long)]
        preferred_driver_id: Option<String>,
        /// Stable identity for this exact publication.
        #[arg(long)]
        idempotency_key: String,
        /// Plaintext verification block bytes.
        #[arg(long, default_value_t = 4 * 1024 * 1024)]
        verification_block_bytes: u64,
        /// Authenticated encryption frame bytes.
        #[arg(long, default_value_t = 4 * 1024 * 1024)]
        encryption_frame_bytes: u64,
        /// Private encoded-staging directory.
        #[arg(long)]
        staging_directory: Option<std::path::PathBuf>,
        /// Provider multipart/resume segment bytes.
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        transfer_part_bytes: u64,
        /// Maximum provider operations in flight.
        #[arg(long, default_value_t = 8)]
        maximum_concurrency: usize,
        /// Output encoding.
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Download, decrypt, and verify one VFS file.
    Get {
        /// Absolute source VFS path.
        source: String,
        /// Local destination that must not already exist.
        destination: std::path::PathBuf,
        /// Private encoded-download staging directory.
        #[arg(long)]
        staging_directory: Option<std::path::PathBuf>,
        /// Provider range/resume segment bytes.
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        transfer_part_bytes: u64,
        /// Maximum provider range operations in flight.
        #[arg(long, default_value_t = 8)]
        maximum_concurrency: usize,
        /// Output encoding.
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Incrementally synchronize one VFS directory into a local directory.
    Sync {
        /// Absolute source VFS directory path.
        source: String,
        /// Local destination directory.
        destination: std::path::PathBuf,
        /// Private sync state and download journal directory.
        #[arg(long)]
        state_directory: Option<std::path::PathBuf>,
        /// Provider range/resume segment bytes within each file.
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        transfer_part_bytes: u64,
        /// Maximum changed files downloaded concurrently.
        #[arg(long, default_value_t = 4)]
        maximum_concurrency: usize,
        /// Maximum provider ranges in flight within each changed file.
        #[arg(long, default_value_t = 4)]
        maximum_file_concurrency: usize,
        /// Output encoding.
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Logically remove one file or empty directory; server GC owns payload deletion.
    Remove {
        /// Absolute VFS path.
        path: String,
        /// Stable identity for this exact removal.
        #[arg(long)]
        idempotency_key: String,
        /// Output encoding.
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Atomically rename or move one VFS entry without copying payload bytes.
    Rename {
        /// Existing absolute VFS path.
        source: String,
        /// New absolute VFS path in the same filesystem.
        destination: String,
        /// Stable identity for this exact namespace mutation.
        #[arg(long)]
        idempotency_key: String,
        /// Output encoding.
        #[arg(long = "format", value_enum, default_value_t = Output::Json)]
        output: Output,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Output {
    Json,
}

#[derive(Serialize)]
struct VersionOutput<'a> {
    schema: &'a str,
    binary: &'a str,
    version: &'a str,
    protocol_epoch: u64,
}

#[derive(Serialize)]
struct FilesystemEntryOutput<'a> {
    name: &'a str,
    kind: EntryKind,
    size_bytes: u64,
    data_root: &'a str,
    updated_at: u64,
}

#[derive(Serialize)]
struct ListOutput<'a> {
    schema: &'a str,
    path: &'a str,
    data_root: &'a str,
    entries: Vec<FilesystemEntryOutput<'a>>,
}

#[derive(Serialize)]
struct StatOutput<'a> {
    schema: &'a str,
    path: &'a str,
    kind: EntryKind,
    size_bytes: u64,
    data_root: &'a str,
    updated_at: Option<u64>,
}

#[derive(Serialize)]
struct MkdirOutput<'a> {
    schema: &'a str,
    path: &'a str,
    directory_id: &'a str,
    data_root: &'a str,
    created_at: u64,
    state: &'a str,
}

#[derive(Serialize)]
struct ErrorOutput<'a> {
    schema: &'a str,
    code: &'a str,
    exit_status: u8,
    message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ErrorDisposition {
    code: &'static str,
    exit_status: u8,
}

/// Runs one native Carrack command with a stable binary identity.
///
/// # Errors
///
/// Returns an error when arguments identify an unsafe peer, compatibility
/// fails, the request cannot complete, or structured output cannot be encoded.
pub async fn run(surface: Surface) -> Result<(), Error> {
    if matches!(surface, Surface::Filesystem) {
        run_filesystem().await
    } else {
        run_management().await
    }
}

async fn run_management() -> Result<(), Error> {
    let arguments = match ManagementArguments::try_parse() {
        Ok(arguments) => arguments,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            error
                .print()
                .map_err(|print_error| Error::Arguments(print_error.to_string()))?;
            return Ok(());
        }
        Err(error) => return Err(Error::Arguments(error.to_string())),
    };
    match arguments.command {
        ManagementCommand::Version { output } => write_version(output, Surface::Management)?,
        ManagementCommand::Compatibility { output } => {
            let control_url = require_control_url(arguments.control_url)?;
            write_json(
                output,
                &Client::new(&control_url)?.check_compatibility().await?,
            )?;
        }
        ManagementCommand::Snapshot { output } => {
            let client = admin_client(arguments.control_url)?;
            client.check_compatibility().await?;
            write_json(output, &client.snapshot().await?)?;
        }
        ManagementCommand::Watch {
            after,
            limit,
            output,
        } => {
            let client = admin_client(arguments.control_url)?;
            client.check_compatibility().await?;
            write_json(output, &client.events(after, limit).await?)?;
        }
        ManagementCommand::Directory { id, output } => {
            let client = admin_client(arguments.control_url)?;
            client.check_compatibility().await?;
            write_json(output, &client.directory(&id).await?)?;
        }
        ManagementCommand::Token { command } => {
            let client = admin_client(arguments.control_url)?;
            client.check_compatibility().await?;
            run_token_command(&client, command).await?;
        }
        ManagementCommand::Driver { command } => {
            let client = admin_client(arguments.control_url)?;
            client.check_compatibility().await?;
            run_driver_command(&client, command).await?;
        }
        ManagementCommand::Quota { command } => {
            let client = admin_client(arguments.control_url)?;
            client.check_compatibility().await?;
            run_quota_command(&client, command).await?;
        }
        ManagementCommand::Vfs { command } => {
            let client = vfs_client(arguments.control_url)?;
            client.check_compatibility().await?;
            run_vfs_management_command(&client, command).await?;
        }
    }
    Ok(())
}

async fn run_quota_command(client: &AdminClient, command: QuotaCommand) -> Result<(), Error> {
    match command {
        QuotaCommand::Set {
            scope,
            resource_id,
            max_file_bytes,
            max_logical_bytes,
            max_file_count,
            max_physical_bytes,
            max_object_count,
            expected_revision,
            idempotency_key,
            check,
            output,
        } => {
            let limits = QuotaLimits {
                max_file_bytes,
                max_logical_bytes,
                max_file_count,
                max_physical_bytes,
                max_object_count,
            };
            let validation = client
                .validate_quota(scope.as_str(), &resource_id, &limits, expected_revision)
                .await?;
            if check {
                write_json(output, &validation)?;
                return Ok(());
            }
            let idempotency_key = require_idempotency_key(idempotency_key)?;
            let receipt = client.apply_quota(&validation, &idempotency_key).await?;
            let snapshot = client.snapshot().await?;
            let matches = if matches!(scope, QuotaScope::Driver) {
                snapshot.drivers.iter().any(|driver| {
                    driver.id == resource_id
                        && driver.quota_revision == receipt.final_revision
                        && driver.max_physical_bytes == receipt.limits.max_physical_bytes
                        && driver.max_object_count == receipt.limits.max_object_count
                })
            } else {
                let directory = client.directory(&resource_id).await?;
                directory.directory.quota_revision == receipt.final_revision
                    && directory.directory.max_file_bytes == receipt.limits.max_file_bytes
                    && directory.directory.max_logical_bytes == receipt.limits.max_logical_bytes
                    && directory.directory.max_file_count == receipt.limits.max_file_count
            };
            if !matches {
                return Err(Error::Verification(format!(
                    "quota {} did not match receipt {}",
                    resource_id, receipt.operation_id
                )));
            }
            write_json(output, &receipt)?;
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the agent management surface keeps each validated mutation explicit"
)]
async fn run_vfs_management_command(
    client: &VfsClient,
    command: VfsManagementCommand,
) -> Result<(), Error> {
    match command {
        VfsManagementCommand::Acl { command } => match command {
            VfsAclCommand::Show { path, output } => write_json(output, &client.acl(&path).await?)?,
            VfsAclCommand::Replace {
                path,
                principal_id,
                action,
                expected_revision,
                idempotency_key,
                output,
            } => write_json(
                output,
                &client
                    .replace_acl(
                        &path,
                        &principal_id,
                        action,
                        expected_revision,
                        &idempotency_key,
                    )
                    .await?,
            )?,
        },
        VfsManagementCommand::Placement { command } => match command {
            VfsPlacementCommand::Show { path, output } => {
                write_json(output, &client.placements(&path).await?)?;
            }
            VfsPlacementCommand::Replace {
                path,
                placements,
                expected_revision,
                idempotency_key,
                output,
            } => {
                let placements = placements
                    .into_iter()
                    .map(|encoded| {
                        let (driver_id, priority) = encoded.rsplit_once(':').ok_or_else(|| {
                            Error::Arguments(format!(
                                "invalid placement {encoded:?}; expected DRIVER_ID:PRIORITY"
                            ))
                        })?;
                        if driver_id.is_empty() {
                            return Err(Error::Arguments(
                                "placement driver ID is empty".to_owned(),
                            ));
                        }
                        let write_priority = priority.parse::<u64>().map_err(|_| {
                            Error::Arguments(format!("invalid placement priority in {encoded:?}"))
                        })?;
                        Ok(Placement {
                            driver_id: driver_id.to_owned(),
                            write_priority,
                        })
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                write_json(
                    output,
                    &client
                        .replace_placements(&path, placements, expected_revision, &idempotency_key)
                        .await?,
                )?;
            }
        },
        VfsManagementCommand::Token { command } => match command {
            VfsTokenCommand::Issue {
                root,
                action,
                driver_id,
                expires_at,
                idempotency_key,
                output,
            } => {
                let resolved = client.resolve(&root).await?;
                let root_directory_id = match resolved.entry {
                    None => resolved.parent.id,
                    Some(entry) if entry.kind == EntryKind::Directory => {
                        entry.child_directory_id.ok_or_else(|| {
                            Error::Input("directory identity is missing".to_owned())
                        })?
                    }
                    Some(_) => {
                        return Err(Error::Input("token root must be a directory".to_owned()));
                    }
                };
                let drivers = (!driver_id.is_empty()).then_some(driver_id);
                let mut issued = client
                    .issue_token(
                        &root_directory_id,
                        action,
                        drivers,
                        expires_at,
                        &idempotency_key,
                    )
                    .await?;
                write_json(output, &issued)?;
                issued.zeroize();
            }
            VfsTokenCommand::Revoke {
                token_id,
                idempotency_key,
                output,
            } => {
                write_json(
                    output,
                    &client.revoke_token(&token_id, &idempotency_key).await?,
                )?;
            }
        },
    }
    Ok(())
}

async fn run_token_command(client: &AdminClient, command: TokenCommand) -> Result<(), Error> {
    match command {
        TokenCommand::Annotate {
            token_id,
            label,
            note,
            expected_revision,
            idempotency_key,
            check,
            output,
        } => {
            let validation = client
                .validate_token_annotation(&token_id, &label, &note, expected_revision)
                .await?;
            if check {
                write_json(output, &validation)?;
            } else {
                let idempotency_key = require_idempotency_key(idempotency_key)?;
                let receipt = client
                    .apply_token_annotation(&validation, &idempotency_key)
                    .await?;
                let snapshot = client.snapshot().await?;
                let effective = snapshot
                    .tokens
                    .iter()
                    .find(|token| token.id == receipt.token_id);
                if !effective.is_some_and(|token| {
                    token.metadata_revision == receipt.final_revision
                        && token.label == receipt.label
                        && token.note == receipt.note
                }) {
                    return Err(Error::Verification(format!(
                        "token {} did not match receipt {}",
                        receipt.token_id, receipt.operation_id
                    )));
                }
                write_json(output, &receipt)?;
            }
        }
    }
    Ok(())
}

async fn run_driver_command(client: &AdminClient, command: DriverCommand) -> Result<(), Error> {
    match command {
        DriverCommand::Enable(arguments) => run_driver_state(client, arguments, true).await?,
        DriverCommand::Disable(arguments) => run_driver_state(client, arguments, false).await?,
        DriverCommand::Register {
            driver_id,
            kind,
            config_file,
            idempotency_key,
            check,
            output,
        } => {
            let config = read_json_object(&config_file, false)?;
            let validation = client
                .validate_driver_registration(&driver_id, &kind, &config)
                .await?;
            if check {
                write_json(output, &validation)?;
            } else {
                let idempotency_key = require_idempotency_key(idempotency_key)?;
                let receipt = client
                    .apply_driver_registration(&validation, &idempotency_key)
                    .await?;
                let snapshot = client.snapshot().await?;
                let effective = snapshot
                    .drivers
                    .iter()
                    .find(|driver| driver.id == receipt.driver_id);
                if !effective.is_some_and(|driver| {
                    driver.revision == receipt.final_revision
                        && driver.kind == receipt.kind
                        && driver.config == receipt.config
                        && driver.enabled == receipt.enabled
                }) {
                    return Err(Error::Verification(format!(
                        "driver {} did not match receipt {}",
                        receipt.driver_id, receipt.operation_id
                    )));
                }
                write_json(output, &receipt)?;
            }
        }
        DriverCommand::Credential { command } => match command {
            DriverCredentialCommand::Set {
                driver_id,
                credential_file,
                expected_revision,
                idempotency_key,
                check,
                output,
            } => {
                let mut credential = read_json_object(&credential_file, true)?;
                let validation = client
                    .validate_driver_credential(&driver_id, &credential, expected_revision)
                    .await?;
                if check {
                    credential = Value::Null;
                    write_json(output, &validation)?;
                } else {
                    let idempotency_key = require_idempotency_key(idempotency_key)?;
                    let receipt = client
                        .apply_driver_credential(&validation, &credential, &idempotency_key)
                        .await?;
                    credential = Value::Null;
                    let snapshot = client.snapshot().await?;
                    let effective = snapshot
                        .drivers
                        .iter()
                        .find(|driver| driver.id == receipt.driver_id);
                    if !effective.is_some_and(|driver| {
                        driver.revision == receipt.final_revision
                            && driver.credential_present
                            && driver.credential_rotated_at == Some(receipt.rotated_at)
                            && driver.credential_expires_at == Some(receipt.credential_expires_at)
                            && driver.credential_refresh_token_expires_at
                                == Some(receipt.refresh_token_expires_at)
                    }) {
                        return Err(Error::Verification(format!(
                            "driver credential {} did not match receipt {}",
                            receipt.driver_id, receipt.operation_id
                        )));
                    }
                    write_json(output, &receipt)?;
                }
                drop(credential);
            }
        },
    }
    Ok(())
}

async fn run_driver_state(
    client: &AdminClient,
    arguments: DriverStateArguments,
    enabled: bool,
) -> Result<(), Error> {
    let validation = client
        .validate_driver_state(&arguments.driver_id, enabled, arguments.expected_revision)
        .await?;
    if arguments.check {
        write_json(arguments.output, &validation)?;
    } else {
        let idempotency_key = require_idempotency_key(arguments.idempotency_key)?;
        let receipt = client
            .apply_driver_state(&validation, &idempotency_key)
            .await?;
        let snapshot = client.snapshot().await?;
        let effective = snapshot
            .drivers
            .iter()
            .find(|driver| driver.id == receipt.driver_id);
        if !effective.is_some_and(|driver| {
            driver.revision == receipt.final_revision && driver.enabled == receipt.enabled
        }) {
            return Err(Error::Verification(format!(
                "driver {} did not match receipt {}",
                receipt.driver_id, receipt.operation_id
            )));
        }
        write_json(arguments.output, &receipt)?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the filesystem command dispatcher keeps Clap ownership and output schemas explicit"
)]
async fn run_filesystem() -> Result<(), Error> {
    let arguments = match FilesystemArguments::try_parse() {
        Ok(arguments) => arguments,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            error
                .print()
                .map_err(|print_error| Error::Arguments(print_error.to_string()))?;
            return Ok(());
        }
        Err(error) => return Err(Error::Arguments(error.to_string())),
    };
    match arguments.command {
        FilesystemCommand::Version { output } => write_version(output, Surface::Filesystem)?,
        FilesystemCommand::Compatibility { output } => {
            let control_url = require_control_url(arguments.control_url)?;
            let compatibility = Client::new(&control_url)?.check_compatibility().await?;
            write_json(output, &compatibility)?;
        }
        FilesystemCommand::List { path, output } => {
            let client = vfs_client(arguments.control_url)?;
            client.check_compatibility().await?;
            let page = client.list_path(&path).await?;
            let entries = page
                .entries
                .iter()
                .map(|entry| FilesystemEntryOutput {
                    name: &entry.name,
                    kind: entry.kind,
                    size_bytes: entry.size_bytes,
                    data_root: &entry.data_root,
                    updated_at: entry.updated_at,
                })
                .collect();
            write_json(
                output,
                &ListOutput {
                    schema: "carrack.fs-list.v1",
                    path: &path,
                    data_root: &page.directory.data_root,
                    entries,
                },
            )?;
        }
        FilesystemCommand::Stat { path, output } => {
            let client = vfs_client(arguments.control_url)?;
            client.check_compatibility().await?;
            let resolved = client.resolve(&path).await?;
            let stat = match &resolved.entry {
                Some(entry) => StatOutput {
                    schema: "carrack.fs-stat.v1",
                    path: &path,
                    kind: entry.kind,
                    size_bytes: entry.size_bytes,
                    data_root: &entry.data_root,
                    updated_at: Some(entry.updated_at),
                },
                None => StatOutput {
                    schema: "carrack.fs-stat.v1",
                    path: &path,
                    kind: EntryKind::Directory,
                    size_bytes: 0,
                    data_root: &resolved.parent.data_root,
                    updated_at: None,
                },
            };
            write_json(output, &stat)?;
        }
        FilesystemCommand::Mkdir {
            path,
            idempotency_key,
            output,
        } => {
            let client = vfs_client(arguments.control_url)?;
            client.check_compatibility().await?;
            let receipt = client.mkdir(&path, &idempotency_key).await?;
            write_json(
                output,
                &MkdirOutput {
                    schema: "carrack.fs-mkdir.v1",
                    path: &path,
                    directory_id: &receipt.directory_id,
                    data_root: &receipt.data_root,
                    created_at: receipt.created_at,
                    state: &receipt.state,
                },
            )?;
        }
        FilesystemCommand::Put {
            source,
            destination,
            expected_revision,
            preferred_driver_id,
            idempotency_key,
            verification_block_bytes,
            encryption_frame_bytes,
            staging_directory,
            transfer_part_bytes,
            maximum_concurrency,
            output,
        } => {
            let client = vfs_client(arguments.control_url)?;
            client.check_compatibility().await?;
            let staging_directory = match staging_directory {
                Some(path) => path,
                None => default_state_directory()?.join("staging"),
            };
            let result = client
                .put_file(
                    &source,
                    &destination,
                    &PutOptions {
                        expected_entry_revision: expected_revision,
                        preferred_driver_id,
                        idempotency_key,
                        verification_block_bytes,
                        encryption_frame_bytes,
                        staging_directory,
                        transfer_part_bytes,
                        maximum_concurrency,
                    },
                )
                .await?;
            write_json(output, &result)?;
        }
        FilesystemCommand::Get {
            source,
            destination,
            staging_directory,
            transfer_part_bytes,
            maximum_concurrency,
            output,
        } => {
            let client = vfs_client(arguments.control_url)?;
            client.check_compatibility().await?;
            let staging_directory = match staging_directory {
                Some(path) => path,
                None => default_state_directory()?.join("downloads"),
            };
            write_json(
                output,
                &client
                    .get_file(
                        &source,
                        &destination,
                        &GetOptions {
                            staging_directory,
                            transfer_part_bytes,
                            maximum_concurrency,
                        },
                    )
                    .await?,
            )?;
        }
        FilesystemCommand::Sync {
            source,
            destination,
            state_directory,
            transfer_part_bytes,
            maximum_concurrency,
            maximum_file_concurrency,
            output,
        } => {
            let client = vfs_client(arguments.control_url)?;
            client.check_compatibility().await?;
            let state_directory =
                state_directory.unwrap_or(default_state_directory()?.join("sync"));
            write_json(
                output,
                &client
                    .sync_to_local(
                        &source,
                        &destination,
                        &SyncOptions {
                            state_directory,
                            transfer_part_bytes,
                            maximum_concurrency,
                            maximum_file_concurrency,
                        },
                    )
                    .await?,
            )?;
        }
        FilesystemCommand::Remove {
            path,
            idempotency_key,
            output,
        } => {
            let client = vfs_client(arguments.control_url)?;
            client.check_compatibility().await?;
            write_json(output, &client.remove(&path, &idempotency_key).await?)?;
        }
        FilesystemCommand::Rename {
            source,
            destination,
            idempotency_key,
            output,
        } => {
            let client = vfs_client(arguments.control_url)?;
            client.check_compatibility().await?;
            write_json(
                output,
                &client
                    .rename(&source, &destination, &idempotency_key)
                    .await?,
            )?;
        }
    }
    Ok(())
}

fn write_version(output: Output, surface: Surface) -> Result<(), Error> {
    write_json(
        output,
        &VersionOutput {
            schema: "carrack.cli-version.v1",
            binary: match surface {
                Surface::Filesystem => "carrack",
                Surface::Management => "carrackctl",
            },
            version: env!("CARGO_PKG_VERSION"),
            protocol_epoch: carrack_client::PROTOCOL_EPOCH,
        },
    )
}

fn require_control_url(control_url: Option<String>) -> Result<String, Error> {
    control_url.ok_or(Error::MissingEnvironment(
        "CARRACK_CONTROL_URL or --control-url",
    ))
}

fn vfs_client(control_url: Option<String>) -> Result<VfsClient, Error> {
    let endpoint = require_control_url(control_url)?;
    let encoded = std::env::var("CARRACK_VFS_TOKEN")
        .map_err(|_| Error::MissingEnvironment("CARRACK_VFS_TOKEN"))?;
    Ok(VfsClient::new(&endpoint, VfsToken::parse(&encoded)?)?)
}

fn admin_client(control_url: Option<String>) -> Result<AdminClient, Error> {
    let endpoint = require_control_url(control_url)?;
    let encoded = std::env::var("CARRACK_OPERATOR_CREDENTIAL")
        .map_err(|_| Error::MissingEnvironment("CARRACK_OPERATOR_CREDENTIAL"))?;
    Ok(AdminClient::new(
        &endpoint,
        OperatorCredential::parse(&encoded)?,
    )?)
}

fn default_state_directory() -> Result<std::path::PathBuf, Error> {
    if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(std::path::PathBuf::from(path).join("carrack"));
    }
    std::env::var_os("HOME")
        .map(|home| std::path::PathBuf::from(home).join(".local/state/carrack"))
        .ok_or(Error::MissingEnvironment("XDG_STATE_HOME or HOME"))
}

fn require_idempotency_key(key: Option<String>) -> Result<String, Error> {
    let key = key.ok_or_else(|| {
        Error::Arguments("--idempotency-key is required unless --check is used".to_owned())
    })?;
    if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
        return Err(Error::Arguments("invalid idempotency key".to_owned()));
    }
    Ok(key)
}

fn read_json_object(path: &std::path::Path, secret: bool) -> Result<Value, Error> {
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path)
            .map_err(|error| Error::Input(format!("inspect {}: {error}", path.display())))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(Error::Input(format!(
                "secret file {} must not be accessible by group or others",
                path.display()
            )));
        }
    }
    let mut bytes = std::fs::read(path)
        .map_err(|error| Error::Input(format!("read {}: {error}", path.display())))?;
    if bytes.len() > 64 * 1024 {
        bytes.zeroize();
        return Err(Error::Input("JSON input exceeds 64 KiB".to_owned()));
    }
    let parsed = serde_json::from_slice::<Value>(&bytes)
        .map_err(|error| Error::Input(format!("parse {}: {error}", path.display())));
    bytes.zeroize();
    let value = parsed?;
    if !value.is_object() {
        return Err(Error::Input("JSON input must be one object".to_owned()));
    }
    Ok(value)
}

/// Prints one stable JSON error and terminates with a failure status.
///
/// This function never returns.
pub fn exit_with_error(error: &Error) -> ! {
    let disposition = error_disposition(error);
    let output = ErrorOutput {
        schema: "carrack.cli-error.v1",
        code: disposition.code,
        exit_status: disposition.exit_status,
        message: error.to_string(),
    };
    match serde_json::to_string(&output) {
        Ok(encoded) => eprintln!("{encoded}"),
        Err(_) => eprintln!(
            "{{\"schema\":\"carrack.cli-error.v1\",\"code\":\"internal_output_error\",\"exit_status\":13,\"message\":\"encode Carrack CLI error\"}}"
        ),
    }
    std::process::exit(i32::from(disposition.exit_status));
}

fn error_disposition(error: &Error) -> ErrorDisposition {
    let (code, exit_status) = match error {
        Error::Arguments(_) => ("invalid_arguments", 2),
        Error::Input(_) => ("invalid_input", 3),
        Error::Client(carrack_client::Error::InvalidEndpoint(_)) => ("invalid_control_plane", 4),
        Error::Client(carrack_client::Error::UpgradeRequired(_)) => ("sdk_upgrade_required", 5),
        Error::Client(
            carrack_client::Error::InvalidCompatibility(_)
            | carrack_client::Error::InvalidResponse(_),
        ) => ("invalid_control_plane_response", 6),
        Error::Client(carrack_client::Error::Rejected {
            status: 401 | 403, ..
        }) => ("permission_denied", 7),
        Error::Client(carrack_client::Error::Rejected { status: 404, .. }) => ("not_found", 8),
        Error::Client(carrack_client::Error::Rejected { status: 409, .. }) => {
            ("revision_conflict", 9)
        }
        Error::Client(carrack_client::Error::Rejected { .. }) => ("request_rejected", 10),
        Error::Client(carrack_client::Error::Transport(_)) => ("control_plane_transport_error", 11),
        Error::Verification(_) => ("management_verification_failed", 12),
        Error::Serialize(_) => ("internal_output_error", 13),
        Error::MissingEnvironment(_) => ("missing_environment", 14),
    };
    ErrorDisposition { code, exit_status }
}

#[cfg(test)]
fn error_json(error: &Error) -> Result<String, serde_json::Error> {
    let disposition = error_disposition(error);
    serde_json::to_string(&ErrorOutput {
        schema: "carrack.cli-error.v1",
        code: disposition.code,
        exit_status: disposition.exit_status,
        message: error.to_string(),
    })
}

#[cfg(test)]
fn rejected_error(status: u16) -> Error {
    Error::Client(carrack_client::Error::Rejected {
        status,
        message: "test rejection".to_owned(),
    })
}

#[cfg(test)]
fn assert_error_disposition(error: &Error, code: &str, exit_status: u8) {
    let disposition = error_disposition(error);
    assert_eq!(disposition.code, code);
    assert_eq!(disposition.exit_status, exit_status);
    let encoded = error_json(error).expect("encode CLI error");
    let decoded: Value = serde_json::from_str(&encoded).expect("decode CLI error");
    assert_eq!(decoded["schema"], "carrack.cli-error.v1");
    assert_eq!(decoded["code"], code);
    assert_eq!(decoded["exit_status"], u64::from(exit_status));
}

fn write_json<T: Serialize>(output: Output, value: &T) -> Result<(), Error> {
    match output {
        Output::Json => println!("{}", serde_json::to_string_pretty(value)?),
    }
    Ok(())
}

/// Serializes compatibility output for contract tests and embedding.
///
/// # Errors
///
/// Returns an error when the stable JSON response cannot be encoded.
pub fn compatibility_json(value: &ProtocolCompatibility) -> Result<String, Error> {
    Ok(serde_json::to_string(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn native_cli_does_not_expose_provider_or_gc_internals() {
        let command = FilesystemArguments::command();
        let names = command
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "version",
                "compatibility",
                "list",
                "stat",
                "mkdir",
                "put",
                "get",
                "sync",
                "remove",
                "rename"
            ]
        );
        assert!(
            !names
                .iter()
                .any(|name| matches!(*name, "gc" | "janitor" | "driver-grant"))
        );
    }

    #[test]
    fn management_cli_exposes_bounded_event_watch() {
        let command = ManagementArguments::command();
        let names = command
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect::<Vec<_>>();
        assert!(names.contains(&"watch"));
    }

    #[test]
    fn exposes_stable_machine_readable_exit_statuses() {
        assert_error_disposition(
            &Error::Arguments("invalid".to_owned()),
            "invalid_arguments",
            2,
        );
        assert_error_disposition(&Error::Input("invalid".to_owned()), "invalid_input", 3);
        assert_error_disposition(
            &Error::Client(carrack_client::Error::InvalidEndpoint("invalid".to_owned())),
            "invalid_control_plane",
            4,
        );
        assert_error_disposition(
            &Error::Client(carrack_client::Error::UpgradeRequired(Box::new(
                carrack_client::UpgradeRequired {
                    schema: "carrack.protocol-error.v1".to_owned(),
                    code: "sdk_upgrade_required".to_owned(),
                    message: "upgrade".to_owned(),
                    protocol_epoch: 2,
                    minimum_sdk_version: "1.0.0".to_owned(),
                    server_version: "1.0.0".to_owned(),
                    upgrade_command: "upgrade carrack".to_owned(),
                },
            ))),
            "sdk_upgrade_required",
            5,
        );
        assert_error_disposition(
            &Error::Client(carrack_client::Error::InvalidResponse("invalid".to_owned())),
            "invalid_control_plane_response",
            6,
        );
        assert_error_disposition(&rejected_error(401), "permission_denied", 7);
        assert_error_disposition(&rejected_error(404), "not_found", 8);
        assert_error_disposition(&rejected_error(409), "revision_conflict", 9);
        assert_error_disposition(&rejected_error(422), "request_rejected", 10);
        assert_error_disposition(
            &Error::Verification("mismatch".to_owned()),
            "management_verification_failed",
            12,
        );
        assert_error_disposition(
            &Error::MissingEnvironment("CARRACK_VFS_TOKEN"),
            "missing_environment",
            14,
        );
    }
}
