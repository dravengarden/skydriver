//! Pure control-plane state validation shared by Worker handlers and tests.

use std::{error::Error, fmt};

const INCARNATION_HEX_BYTES: usize = 32;

/// Current mutation availability of the control plane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlMode {
    /// Normal mutations may acquire and use current leases.
    Active,
    /// Operators have disabled all mutations for maintenance.
    Maintenance,
    /// Metadata reconciliation is running after a control-plane restore.
    Recovering,
}

/// One client-supplied authority proof for a mutating request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationFence<'a> {
    /// Control-plane incarnation observed when the work was claimed.
    pub incarnation: &'a str,
    /// Unique lease identity returned by the control plane.
    pub lease_id: &'a str,
    /// Monotonic resource fencing token returned with the lease.
    pub fencing_token: u64,
}

/// The current lease record read inside the mutation transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseRecord<'a> {
    /// Incarnation in which this lease was created.
    pub incarnation: &'a str,
    /// Unique durable lease identity.
    pub lease_id: &'a str,
    /// Current monotonic token for the leased resource.
    pub fencing_token: u64,
    /// Server-time expiry as Unix seconds.
    pub expires_at: u64,
    /// Server-time release timestamp when explicitly released.
    pub released_at: Option<u64>,
}

/// Monotonic counters sent by a client for one operation attempt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProgressCounters {
    /// Total bytes read from provider transports, including retries.
    pub wire_bytes_read: u64,
    /// Total bytes written to provider transports, including retries.
    pub wire_bytes_written: u64,
    /// Unique bytes whose final identity has been verified.
    pub useful_bytes_verified: u64,
    /// Nanoseconds spent actively transferring or processing data.
    pub active_nanoseconds: u64,
    /// Total retried requests or units of work.
    pub retries: u64,
    /// Total observed provider throttling events.
    pub throttles: u64,
}

/// One ordered progress observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgressSnapshot {
    /// Monotonic attempt number for one operation component.
    pub attempt: u64,
    /// Monotonic sample sequence within the attempt.
    pub sequence: u64,
    /// Cumulative counters for this attempt.
    pub counters: ProgressCounters,
}

/// A rejected state or concurrency transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// An incarnation was not canonical random 128-bit lowercase hexadecimal.
    InvalidIncarnation,
    /// Maintenance or recovery mode currently rejects mutations.
    MutationsDisabled,
    /// A request or lease belongs to an earlier control-plane incarnation.
    StaleIncarnation,
    /// The supplied lease identifier differs from the current lease.
    LeaseMismatch,
    /// Another owner has acquired a newer fencing token.
    StaleFencingToken,
    /// The lease expired according to control-plane time.
    LeaseExpired,
    /// The lease was explicitly released.
    LeaseReleased,
    /// A progress sample belongs to another attempt.
    AttemptMismatch,
    /// A progress sample is duplicated or reordered.
    StaleSequence,
    /// At least one cumulative progress counter moved backwards.
    CounterRegression,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIncarnation => "invalid control-plane incarnation",
            Self::MutationsDisabled => "control-plane mutations are disabled",
            Self::StaleIncarnation => "stale control-plane incarnation",
            Self::LeaseMismatch => "lease identity does not match",
            Self::StaleFencingToken => "stale fencing token",
            Self::LeaseExpired => "lease has expired",
            Self::LeaseReleased => "lease has been released",
            Self::AttemptMismatch => "operation attempt does not match",
            Self::StaleSequence => "progress sequence is stale",
            Self::CounterRegression => "progress counter regressed",
        })
    }
}

impl Error for ProtocolError {}

/// Validates a random 128-bit incarnation encoded as lowercase hexadecimal.
///
/// # Errors
///
/// Returns [`ProtocolError::InvalidIncarnation`] for a malformed or all-zero
/// value.
pub fn validate_incarnation(value: &str) -> Result<(), ProtocolError> {
    if value.len() != INCARNATION_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || value.bytes().all(|byte| byte == b'0')
    {
        return Err(ProtocolError::InvalidIncarnation);
    }

    Ok(())
}

/// Checks that a request still owns a live lease in the current incarnation.
/// This check must occur in the same short D1 transaction as the mutation.
///
/// # Errors
///
/// Returns the precise mode, incarnation, identity, token, release, or expiry
/// rejection that makes the mutation stale.
pub fn authorize_mutation(
    mode: ControlMode,
    current_incarnation: &str,
    now: u64,
    supplied: MutationFence<'_>,
    lease: LeaseRecord<'_>,
) -> Result<(), ProtocolError> {
    validate_incarnation(current_incarnation)?;

    if mode != ControlMode::Active {
        return Err(ProtocolError::MutationsDisabled);
    }

    if supplied.incarnation != current_incarnation || lease.incarnation != current_incarnation {
        return Err(ProtocolError::StaleIncarnation);
    }

    if supplied.lease_id != lease.lease_id {
        return Err(ProtocolError::LeaseMismatch);
    }

    if supplied.fencing_token != lease.fencing_token {
        return Err(ProtocolError::StaleFencingToken);
    }

    if lease.released_at.is_some() {
        return Err(ProtocolError::LeaseReleased);
    }

    if lease.expires_at <= now {
        return Err(ProtocolError::LeaseExpired);
    }

    Ok(())
}

/// Accepts only a newer cumulative sample for the same attempt.
///
/// # Errors
///
/// Returns an attempt, sequence, or cumulative-counter error when accepting
/// the sample would make telemetry ambiguous.
pub fn validate_progress(
    previous: ProgressSnapshot,
    candidate: ProgressSnapshot,
) -> Result<(), ProtocolError> {
    if candidate.attempt != previous.attempt {
        return Err(ProtocolError::AttemptMismatch);
    }

    if candidate.sequence <= previous.sequence {
        return Err(ProtocolError::StaleSequence);
    }

    let old = previous.counters;
    let new = candidate.counters;
    if new.wire_bytes_read < old.wire_bytes_read
        || new.wire_bytes_written < old.wire_bytes_written
        || new.useful_bytes_verified < old.useful_bytes_verified
        || new.active_nanoseconds < old.active_nanoseconds
        || new.retries < old.retries
        || new.throttles < old.throttles
    {
        return Err(ProtocolError::CounterRegression);
    }

    Ok(())
}

/// Returns whether an operation state transition is monotonic and allowed.
#[must_use]
pub fn valid_operation_transition(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("planned", "running" | "cancelled")
            | ("running", "verifying" | "failed" | "cancelled")
            | ("verifying", "committing" | "failed" | "cancelled")
            | ("committing", "succeeded" | "failed")
    )
}

/// Returns whether a location state transition preserves immutable data.
#[must_use]
pub fn valid_location_transition(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("staging", "verified" | "quarantined")
            | ("verified", "available" | "quarantined")
            | (
                "available",
                "missing" | "corrupt" | "quarantined" | "tombstoned"
            )
            | ("missing" | "quarantined", "verified" | "tombstoned")
            | ("corrupt", "quarantined")
            | ("tombstoned", "available" | "deleted")
    )
}

#[cfg(test)]
mod tests {
    use super::{
        ControlMode, LeaseRecord, MutationFence, ProgressCounters, ProgressSnapshot, ProtocolError,
        authorize_mutation, valid_location_transition, valid_operation_transition,
        validate_incarnation, validate_progress,
    };

    const CURRENT: &str = "0123456789abcdef0123456789abcdef";
    const OLD: &str = "abcdef0123456789abcdef0123456789";

    #[test]
    fn accepts_only_canonical_nonzero_incarnations() {
        assert_eq!(validate_incarnation(CURRENT), Ok(()));

        for invalid in [
            "",
            "0123",
            "0123456789ABCDEF0123456789ABCDEF",
            "gggggggggggggggggggggggggggggggg",
            "00000000000000000000000000000000",
        ] {
            assert_eq!(
                validate_incarnation(invalid),
                Err(ProtocolError::InvalidIncarnation)
            );
        }
    }

    #[test]
    fn authorizes_only_the_current_live_fence() {
        let supplied = MutationFence {
            incarnation: CURRENT,
            lease_id: "lease-1",
            fencing_token: 8,
        };
        let lease = LeaseRecord {
            incarnation: CURRENT,
            lease_id: "lease-1",
            fencing_token: 8,
            expires_at: 200,
            released_at: None,
        };

        assert_eq!(
            authorize_mutation(ControlMode::Active, CURRENT, 100, supplied, lease),
            Ok(())
        );

        assert_eq!(
            authorize_mutation(ControlMode::Maintenance, CURRENT, 100, supplied, lease),
            Err(ProtocolError::MutationsDisabled)
        );

        let stale = MutationFence {
            incarnation: OLD,
            ..supplied
        };
        assert_eq!(
            authorize_mutation(ControlMode::Active, CURRENT, 100, stale, lease),
            Err(ProtocolError::StaleIncarnation)
        );

        let expired = LeaseRecord {
            expires_at: 100,
            ..lease
        };
        assert_eq!(
            authorize_mutation(ControlMode::Active, CURRENT, 100, supplied, expired),
            Err(ProtocolError::LeaseExpired)
        );

        let released = LeaseRecord {
            released_at: Some(90),
            ..lease
        };
        assert_eq!(
            authorize_mutation(ControlMode::Active, CURRENT, 100, supplied, released),
            Err(ProtocolError::LeaseReleased)
        );
    }

    #[test]
    fn rejects_every_stale_lease_dimension() {
        let supplied = MutationFence {
            incarnation: CURRENT,
            lease_id: "lease-1",
            fencing_token: 8,
        };
        let lease = LeaseRecord {
            incarnation: CURRENT,
            lease_id: "lease-1",
            fencing_token: 8,
            expires_at: 200,
            released_at: None,
        };

        let wrong_incarnation = LeaseRecord {
            incarnation: OLD,
            ..lease
        };
        assert_eq!(
            authorize_mutation(
                ControlMode::Active,
                CURRENT,
                100,
                supplied,
                wrong_incarnation
            ),
            Err(ProtocolError::StaleIncarnation)
        );

        let wrong_lease = LeaseRecord {
            lease_id: "lease-2",
            ..lease
        };
        assert_eq!(
            authorize_mutation(ControlMode::Active, CURRENT, 100, supplied, wrong_lease),
            Err(ProtocolError::LeaseMismatch)
        );

        let wrong_token = LeaseRecord {
            fencing_token: 9,
            ..lease
        };
        assert_eq!(
            authorize_mutation(ControlMode::Active, CURRENT, 100, supplied, wrong_token),
            Err(ProtocolError::StaleFencingToken)
        );
    }

    #[test]
    fn accepts_only_monotonic_progress_for_one_attempt() {
        let previous = ProgressSnapshot {
            attempt: 3,
            sequence: 10,
            counters: ProgressCounters {
                wire_bytes_read: 100,
                wire_bytes_written: 80,
                useful_bytes_verified: 64,
                active_nanoseconds: 1_000,
                retries: 1,
                throttles: 2,
            },
        };
        let candidate = ProgressSnapshot {
            sequence: 11,
            counters: ProgressCounters {
                wire_bytes_read: 120,
                ..previous.counters
            },
            ..previous
        };

        assert_eq!(validate_progress(previous, candidate), Ok(()));
        assert_eq!(
            validate_progress(
                previous,
                ProgressSnapshot {
                    sequence: 10,
                    ..candidate
                }
            ),
            Err(ProtocolError::StaleSequence)
        );
        assert_eq!(
            validate_progress(
                previous,
                ProgressSnapshot {
                    attempt: 4,
                    ..candidate
                }
            ),
            Err(ProtocolError::AttemptMismatch)
        );
        assert_eq!(
            validate_progress(
                previous,
                ProgressSnapshot {
                    counters: ProgressCounters {
                        useful_bytes_verified: 63,
                        ..candidate.counters
                    },
                    ..candidate
                }
            ),
            Err(ProtocolError::CounterRegression)
        );
    }

    #[test]
    fn state_machines_are_monotonic() {
        assert!(valid_operation_transition("planned", "running"));
        assert!(valid_operation_transition("running", "verifying"));
        assert!(valid_operation_transition("committing", "succeeded"));
        assert!(!valid_operation_transition("succeeded", "running"));
        assert!(!valid_operation_transition("verifying", "planned"));

        assert!(valid_location_transition("staging", "verified"));
        assert!(valid_location_transition("available", "tombstoned"));
        assert!(valid_location_transition("tombstoned", "available"));
        assert!(valid_location_transition("tombstoned", "deleted"));
        assert!(!valid_location_transition("deleted", "available"));
        assert!(!valid_location_transition("staging", "available"));
    }
}
