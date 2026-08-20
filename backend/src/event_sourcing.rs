// #151 — Event Sourcing: Append-Only Log, Snapshots, Versioning, Replay
//
// Design:
//  - EventLog is the single source of truth — events are never mutated or deleted.
//  - Each event carries a monotonically increasing `sequence` number and a
//    `schema_version` field so consumers can handle format upgrades.
//  - Snapshots capture a point-in-time vault state to bound replay cost.
//  - EventReplayer rebuilds vault state by applying events from a snapshot (or
//    from the beginning) forward.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::models::{EventType, Vault, VaultEvent, VaultStatus};

// ── Schema version ────────────────────────────────────────────────────────────

/// Current schema version for new events.  Bump this when the `data` payload
/// shape changes in a breaking way and add a migration arm in
/// `migrate_event_data`.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

// ── Versioned / append-only event ────────────────────────────────────────────

/// An immutable, versioned event stored in the append-only log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    /// Vault this event belongs to.
    pub vault_id: String,
    /// Monotonically increasing per-vault sequence number (1-based).
    pub sequence: u64,
    /// Event category.
    pub event_type: EventType,
    /// Wall-clock time the event was appended.
    pub timestamp: DateTime<Utc>,
    /// Arbitrary JSON payload whose shape is governed by `schema_version`.
    pub data: serde_json::Value,
    /// Schema version of `data` at the time this event was written.
    pub schema_version: u32,
}

impl StoredEvent {
    /// Create a new event for appending.  `sequence` is assigned by the log.
    pub fn new(
        vault_id: impl Into<String>,
        sequence: u64,
        event_type: EventType,
        data: serde_json::Value,
    ) -> Self {
        Self {
            vault_id: vault_id.into(),
            sequence,
            event_type,
            timestamp: Utc::now(),
            data,
            schema_version: CURRENT_SCHEMA_VERSION,
        }
    }

    /// Migrate the event's data payload to the current schema version.
    /// Add new `match` arms here when `CURRENT_SCHEMA_VERSION` is bumped.
    pub fn migrate_to_current(mut self) -> Self {
        if self.schema_version == CURRENT_SCHEMA_VERSION {
            return self;
        }
        // Example migration: v0 → v1 renamed "amount" to "balance_delta"
        if self.schema_version == 0 {
            if let Some(obj) = self.data.as_object_mut() {
                if let Some(v) = obj.remove("amount") {
                    obj.insert("balance_delta".into(), v);
                }
            }
            self.schema_version = 1;
        }
        self
    }
}

// ── Append-only log ───────────────────────────────────────────────────────────

/// Thread-safe, append-only event log.
///
/// Invariants:
///  - Events are only ever appended; existing entries are never modified.
///  - The per-vault `next_sequence` counter strictly increases.
#[derive(Debug, Clone)]
pub struct EventLog {
    /// All stored events, ordered by insertion (global append order).
    events: Arc<Mutex<Vec<StoredEvent>>>,
    /// Per-vault next sequence number.
    sequences: Arc<Mutex<HashMap<String, u64>>>,
}

impl EventLog {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
            sequences: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Append a new event.  Returns the assigned sequence number.
    ///
    /// This is the **only** way to add events — there is no update or delete.
    pub fn append(
        &self,
        vault_id: impl Into<String>,
        event_type: EventType,
        data: serde_json::Value,
    ) -> Result<u64, EventSourcingError> {
        let vault_id = vault_id.into();

        let seq = {
            let mut seqs = self
                .sequences
                .lock()
                .map_err(|_| EventSourcingError::LockPoisoned)?;
            let next = seqs.entry(vault_id.clone()).or_insert(1);
            let assigned = *next;
            *next += 1;
            assigned
        };

        let event = StoredEvent::new(vault_id, seq, event_type, data);

        self.events
            .lock()
            .map_err(|_| EventSourcingError::LockPoisoned)?
            .push(event);

        Ok(seq)
    }

    /// Return all events for a vault, ordered by sequence ascending.
    pub fn events_for_vault(&self, vault_id: &str) -> Result<Vec<StoredEvent>, EventSourcingError> {
        let guard = self
            .events
            .lock()
            .map_err(|_| EventSourcingError::LockPoisoned)?;
        let mut result: Vec<StoredEvent> = guard
            .iter()
            .filter(|e| e.vault_id == vault_id)
            .cloned()
            .collect();
        result.sort_by_key(|e| e.sequence);
        Ok(result)
    }

    /// Return events for a vault with sequence > `after_sequence`.
    pub fn events_after(
        &self,
        vault_id: &str,
        after_sequence: u64,
    ) -> Result<Vec<StoredEvent>, EventSourcingError> {
        let all = self.events_for_vault(vault_id)?;
        Ok(all
            .into_iter()
            .filter(|e| e.sequence > after_sequence)
            .collect())
    }

    /// Total number of events across all vaults.
    pub fn len(&self) -> Result<usize, EventSourcingError> {
        Ok(self
            .events
            .lock()
            .map_err(|_| EventSourcingError::LockPoisoned)?
            .len())
    }

    /// Convert from the legacy `VaultEvent` format used by `EventStore`.
    pub fn import_legacy_event(&self, e: &VaultEvent) -> Result<u64, EventSourcingError> {
        self.append(e.vault_id.clone(), e.event_type.clone(), e.data.clone())
    }
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new()
    }
}

// ── Snapshots ─────────────────────────────────────────────────────────────────

/// A point-in-time snapshot of a vault's materialized state.
///
/// Replay starts from the snapshot (if one exists) and then applies only the
/// events that followed it, bounding the work required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSnapshot {
    pub vault_id: String,
    /// The sequence number of the last event applied before this snapshot was
    /// captured.  Replay should resume with `sequence > snapshot_sequence`.
    pub snapshot_sequence: u64,
    /// Wall-clock time the snapshot was taken.
    pub taken_at: DateTime<Utc>,
    /// Serialized vault state at `snapshot_sequence`.
    pub state: SnapshotState,
}

/// The vault fields we reconstruct via event replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotState {
    pub balance: i128,
    pub status: VaultStatus,
    pub last_check_in: DateTime<Utc>,
    pub ttl_remaining: Option<u64>,
}

impl SnapshotState {
    pub fn initial(vault: &Vault) -> Self {
        Self {
            balance: vault.balance,
            status: vault.status.clone(),
            last_check_in: vault.last_check_in,
            ttl_remaining: vault.ttl_remaining,
        }
    }
}

/// Thread-safe snapshot store keyed by vault ID.
#[derive(Debug, Clone, Default)]
pub struct SnapshotStore {
    snapshots: Arc<Mutex<HashMap<String, VaultSnapshot>>>,
}

impl SnapshotStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Persist a new snapshot, replacing any previous one for the vault.
    pub fn save(&self, snapshot: VaultSnapshot) -> Result<(), EventSourcingError> {
        self.snapshots
            .lock()
            .map_err(|_| EventSourcingError::LockPoisoned)?
            .insert(snapshot.vault_id.clone(), snapshot);
        Ok(())
    }

    /// Retrieve the latest snapshot for a vault, if any.
    pub fn get(&self, vault_id: &str) -> Result<Option<VaultSnapshot>, EventSourcingError> {
        Ok(self
            .snapshots
            .lock()
            .map_err(|_| EventSourcingError::LockPoisoned)?
            .get(vault_id)
            .cloned())
    }

    /// Create a snapshot from the current vault state and the sequence number
    /// of the last applied event.
    pub fn take_snapshot(
        &self,
        vault: &Vault,
        last_sequence: u64,
    ) -> Result<(), EventSourcingError> {
        let snapshot = VaultSnapshot {
            vault_id: vault.id.clone(),
            snapshot_sequence: last_sequence,
            taken_at: Utc::now(),
            state: SnapshotState::initial(vault),
        };
        self.save(snapshot)
    }
}

// ── Event replay ──────────────────────────────────────────────────────────────

/// Replay engine: rebuilds vault state from snapshots + events.
pub struct EventReplayer<'a> {
    log: &'a EventLog,
    snapshots: &'a SnapshotStore,
}

impl<'a> EventReplayer<'a> {
    pub fn new(log: &'a EventLog, snapshots: &'a SnapshotStore) -> Self {
        Self { log, snapshots }
    }

    /// Reconstruct the latest vault state for `vault_id`.
    ///
    /// Strategy:
    ///  1. Load the most recent snapshot (if any).
    ///  2. Fetch events with sequence > snapshot_sequence.
    ///  3. Apply each event in order.
    pub fn replay(&self, vault_id: &str) -> Result<ReplayedState, EventSourcingError> {
        // Step 1 — baseline state
        let (mut state, start_seq) = match self.snapshots.get(vault_id)? {
            Some(snap) => (snap.state, snap.snapshot_sequence),
            None => (
                SnapshotState {
                    balance: 0,
                    status: VaultStatus::Active,
                    last_check_in: Utc::now(),
                    ttl_remaining: None,
                },
                0,
            ),
        };

        // Step 2 — events after snapshot
        let events = self.log.events_after(vault_id, start_seq)?;
        let event_count = events.len();
        let last_sequence = events.last().map(|e| e.sequence).unwrap_or(start_seq);

        // Step 3 — apply
        for raw in events {
            let event = raw.migrate_to_current();
            apply_event(&mut state, &event);
        }

        Ok(ReplayedState {
            vault_id: vault_id.to_string(),
            state,
            last_sequence,
            events_applied: event_count,
        })
    }

    /// Replay up to (and including) a specific sequence number — useful for
    /// point-in-time audits.
    pub fn replay_to(
        &self,
        vault_id: &str,
        target_sequence: u64,
    ) -> Result<ReplayedState, EventSourcingError> {
        let (mut state, start_seq) = match self.snapshots.get(vault_id)? {
            Some(snap) if snap.snapshot_sequence <= target_sequence => {
                (snap.state, snap.snapshot_sequence)
            }
            _ => (
                SnapshotState {
                    balance: 0,
                    status: VaultStatus::Active,
                    last_check_in: Utc::now(),
                    ttl_remaining: None,
                },
                0,
            ),
        };

        let events = self.log.events_after(vault_id, start_seq)?;
        let filtered: Vec<StoredEvent> = events
            .into_iter()
            .filter(|e| e.sequence <= target_sequence)
            .collect();

        let event_count = filtered.len();
        let last_sequence = filtered.last().map(|e| e.sequence).unwrap_or(start_seq);

        for raw in filtered {
            let event = raw.migrate_to_current();
            apply_event(&mut state, &event);
        }

        Ok(ReplayedState {
            vault_id: vault_id.to_string(),
            state,
            last_sequence,
            events_applied: event_count,
        })
    }
}

/// Result returned by the replayer.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReplayedState {
    pub vault_id: String,
    pub state: SnapshotState,
    /// Sequence number of the last event that was applied.
    pub last_sequence: u64,
    /// Number of events applied during this replay run.
    pub events_applied: usize,
}

// ── Event application ─────────────────────────────────────────────────────────

/// Apply a single event to a mutable state.  Keep this pure so it is easy to
/// test in isolation.
fn apply_event(state: &mut SnapshotState, event: &StoredEvent) {
    match &event.event_type {
        EventType::Deposit => {
            if let Some(delta) = event.data.get("balance_delta").and_then(|v| v.as_i64()) {
                state.balance += delta as i128;
            }
        }
        EventType::Withdrawal => {
            if let Some(delta) = event.data.get("balance_delta").and_then(|v| v.as_i64()) {
                state.balance -= delta as i128;
            }
        }
        EventType::CheckIn => {
            state.last_check_in = event.timestamp;
            if let Some(ttl) = event.data.get("ttl_remaining").and_then(|v| v.as_u64()) {
                state.ttl_remaining = Some(ttl);
            }
        }
        EventType::TtlUpdate => {
            if let Some(ttl) = event.data.get("ttl_remaining").and_then(|v| v.as_u64()) {
                state.ttl_remaining = Some(ttl);
            }
        }
        EventType::StatusChange => {
            if let Some(s) = event.data.get("status").and_then(|v| v.as_str()) {
                state.status = match s {
                    "active" => VaultStatus::Active,
                    "expired" => VaultStatus::Expired,
                    "released" => VaultStatus::Released,
                    "paused" => VaultStatus::Paused,
                    _ => state.status.clone(),
                };
            }
        }
        EventType::Release => {
            state.status = VaultStatus::Released;
            state.balance = 0;
        }
    }
}

// ── Shared state wrapper ──────────────────────────────────────────────────────

/// All event-sourcing state bundled for easy injection into `AppState`.
#[derive(Clone)]
pub struct EventSourcingState {
    pub log: Arc<EventLog>,
    pub snapshots: Arc<SnapshotStore>,
}

impl EventSourcingState {
    pub fn new() -> Self {
        Self {
            log: Arc::new(EventLog::new()),
            snapshots: Arc::new(SnapshotStore::new()),
        }
    }

    pub fn replayer(&self) -> EventReplayer<'_> {
        EventReplayer::new(&self.log, &self.snapshots)
    }
}

impl Default for EventSourcingState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum EventSourcingError {
    #[error("internal lock was poisoned")]
    LockPoisoned,
    #[error("vault not found: {0}")]
    VaultNotFound(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_log_with_events() -> EventLog {
        let log = EventLog::new();
        log.append(
            "vault-1",
            EventType::Deposit,
            serde_json::json!({"balance_delta": 1000}),
        )
        .unwrap();
        log.append(
            "vault-1",
            EventType::CheckIn,
            serde_json::json!({"ttl_remaining": 86400}),
        )
        .unwrap();
        log.append(
            "vault-1",
            EventType::Withdrawal,
            serde_json::json!({"balance_delta": 200}),
        )
        .unwrap();
        log
    }

    #[test]
    fn append_is_append_only_and_sequences_are_monotonic() {
        let log = make_log_with_events();
        let events = log.events_for_vault("vault-1").unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[1].sequence, 2);
        assert_eq!(events[2].sequence, 3);
    }

    #[test]
    fn events_after_filters_correctly() {
        let log = make_log_with_events();
        let events = log.events_after("vault-1", 1).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence, 2);
    }

    #[test]
    fn replay_rebuilds_balance_from_scratch() {
        let log = make_log_with_events();
        let snapshots = SnapshotStore::new();
        let replayer = EventReplayer::new(&log, &snapshots);
        let result = replayer.replay("vault-1").unwrap();
        // 1000 deposit − 200 withdrawal = 800
        assert_eq!(result.state.balance, 800);
        assert_eq!(result.events_applied, 3);
    }

    #[test]
    fn replay_uses_snapshot_as_baseline() {
        let log = make_log_with_events();
        let snapshots = SnapshotStore::new();

        // Simulate a snapshot taken after seq 2 with balance = 1000
        snapshots
            .save(VaultSnapshot {
                vault_id: "vault-1".into(),
                snapshot_sequence: 2,
                taken_at: Utc::now(),
                state: SnapshotState {
                    balance: 1000,
                    status: VaultStatus::Active,
                    last_check_in: Utc::now(),
                    ttl_remaining: Some(86400),
                },
            })
            .unwrap();

        let replayer = EventReplayer::new(&log, &snapshots);
        let result = replayer.replay("vault-1").unwrap();
        // Snapshot balance 1000 − 200 withdrawal (seq 3) = 800
        assert_eq!(result.state.balance, 800);
        assert_eq!(result.events_applied, 1);
    }

    #[test]
    fn replay_to_target_sequence_stops_at_correct_point() {
        let log = make_log_with_events();
        let snapshots = SnapshotStore::new();
        let replayer = EventReplayer::new(&log, &snapshots);
        // Replay only deposit (seq 1) — balance should be 1000
        let result = replayer.replay_to("vault-1", 1).unwrap();
        assert_eq!(result.state.balance, 1000);
        assert_eq!(result.events_applied, 1);
    }

    #[test]
    fn schema_version_migration_renames_amount_field() {
        let mut event = StoredEvent {
            vault_id: "v".into(),
            sequence: 1,
            event_type: EventType::Deposit,
            timestamp: Utc::now(),
            data: serde_json::json!({"amount": 500}),
            schema_version: 0,
        };
        event = event.migrate_to_current();
        assert_eq!(event.schema_version, CURRENT_SCHEMA_VERSION);
        assert!(event.data.get("balance_delta").is_some());
        assert!(event.data.get("amount").is_none());
    }

    #[test]
    fn separate_vaults_have_independent_sequences() {
        let log = EventLog::new();
        log.append("vault-a", EventType::Deposit, serde_json::json!({}))
            .unwrap();
        log.append("vault-b", EventType::Deposit, serde_json::json!({}))
            .unwrap();
        log.append("vault-a", EventType::CheckIn, serde_json::json!({}))
            .unwrap();

        let a_events = log.events_for_vault("vault-a").unwrap();
        let b_events = log.events_for_vault("vault-b").unwrap();

        assert_eq!(a_events[0].sequence, 1);
        assert_eq!(a_events[1].sequence, 2);
        assert_eq!(b_events[0].sequence, 1);
    }

    #[test]
    fn status_change_event_updates_status() {
        let log = EventLog::new();
        log.append(
            "vault-1",
            EventType::StatusChange,
            serde_json::json!({"status": "released"}),
        )
        .unwrap();
        let snapshots = SnapshotStore::new();
        let replayer = EventReplayer::new(&log, &snapshots);
        let result = replayer.replay("vault-1").unwrap();
        assert_eq!(result.state.status, VaultStatus::Released);
    }
}
