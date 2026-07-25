#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, Address,
    Bytes, BytesN, Env, Vec,
};

pub const MAX_PROOF_SIZE: u32 = 4096;
pub const MAX_CLAIM_SIZE: u32 = 1024;
/// Maximum size of a dispute's `reason` bytes, mirroring MAX_CLAIM_SIZE so a
/// dispute cannot be used to smuggle unbounded data onto the ledger.
pub const MAX_REASON_SIZE: u32 = 1024;
/// Number of concurring oracle votes required to resolve a dispute (either
/// upholding or rejecting it) when no explicit threshold has been configured
/// by the admin via [`ZkVerifierContract::set_dispute_threshold`].
pub const DEFAULT_DISPUTE_THRESHOLD: u32 = 3;
/// Maximum number of historical snapshots retained per credential. Once a
/// credential's snapshot count exceeds this, the oldest snapshot is pruned
/// to bound persistent-storage growth. See docs/zk-verifier.md, "Credential
/// Retention Policy".
pub const MAX_CREDENTIAL_SNAPSHOTS: u32 = 1000;

const VERIFY_CLAIM_TOPIC: soroban_sdk::Symbol = symbol_short!("vfy_claim");
const DISPUTE_OPEN_TOPIC: soroban_sdk::Symbol = symbol_short!("disp_open");
const DISPUTE_VOTE_TOPIC: soroban_sdk::Symbol = symbol_short!("disp_vote");
const DISPUTE_RESOLVED_TOPIC: soroban_sdk::Symbol = symbol_short!("disp_res");

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VerifierError {
    /// Proof bytes were empty.
    EmptyProof = 1,
    /// Claim bytes were empty.
    EmptyClaim = 2,
    /// Proof bytes exceed MAX_PROOF_SIZE.
    ProofTooLarge = 3,
    /// Claim bytes exceed MAX_CLAIM_SIZE.
    ClaimTooLarge = 4,
    /// Contract has already been initialized.
    AlreadyInitialized = 5,
    /// Contract has not been initialized.
    NotInitialized = 6,
    /// The oracle address is not registered.
    OracleNotFound = 7,
    /// No credential exists with the given id.
    CredentialNotFound = 8,
    /// No dispute exists with the given id.
    DisputeNotFound = 9,
    /// The dispute has already been resolved and no longer accepts votes.
    DisputeNotOpen = 10,
    /// This voter has already cast a vote on this dispute.
    AlreadyVoted = 11,
    /// A dispute is already open for this credential; wait for it to resolve
    /// before filing another.
    DisputeAlreadyOpen = 12,
    /// Dispute reason bytes were empty.
    EmptyReason = 13,
    /// Dispute reason bytes exceed MAX_REASON_SIZE.
    ReasonTooLarge = 14,
    /// Threshold must be greater than zero.
    InvalidThreshold = 15,
    /// The caller is not permitted to view this credential at its current
    /// privacy level.
    AccessDenied = 16,
    /// No version exists with the given number for this credential — either
    /// it was never recorded, or it has since been pruned by the retention
    /// policy.
    VersionNotFound = 17,
}

/// Storage key discriminants.
mod keys {
    use soroban_sdk::{contracttype, Address, BytesN};

    #[contracttype]
    pub enum DataKey {
        Admin,
        Oracle(Address),
        /// Attestation: (proof_sha256, claim_sha256) -> AttestationRecord
        Attestation(BytesN<32>, BytesN<32>),
        /// Incrementing generation counter for credential ids.
        CredentialCount,
        /// credential_id -> (proof_sha256, claim_sha256), the reverse of
        /// `Attestation`, so a credential can be looked up by id.
        CredentialHashes(u64),
        /// Present (and true) once a dispute against this credential has
        /// been upheld; absence means the credential is not disputed-invalid.
        CredentialInvalidated(u64),
        /// credential_id -> dispute_id of the currently open dispute against
        /// it, if any. Cleared once that dispute resolves.
        CredentialOpenDispute(u64),
        /// credential_id -> Vec<dispute_id>, full dispute history.
        CredentialDisputeHistory(u64),
        /// Incrementing generation counter for dispute ids.
        DisputeCount,
        DisputeRecord(u64),
        /// (dispute_id, voter) -> vote cast, used to prevent double-voting.
        DisputeVote(u64, Address),
        /// Number of concurring votes needed to resolve a dispute. Falls
        /// back to DEFAULT_DISPUTE_THRESHOLD when unset.
        DisputeThreshold,
        /// (credential_id, timestamp) -> CredentialSnapshot, captured every
        /// time a credential's attestation or invalidation status changes.
        CredentialSnapshot(u64, u64),
        /// credential_id -> Vec<timestamp>, ascending, one entry per
        /// retained snapshot for that credential (bounded by
        /// MAX_CREDENTIAL_SNAPSHOTS).
        CredentialSnapshotTimestamps(u64),
        /// credential_id -> Vec<version>, ascending, a parallel index to
        /// `CredentialSnapshotTimestamps` (same length, same order, same
        /// retention bound) mapping each retained snapshot to its version
        /// number.
        CredentialSnapshotVersions(u64),
        /// credential_id -> PrivacyLevel. Absence means `Public`, so
        /// pre-existing credentials are unaffected until an admin opts them
        /// into a stricter level via `set_credential_privacy`.
        CredentialPrivacy(u64),
    }
}

use keys::DataKey;

/// A stored oracle attestation, now addressable by a stable `credential_id`
/// in addition to the `(proof_hash, claim_hash)` pair used by `verify_claim`.
#[contracttype]
#[derive(Clone)]
pub struct AttestationRecord {
    pub credential_id: u64,
    pub oracle: Address,
}

/// A point-in-time snapshot of a credential's attestation state, captured
/// whenever that state changes (re-attestation, or a dispute resolving).
/// Used to answer historical questions like "was this credential valid at
/// time T?" via [`ZkVerifierContract::get_credential_at_time`], or "what did
/// version N look like?" via [`ZkVerifierContract::get_credential_version`].
#[contracttype]
#[derive(Clone)]
pub struct CredentialSnapshot {
    pub credential_id: u64,
    pub oracle: Address,
    pub invalidated: bool,
    /// Ledger timestamp at which this snapshot was captured.
    pub timestamp: u64,
    /// Monotonically increasing version number for this credential, starting
    /// at 1. Unlike the snapshot itself, a version number is never reused or
    /// renumbered once assigned — even after the retention policy prunes the
    /// snapshot it identifies, so audit references to "version N" remain
    /// meaningful (as "not found") rather than silently pointing at a
    /// different state. See docs/zk-verifier.md, "Credential Version
    /// History".
    pub version: u32,
}

/// The result of comparing two recorded versions of a credential's
/// attestation state, returned by
/// [`ZkVerifierContract::diff_credential_versions`].
#[contracttype]
#[derive(Clone)]
pub struct CredentialVersionDiff {
    pub credential_id: u64,
    pub from_version: u32,
    pub to_version: u32,
    pub from_timestamp: u64,
    pub to_timestamp: u64,
    pub oracle_changed: bool,
    pub previous_oracle: Address,
    pub current_oracle: Address,
    pub invalidated_changed: bool,
    pub previous_invalidated: bool,
    pub current_invalidated: bool,
}

/// Controls who may read a credential's attestation state via
/// [`ZkVerifierContract::get_credential_at_time`]. Set per-credential by the
/// admin via [`ZkVerifierContract::set_credential_privacy`]; defaults to
/// `Public` for every credential until explicitly changed.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyLevel {
    /// Readable by anyone.
    Public,
    /// Readable only by the admin and registered oracles.
    Internal,
    /// Readable only by the admin.
    Confidential,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisputeStatus {
    /// Open for voting.
    Open,
    /// Threshold of "invalid" votes reached; the credential is now treated
    /// as invalid by `verify_claim`.
    Upheld,
    /// Threshold of "valid" votes reached; the credential remains valid.
    Rejected,
}

#[contracttype]
#[derive(Clone)]
pub struct Dispute {
    pub id: u64,
    pub credential_id: u64,
    pub initiator: Address,
    pub reason: Bytes,
    pub status: DisputeStatus,
    /// Votes asserting the credential is invalid.
    pub votes_for: u32,
    /// Votes asserting the credential remains valid.
    pub votes_against: u32,
    pub created_at: u64,
    /// Ledger timestamp of resolution, or 0 while still Open.
    pub resolved_at: u64,
}

#[contract]
pub struct ZkVerifierContract;

#[contractimpl]
impl ZkVerifierContract {
    /// Initialize the contract with an admin address.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(&env, VerifierError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Register a trusted oracle. Admin only.
    pub fn register_oracle(env: Env, oracle: Address) {
        Self::require_admin(&env);
        env.storage()
            .instance()
            .set(&DataKey::Oracle(oracle), &true);
    }

    /// Revoke a trusted oracle. Admin only.
    pub fn revoke_oracle(env: Env, oracle: Address) {
        Self::require_admin(&env);
        env.storage().instance().remove(&DataKey::Oracle(oracle));
    }

    /// Returns whether the given address is a registered oracle.
    pub fn is_oracle(env: Env, oracle: Address) -> bool {
        env.storage()
            .instance()
            .get::<DataKey, bool>(&DataKey::Oracle(oracle))
            .unwrap_or(false)
    }

    /// An oracle publishes an attestation that `proof` is valid for `claim`.
    ///
    /// The contract stores the SHA-256 digests of both byte strings so that
    /// the full proof bytes are not stored on-chain. Returns the stable
    /// `credential_id` for this `(proof, claim)` pair — a fresh id the first
    /// time it is attested, or the existing id if it was attested before
    /// (e.g. by a different oracle, or re-attested after a dispute).
    pub fn attest(env: Env, oracle: Address, proof: Bytes, claim: Bytes) -> u64 {
        if proof.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }
        if claim.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyClaim);
        }
        Self::require_registered_oracle(&env, &oracle);
        oracle.require_auth();
        let proof_hash: BytesN<32> = env.crypto().sha256(&proof).into();
        let claim_hash: BytesN<32> = env.crypto().sha256(&claim).into();

        let attestation_key = DataKey::Attestation(proof_hash.clone(), claim_hash.clone());
        let credential_id = match env
            .storage()
            .instance()
            .get::<DataKey, AttestationRecord>(&attestation_key)
        {
            Some(existing) => existing.credential_id,
            None => {
                let id = env
                    .storage()
                    .instance()
                    .get::<DataKey, u64>(&DataKey::CredentialCount)
                    .unwrap_or(0)
                    + 1;
                env.storage().instance().set(&DataKey::CredentialCount, &id);
                env.storage()
                    .instance()
                    .set(&DataKey::CredentialHashes(id), &(proof_hash, claim_hash));
                id
            }
        };

        env.storage().instance().set(
            &attestation_key,
            &AttestationRecord {
                credential_id,
                oracle: oracle.clone(),
            },
        );

        let invalidated = Self::is_credential_invalidated(env.clone(), credential_id);
        Self::record_credential_snapshot(&env, credential_id, oracle, invalidated);

        credential_id
    }

    /// Verifies a zero-knowledge proof against a claim using oracle attestation.
    ///
    /// This hashes `proof` and `claim` with SHA-256 (the same digests used by
    /// [`Self::attest`]) and looks up `DataKey::Attestation(proof_hash,
    /// claim_hash)` in instance storage. Returns `true` only if:
    ///   1. an attestation exists for this exact `(proof, claim)` pair, AND
    ///   2. the oracle that made that attestation is *currently* a registered
    ///      oracle (i.e. has not since been revoked via `revoke_oracle`).
    ///
    /// Revocation semantics: attestations are not deleted on revocation, but
    /// they are only honored while the attesting oracle remains registered.
    /// This is the safer choice for a contract that gates release of real
    /// funds — a revoked oracle (e.g. one that was compromised or found to be
    /// misbehaving) should immediately lose the ability to have its past
    /// attestations relied upon, without requiring a separate sweep to purge
    /// its attestation records.
    ///
    /// Returns `false` (does not panic) when no matching attestation exists,
    /// when the attesting oracle is no longer registered, or when the
    /// credential has been invalidated by an upheld dispute (see
    /// [`Self::vote_on_dispute`]) — all are normal "not verified" outcomes.
    ///
    /// Emits a `vfy_claim` event with `(result, claim_hash)` on every call
    /// that passes input validation.
    pub fn verify_claim(env: Env, proof: Bytes, claim: Bytes) -> bool {
        if proof.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }
        if proof.len() > MAX_PROOF_SIZE {
            panic_with_error!(&env, VerifierError::ProofTooLarge);
        }
        if claim.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyClaim);
        }
        if claim.len() > MAX_CLAIM_SIZE {
            panic_with_error!(&env, VerifierError::ClaimTooLarge);
        }

        let proof_hash: BytesN<32> = env.crypto().sha256(&proof).into();
        let claim_hash: BytesN<32> = env.crypto().sha256(&claim).into();

        let result = env
            .storage()
            .instance()
            .get::<DataKey, AttestationRecord>(&DataKey::Attestation(proof_hash, claim_hash.clone()))
            .map(|record| {
                let oracle_ok = env
                    .storage()
                    .instance()
                    .get::<DataKey, bool>(&DataKey::Oracle(record.oracle))
                    .unwrap_or(false);
                let not_invalidated = !env
                    .storage()
                    .instance()
                    .get::<DataKey, bool>(&DataKey::CredentialInvalidated(record.credential_id))
                    .unwrap_or(false);
                oracle_ok && not_invalidated
            })
            .unwrap_or(false);

        env.events()
            .publish((VERIFY_CLAIM_TOPIC,), (result, claim_hash));

        result
    }

    /// Files a dispute challenging the validity of `credential_id`. Anyone
    /// may initiate a dispute (resolution, not initiation, is the trust
    /// boundary) — `initiator` just needs to authorize the call so the
    /// recorded initiator cannot be spoofed.
    ///
    /// Only one dispute may be open against a given credential at a time;
    /// file a fresh one once the prior dispute resolves. Returns the new
    /// `dispute_id`.
    pub fn initiate_credential_dispute(
        env: Env,
        credential_id: u64,
        initiator: Address,
        reason: Bytes,
    ) -> u64 {
        if reason.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyReason);
        }
        if reason.len() > MAX_REASON_SIZE {
            panic_with_error!(&env, VerifierError::ReasonTooLarge);
        }
        if !env
            .storage()
            .instance()
            .has(&DataKey::CredentialHashes(credential_id))
        {
            panic_with_error!(&env, VerifierError::CredentialNotFound);
        }
        if env
            .storage()
            .instance()
            .has(&DataKey::CredentialOpenDispute(credential_id))
        {
            panic_with_error!(&env, VerifierError::DisputeAlreadyOpen);
        }
        initiator.require_auth();

        let dispute_id = env
            .storage()
            .instance()
            .get::<DataKey, u64>(&DataKey::DisputeCount)
            .unwrap_or(0)
            + 1;
        env.storage()
            .instance()
            .set(&DataKey::DisputeCount, &dispute_id);

        let created_at = env.ledger().timestamp();
        let dispute = Dispute {
            id: dispute_id,
            credential_id,
            initiator: initiator.clone(),
            reason,
            status: DisputeStatus::Open,
            votes_for: 0,
            votes_against: 0,
            created_at,
            resolved_at: 0,
        };
        env.storage()
            .instance()
            .set(&DataKey::DisputeRecord(dispute_id), &dispute);
        env.storage()
            .instance()
            .set(&DataKey::CredentialOpenDispute(credential_id), &dispute_id);

        let mut history = Self::get_credential_disputes(env.clone(), credential_id);
        history.push_back(dispute_id);
        env.storage()
            .instance()
            .set(&DataKey::CredentialDisputeHistory(credential_id), &history);

        env.events().publish(
            (DISPUTE_OPEN_TOPIC,),
            (dispute_id, credential_id, initiator),
        );

        dispute_id
    }

    /// Casts a registered oracle's vote on an open dispute. `vote = true`
    /// asserts the credential is invalid; `vote = false` asserts it remains
    /// valid. Each oracle may vote once per dispute.
    ///
    /// Once either side reaches the configured threshold (see
    /// [`Self::set_dispute_threshold`]), the dispute resolves immediately:
    /// on `Upheld`, the credential is marked invalidated and `verify_claim`
    /// will return `false` for it going forward regardless of oracle status.
    pub fn vote_on_dispute(env: Env, dispute_id: u64, voter: Address, vote: bool) {
        let mut dispute: Dispute = env
            .storage()
            .instance()
            .get(&DataKey::DisputeRecord(dispute_id))
            .unwrap_or_else(|| panic_with_error!(&env, VerifierError::DisputeNotFound));
        if dispute.status != DisputeStatus::Open {
            panic_with_error!(&env, VerifierError::DisputeNotOpen);
        }
        Self::require_registered_oracle(&env, &voter);
        voter.require_auth();

        let vote_key = DataKey::DisputeVote(dispute_id, voter);
        if env.storage().instance().has(&vote_key) {
            panic_with_error!(&env, VerifierError::AlreadyVoted);
        }
        env.storage().instance().set(&vote_key, &vote);

        if vote {
            dispute.votes_for += 1;
        } else {
            dispute.votes_against += 1;
        }

        let threshold = Self::dispute_threshold(env.clone());
        if dispute.votes_for >= threshold {
            dispute.status = DisputeStatus::Upheld;
        } else if dispute.votes_against >= threshold {
            dispute.status = DisputeStatus::Rejected;
        }

        if dispute.status != DisputeStatus::Open {
            dispute.resolved_at = env.ledger().timestamp();
            env.storage()
                .instance()
                .remove(&DataKey::CredentialOpenDispute(dispute.credential_id));
            if dispute.status == DisputeStatus::Upheld {
                env.storage()
                    .instance()
                    .set(&DataKey::CredentialInvalidated(dispute.credential_id), &true);
            }
            if let Some(record) = Self::load_attestation_record(&env, dispute.credential_id) {
                Self::record_credential_snapshot(
                    &env,
                    dispute.credential_id,
                    record.oracle,
                    dispute.status == DisputeStatus::Upheld,
                );
            }
            env.events().publish(
                (DISPUTE_RESOLVED_TOPIC,),
                (dispute_id, dispute.credential_id, dispute.status),
            );
        }

        env.events()
            .publish((DISPUTE_VOTE_TOPIC,), (dispute_id, vote));

        env.storage()
            .instance()
            .set(&DataKey::DisputeRecord(dispute_id), &dispute);
    }

    /// Returns the full record for a dispute.
    pub fn get_dispute(env: Env, dispute_id: u64) -> Dispute {
        env.storage()
            .instance()
            .get(&DataKey::DisputeRecord(dispute_id))
            .unwrap_or_else(|| panic_with_error!(&env, VerifierError::DisputeNotFound))
    }

    /// Returns the ids of every dispute ever filed against `credential_id`,
    /// oldest first.
    pub fn get_credential_disputes(env: Env, credential_id: u64) -> Vec<u64> {
        env.storage()
            .instance()
            .get(&DataKey::CredentialDisputeHistory(credential_id))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Returns whether `credential_id` has been invalidated by an upheld
    /// dispute.
    pub fn is_credential_invalidated(env: Env, credential_id: u64) -> bool {
        env.storage()
            .instance()
            .get::<DataKey, bool>(&DataKey::CredentialInvalidated(credential_id))
            .unwrap_or(false)
    }

    /// Returns `credential_id`'s attestation state as of `timestamp`: the
    /// most recent snapshot recorded at or before that ledger timestamp.
    ///
    /// A snapshot is captured every time the credential's state changes —
    /// on `attest` (including re-attestation) and whenever a dispute
    /// against it resolves. `get_credential_at_time` finds the latest such
    /// snapshot with `snapshot.timestamp <= timestamp` via binary search
    /// over the credential's (ascending) snapshot-timestamp index, so
    /// lookups are O(log n) in the number of snapshots retained for that
    /// credential rather than a linear scan.
    ///
    /// Returns `None` if the credential had no snapshot at or before
    /// `timestamp` — either it did not exist yet at that time, or its
    /// earliest snapshot has since been pruned by the retention policy
    /// (see docs/zk-verifier.md, "Credential Retention Policy").
    ///
    /// `requester` must authorize the call and must be permitted to view
    /// `credential_id` under its current [`PrivacyLevel`] (see
    /// `set_credential_privacy`), or this panics with `AccessDenied`.
    pub fn get_credential_at_time(
        env: Env,
        requester: Address,
        credential_id: u64,
        timestamp: u64,
    ) -> Option<CredentialSnapshot> {
        requester.require_auth();
        Self::require_credential_access(&env, &requester, credential_id);

        let timestamps: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::CredentialSnapshotTimestamps(credential_id))
            .unwrap_or_else(|| Vec::new(&env));

        let idx = Self::floor_index(&timestamps, timestamp)?;
        let snapshot_ts = timestamps.get(idx).unwrap();
        env.storage()
            .persistent()
            .get(&DataKey::CredentialSnapshot(credential_id, snapshot_ts))
    }

    /// Returns `credential_id`'s recorded state as of a specific `version`
    /// number, or `None` if that version was never recorded or has since
    /// been pruned by the retention policy (see docs/zk-verifier.md,
    /// "Credential Version History").
    ///
    /// Version numbers start at 1 and increment by one each time the
    /// credential's attestation or invalidation status changes; unlike
    /// timestamps, they are never reused, so "version 3" always identifies
    /// the same historical state even if snapshots around it are pruned.
    ///
    /// `requester` is subject to the same [`PrivacyLevel`] access check as
    /// [`Self::get_credential_at_time`].
    pub fn get_credential_version(
        env: Env,
        requester: Address,
        credential_id: u64,
        version: u32,
    ) -> Option<CredentialSnapshot> {
        requester.require_auth();
        Self::require_credential_access(&env, &requester, credential_id);
        Self::load_version_snapshot(&env, credential_id, version)
    }

    /// Returns the latest version number recorded for `credential_id` (0 if
    /// it has never been attested), regardless of whether earlier versions
    /// have since been pruned.
    pub fn credential_version_count(env: Env, credential_id: u64) -> u32 {
        let versions: Vec<u32> = env
            .storage()
            .persistent()
            .get(&DataKey::CredentialSnapshotVersions(credential_id))
            .unwrap_or_else(|| Vec::new(&env));
        versions.last().unwrap_or(0)
    }

    /// Compares two recorded versions of `credential_id` and reports what
    /// changed between them — whether the attesting oracle changed and
    /// whether the invalidated status changed, plus both versions' raw
    /// state and timestamps. `from_version` and `to_version` need not be
    /// adjacent or in chronological order.
    ///
    /// Panics with `VersionNotFound` if either version was never recorded or
    /// has since been pruned. `requester` is subject to the same
    /// [`PrivacyLevel`] access check as [`Self::get_credential_at_time`].
    pub fn diff_credential_versions(
        env: Env,
        requester: Address,
        credential_id: u64,
        from_version: u32,
        to_version: u32,
    ) -> CredentialVersionDiff {
        requester.require_auth();
        Self::require_credential_access(&env, &requester, credential_id);

        let from = Self::load_version_snapshot(&env, credential_id, from_version)
            .unwrap_or_else(|| panic_with_error!(&env, VerifierError::VersionNotFound));
        let to = Self::load_version_snapshot(&env, credential_id, to_version)
            .unwrap_or_else(|| panic_with_error!(&env, VerifierError::VersionNotFound));

        CredentialVersionDiff {
            credential_id,
            from_version,
            to_version,
            from_timestamp: from.timestamp,
            to_timestamp: to.timestamp,
            oracle_changed: from.oracle != to.oracle,
            previous_oracle: from.oracle,
            current_oracle: to.oracle,
            invalidated_changed: from.invalidated != to.invalidated,
            previous_invalidated: from.invalidated,
            current_invalidated: to.invalidated,
        }
    }

    /// Returns the number of concurring votes required to resolve a
    /// dispute.
    pub fn dispute_threshold(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::DisputeThreshold)
            .unwrap_or(DEFAULT_DISPUTE_THRESHOLD)
    }

    /// Sets the number of concurring votes required to resolve a dispute.
    /// Admin only.
    pub fn set_dispute_threshold(env: Env, threshold: u32) {
        Self::require_admin(&env);
        if threshold == 0 {
            panic_with_error!(&env, VerifierError::InvalidThreshold);
        }
        env.storage()
            .instance()
            .set(&DataKey::DisputeThreshold, &threshold);
    }

    /// Sets the [`PrivacyLevel`] governing who may call
    /// `get_credential_at_time` for `credential_id`. Admin only.
    pub fn set_credential_privacy(env: Env, credential_id: u64, level: PrivacyLevel) {
        Self::require_admin(&env);
        if !env
            .storage()
            .instance()
            .has(&DataKey::CredentialHashes(credential_id))
        {
            panic_with_error!(&env, VerifierError::CredentialNotFound);
        }
        env.storage()
            .instance()
            .set(&DataKey::CredentialPrivacy(credential_id), &level);
    }

    /// Returns `credential_id`'s current [`PrivacyLevel`], defaulting to
    /// `Public` if it has never been explicitly set.
    pub fn credential_privacy(env: Env, credential_id: u64) -> PrivacyLevel {
        env.storage()
            .instance()
            .get(&DataKey::CredentialPrivacy(credential_id))
            .unwrap_or(PrivacyLevel::Public)
    }

    // ---- helpers ----

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(env, VerifierError::NotInitialized));
        admin.require_auth();
    }

    fn require_registered_oracle(env: &Env, oracle: &Address) {
        if !Self::is_registered_oracle(env, oracle) {
            panic_with_error!(env, VerifierError::OracleNotFound);
        }
    }

    fn is_registered_oracle(env: &Env, oracle: &Address) -> bool {
        env.storage()
            .instance()
            .get::<DataKey, bool>(&DataKey::Oracle(oracle.clone()))
            .unwrap_or(false)
    }

    fn is_admin(env: &Env, address: &Address) -> bool {
        env.storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::Admin)
            .map(|admin| &admin == address)
            .unwrap_or(false)
    }

    /// Enforces that `requester` is permitted to view `credential_id` under
    /// its current [`PrivacyLevel`]: anyone for `Public`, the admin or a
    /// registered oracle for `Internal`, and only the admin for
    /// `Confidential`. Panics with `AccessDenied` otherwise.
    fn require_credential_access(env: &Env, requester: &Address, credential_id: u64) {
        let allowed = match Self::credential_privacy(env.clone(), credential_id) {
            PrivacyLevel::Public => true,
            PrivacyLevel::Internal => {
                Self::is_admin(env, requester) || Self::is_registered_oracle(env, requester)
            }
            PrivacyLevel::Confidential => Self::is_admin(env, requester),
        };
        if !allowed {
            panic_with_error!(env, VerifierError::AccessDenied);
        }
    }

    /// Looks up the current `AttestationRecord` for `credential_id` by
    /// following `CredentialHashes(credential_id)` to the underlying
    /// `Attestation(proof_hash, claim_hash)` entry. Returns `None` if the
    /// credential id is unknown.
    fn load_attestation_record(env: &Env, credential_id: u64) -> Option<AttestationRecord> {
        let (proof_hash, claim_hash): (BytesN<32>, BytesN<32>) = env
            .storage()
            .instance()
            .get(&DataKey::CredentialHashes(credential_id))?;
        env.storage()
            .instance()
            .get(&DataKey::Attestation(proof_hash, claim_hash))
    }

    /// Captures a `CredentialSnapshot` for `credential_id` at the current
    /// ledger timestamp, appending it to that credential's snapshot and
    /// version indexes. If a snapshot was already captured at this exact
    /// timestamp (e.g. two state changes land in the same ledger close), it
    /// is overwritten in place rather than duplicated in the index — this
    /// keeps the index strictly ascending, which `get_credential_at_time`'s
    /// binary search depends on — and its version number is reused rather
    /// than incremented, since it does not represent a new distinct
    /// historical state.
    ///
    /// Once the credential's retained-snapshot count exceeds
    /// `MAX_CREDENTIAL_SNAPSHOTS`, the oldest snapshot is pruned. See
    /// docs/zk-verifier.md, "Credential Retention Policy". Its version
    /// number is *not* reused by a future snapshot — it simply becomes
    /// unqueryable via `get_credential_version`, per
    /// docs/zk-verifier.md, "Credential Version History".
    fn record_credential_snapshot(env: &Env, credential_id: u64, oracle: Address, invalidated: bool) {
        let timestamp = env.ledger().timestamp();

        let mut timestamps: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::CredentialSnapshotTimestamps(credential_id))
            .unwrap_or_else(|| Vec::new(env));
        let mut versions: Vec<u32> = env
            .storage()
            .persistent()
            .get(&DataKey::CredentialSnapshotVersions(credential_id))
            .unwrap_or_else(|| Vec::new(env));

        // Same-timestamp state changes overwrite the existing snapshot (see
        // `get_credential_at_time`'s doc comment) and reuse its version
        // number rather than minting a new one, so a version always
        // corresponds to a distinct retained timestamp.
        let is_new_timestamp = timestamps.last() != Some(timestamp);
        let version = if is_new_timestamp {
            versions.last().unwrap_or(0) + 1
        } else {
            versions.last().unwrap_or(1)
        };

        env.storage().persistent().set(
            &DataKey::CredentialSnapshot(credential_id, timestamp),
            &CredentialSnapshot {
                credential_id,
                oracle,
                invalidated,
                timestamp,
                version,
            },
        );

        if is_new_timestamp {
            timestamps.push_back(timestamp);
            versions.push_back(version);

            if timestamps.len() > MAX_CREDENTIAL_SNAPSHOTS {
                if let Some(oldest) = timestamps.first() {
                    env.storage()
                        .persistent()
                        .remove(&DataKey::CredentialSnapshot(credential_id, oldest));
                    timestamps.remove(0);
                    versions.remove(0);
                }
            }

            env.storage().persistent().set(
                &DataKey::CredentialSnapshotTimestamps(credential_id),
                &timestamps,
            );
            env.storage().persistent().set(
                &DataKey::CredentialSnapshotVersions(credential_id),
                &versions,
            );
        }
    }

    /// Returns the index of the entry in `versions` exactly equal to
    /// `target`, or `None` if absent. Requires `versions` to be sorted
    /// ascending with no duplicates, which holds by construction (see
    /// `record_credential_snapshot`).
    fn version_index(versions: &Vec<u32>, target: u32) -> Option<u32> {
        let mut lo: u32 = 0;
        let mut hi: u32 = versions.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let v = versions.get(mid).unwrap();
            if v == target {
                return Some(mid);
            } else if v < target {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        None
    }

    /// Looks up the retained snapshot for `credential_id` at exactly
    /// `version`, without any auth or access-control check — callers are
    /// responsible for enforcing those first.
    fn load_version_snapshot(env: &Env, credential_id: u64, version: u32) -> Option<CredentialSnapshot> {
        let versions: Vec<u32> = env
            .storage()
            .persistent()
            .get(&DataKey::CredentialSnapshotVersions(credential_id))
            .unwrap_or_else(|| Vec::new(env));
        let idx = Self::version_index(&versions, version)?;

        let timestamps: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::CredentialSnapshotTimestamps(credential_id))
            .unwrap_or_else(|| Vec::new(env));
        let timestamp = timestamps.get(idx)?;

        env.storage()
            .persistent()
            .get(&DataKey::CredentialSnapshot(credential_id, timestamp))
    }

    /// Returns the index of the rightmost entry in `timestamps` that is
    /// `<= target`, or `None` if every entry exceeds `target` (or the vec
    /// is empty). Requires `timestamps` to be sorted ascending, which holds
    /// by construction: ledger close time is monotonically non-decreasing,
    /// and `record_credential_snapshot` only ever appends.
    fn floor_index(timestamps: &Vec<u64>, target: u64) -> Option<u32> {
        let mut lo: u32 = 0;
        let mut hi: u32 = timestamps.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if timestamps.get(mid).unwrap() <= target {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            None
        } else {
            Some(lo - 1)
        }
    }
}

#[cfg(test)]
mod test;
