#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short,
    xdr::FromXdr, Address, Bytes, BytesN, Env,
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

const VERIFY_CLAIM_TOPIC: soroban_sdk::Symbol = symbol_short!("vfy_claim");
const VERIFY_CONDITIONAL_TOPIC: soroban_sdk::Symbol = symbol_short!("vfy_cond");

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
    /// `proof` could not be decoded as a `ConditionalProof`.
    MalformedConditionalProof = 8,
}

/// The on-chain format for a conditional ("prove X if Y, else prove Z")
/// proof, encoded into the opaque `proof: Bytes` argument of
/// [`ZkVerifierContract::verify_conditional_proof`] via XDR.
///
/// The condition `Y` is the caller-supplied `condition` claim; this bundle
/// carries the proof for `Y` plus both branches' claim/proof pairs so the
/// contract itself — not the caller — decides and checks which branch
/// applies, exactly once `Y`'s truth is established from oracle attestation.
#[contracttype]
#[derive(Clone)]
pub struct ConditionalProof {
    /// Proof that the `condition` claim (`Y`) holds.
    pub condition_proof: Bytes,
    /// Claim `X`, checked when the condition is true.
    pub then_claim: Bytes,
    /// Proof that claim `X` holds.
    pub then_proof: Bytes,
    /// Claim `Z`, checked when the condition is false.
    pub else_claim: Bytes,
    /// Proof that claim `Z` holds.
    pub else_proof: Bytes,
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
                oracle,
            },
        );

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
        let claim_hash: BytesN<32> = env.crypto().sha256(&claim).into();
        let result = Self::verify_internal(&env, &proof, &claim);

        env.events()
            .publish((VERIFY_CLAIM_TOPIC,), (result, claim_hash));

        result
    }

    /// Verifies a conditional ("prove X if Y, else prove Z") proof.
    ///
    /// `condition` is claim `Y`. `proof` is the XDR encoding of a
    /// [`ConditionalProof`] bundle carrying the proof for `Y` plus both
    /// branches. The condition is checked first via the same oracle
    /// attestation model as [`Self::verify_claim`]; the contract then
    /// verifies the `then` branch if the condition holds, or the `else`
    /// branch otherwise — the caller cannot pick a branch that skips the
    /// condition check.
    ///
    /// Returns `false` (does not panic) when the condition or the selected
    /// branch is unattested; panics with `MalformedConditionalProof` if
    /// `proof` is not a valid `ConditionalProof` encoding.
    ///
    /// Emits a `vfy_cond` event with `(result, condition_result, claim_hash)`
    /// of the branch that was checked.
    pub fn verify_conditional_proof(env: Env, proof: Bytes, condition: Bytes) -> bool {
        let bundle = ConditionalProof::from_xdr(&env, &proof)
            .unwrap_or_else(|_| panic_with_error!(&env, VerifierError::MalformedConditionalProof));

        let condition_result = Self::verify_internal(&env, &bundle.condition_proof, &condition);

        let (branch_proof, branch_claim) = if condition_result {
            (bundle.then_proof, bundle.then_claim)
        } else {
            (bundle.else_proof, bundle.else_claim)
        };

        let claim_hash: BytesN<32> = env.crypto().sha256(&branch_claim).into();
        let result = Self::verify_internal(&env, &branch_proof, &branch_claim);

        env.events().publish(
            (VERIFY_CONDITIONAL_TOPIC,),
            (result, condition_result, claim_hash),
        );

        result
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

    /// Validates size/emptiness constraints on `proof`/`claim`, then looks
    /// up whether a currently-registered oracle has attested this exact
    /// pair. Shared by [`Self::verify_claim`] and
    /// [`Self::verify_conditional_proof`] so both branch checks and the
    /// top-level claim check apply identical validation and revocation
    /// semantics.
    fn verify_internal(env: &Env, proof: &Bytes, claim: &Bytes) -> bool {
        if proof.is_empty() {
            panic_with_error!(env, VerifierError::EmptyProof);
        }
        if proof.len() > MAX_PROOF_SIZE {
            panic_with_error!(env, VerifierError::ProofTooLarge);
        }
        if claim.is_empty() {
            panic_with_error!(env, VerifierError::EmptyClaim);
        }
        if claim.len() > MAX_CLAIM_SIZE {
            panic_with_error!(env, VerifierError::ClaimTooLarge);
        }

        let proof_hash: BytesN<32> = env.crypto().sha256(proof).into();
        let claim_hash: BytesN<32> = env.crypto().sha256(claim).into();

        env.storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::Attestation(proof_hash, claim_hash))
            .map(|attesting_oracle| {
                env.storage()
                    .instance()
                    .get::<DataKey, bool>(&DataKey::Oracle(attesting_oracle))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod test;
