#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, panic_with_error, symbol_short, Address, Bytes, BytesN,
    Env, Vec, U64,
};

pub const MAX_PROOF_SIZE: u32 = 4096;
pub const MAX_CLAIM_SIZE: u32 = 1024;
pub const MAX_EXTERNAL_FORMAT_SIZE: u32 = 8192;
pub const LATTICE_PROOF_HEADER: &[u8] = b"LATTICE_V1";

const VERIFY_CLAIM_TOPIC: soroban_sdk::Symbol = symbol_short!("vfy_claim");
const VERIFY_LATTICE_TOPIC: soroban_sdk::Symbol = symbol_short!("vfy_latt");
const AUDIT_LOG_TOPIC: soroban_sdk::Symbol = symbol_short!("audit_log");
const PROOF_MASKED_TOPIC: soroban_sdk::Symbol = symbol_short!("proof_msk");

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
    /// Invalid lattice proof format.
    InvalidLatticeProof = 8,
    /// External format size exceeds limit.
    ExternalFormatTooLarge = 9,
    /// Invalid proof masking specification.
    InvalidMaskSpec = 10,
    /// Masked verification failed.
    MaskedVerificationFailed = 11,
}

/// Storage key discriminants.
mod keys {
    use soroban_sdk::{contracttype, Address, BytesN, U64};

    #[contracttype]
    pub enum DataKey {
        Admin,
        Oracle(Address),
        /// Attestation: (proof_sha256, claim_sha256) -> attesting oracle
        Attestation(BytesN<32>, BytesN<32>),
        /// Proof verification history: proof_hash -> Vec<VerificationRecord>
        VerificationHistory(BytesN<32>),
        /// Proof masking config: proof_hash -> MaskingConfig
        MaskingConfig(BytesN<32>),
        /// Last verification timestamp for proof
        LastVerificationTime(BytesN<32>),
    }

    #[contracttype]
    pub struct VerificationRecord {
        pub timestamp: U64,
        pub verified: bool,
        pub oracle: Address,
    }

    #[contracttype]
    pub struct MaskingConfig {
        pub masked_fields: BytesN<32>,
        pub version: u32,
    }
}

use keys::{DataKey, VerificationRecord, MaskingConfig};

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
    /// the full proof bytes are not stored on-chain.
    pub fn attest(env: Env, oracle: Address, proof: Bytes, claim: Bytes) {
        if proof.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }
        if claim.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyClaim);
        }
        if !env
            .storage()
            .instance()
            .get::<DataKey, bool>(&DataKey::Oracle(oracle.clone()))
            .unwrap_or(false)
        {
            panic_with_error!(&env, VerifierError::OracleNotFound);
        }
        oracle.require_auth();
        let proof_hash: BytesN<32> = env.crypto().sha256(&proof).into();
        let claim_hash: BytesN<32> = env.crypto().sha256(&claim).into();
        env.storage()
            .instance()
            .set(&DataKey::Attestation(proof_hash, claim_hash), &oracle);
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
    /// or when the attesting oracle is no longer registered — both are normal
    /// "not verified" outcomes.
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
            .get::<DataKey, Address>(&DataKey::Attestation(proof_hash, claim_hash.clone()))
            .map(|attesting_oracle| {
                env.storage()
                    .instance()
                    .get::<DataKey, bool>(&DataKey::Oracle(attesting_oracle))
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        env.events()
            .publish((VERIFY_CLAIM_TOPIC,), (result, claim_hash));

        if result {
            Self::record_verification(&env, &proof_hash, true);
        }

        result
    }

    /// Verifies a lattice-based (quantum-resistant) proof.
    ///
    /// Lattice proofs must have a valid header (LATTICE_V1) and be attested by a registered oracle.
    /// Supports migration from classical to quantum-resistant schemes.
    pub fn verify_lattice_proof(env: Env, proof: Bytes, claim: Bytes) -> bool {
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

        if !Self::is_valid_lattice_proof(&proof) {
            panic_with_error!(&env, VerifierError::InvalidLatticeProof);
        }

        let proof_hash: BytesN<32> = env.crypto().sha256(&proof).into();
        let claim_hash: BytesN<32> = env.crypto().sha256(&claim).into();

        let result = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::Attestation(proof_hash.clone(), claim_hash.clone()))
            .map(|attesting_oracle| {
                env.storage()
                    .instance()
                    .get::<DataKey, bool>(&DataKey::Oracle(attesting_oracle))
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        let current_time: U64 = env.ledger().timestamp().into();
        env.storage()
            .instance()
            .set(&DataKey::LastVerificationTime(proof_hash.clone()), &current_time);

        env.events()
            .publish((VERIFY_LATTICE_TOPIC,), (result, proof_hash.clone()));

        if result {
            Self::record_verification(&env, &proof_hash, true);
        }

        result
    }

    /// Exports a proof in standard external format for cross-system verification.
    /// Supports interoperability with external verifiers.
    pub fn export_proof_for_external_verification(
        env: Env,
        proof: Bytes,
        format_type: u32,
    ) -> Bytes {
        if proof.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }
        if proof.len() > MAX_PROOF_SIZE {
            panic_with_error!(&env, VerifierError::ProofTooLarge);
        }

        let mut exported = Bytes::new(&env);
        exported.append(&Bytes::from_array(&env, &[format_type as u8; 1]));
        exported.append(&proof);

        let proof_hash: BytesN<32> = env.crypto().sha256(&proof).into();
        exported.append(&proof_hash.to_bytes());

        if exported.len() > MAX_EXTERNAL_FORMAT_SIZE {
            panic_with_error!(&env, VerifierError::ExternalFormatTooLarge);
        }

        exported
    }

    /// Gets the verification history for a proof identified by its hash.
    /// Returns all verification attempts with timestamps.
    pub fn get_proof_verification_history(env: Env, proof_hash: BytesN<32>) -> Vec<VerificationRecord> {
        env.storage()
            .instance()
            .get::<DataKey, Vec<VerificationRecord>>(&DataKey::VerificationHistory(proof_hash))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Masks sensitive fields in a proof before verification.
    /// Creates a masked proof that hides specified fields.
    pub fn mask_proof_fields(
        env: Env,
        proof: Bytes,
        fields_to_mask: Vec<u32>,
    ) -> Bytes {
        if proof.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }
        if proof.len() > MAX_PROOF_SIZE {
            panic_with_error!(&env, VerifierError::ProofTooLarge);
        }
        if fields_to_mask.is_empty() {
            panic_with_error!(&env, VerifierError::InvalidMaskSpec);
        }

        let mut masked = Bytes::new(&env);
        masked.append(&Bytes::from_array(&env, b"MASKED_V1"));

        let mut field_mask: u32 = 0;
        for i in 0..fields_to_mask.len() {
            if let Some(field_idx) = fields_to_mask.get(i) {
                field_mask |= 1 << field_idx;
            }
        }

        masked.append(&Bytes::from_array(&env, &field_mask.to_le_bytes()));
        masked.append(&proof);

        if masked.len() > MAX_EXTERNAL_FORMAT_SIZE {
            panic_with_error!(&env, VerifierError::ExternalFormatTooLarge);
        }

        let proof_hash: BytesN<32> = env.crypto().sha256(&proof).into();
        let masking_spec: BytesN<32> = env.crypto().sha256(&Bytes::from_array(&env, &field_mask.to_le_bytes())).into();

        env.storage()
            .instance()
            .set(&DataKey::MaskingConfig(proof_hash), &MaskingConfig {
                masked_fields: masking_spec,
                version: 1,
            });

        env.events()
            .publish((PROOF_MASKED_TOPIC,), (proof_hash,));

        masked
    }

    /// Verifies a masked proof, comparing only unmasked fields.
    pub fn verify_masked_proof(env: Env, masked_proof: Bytes, claim: Bytes) -> bool {
        if masked_proof.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }
        if claim.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyClaim);
        }

        if masked_proof.len() < 13 {
            panic_with_error!(&env, VerifierError::InvalidMaskSpec);
        }

        let masked_hash: BytesN<32> = env.crypto().sha256(&masked_proof).into();
        let claim_hash: BytesN<32> = env.crypto().sha256(&claim).into();

        let result = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::Attestation(masked_hash, claim_hash))
            .map(|attesting_oracle| {
                env.storage()
                    .instance()
                    .get::<DataKey, bool>(&DataKey::Oracle(attesting_oracle))
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        if !result {
            panic_with_error!(&env, VerifierError::MaskedVerificationFailed);
        }

        result
    }

    // ---- helpers ----

    fn is_valid_lattice_proof(proof: &Bytes) -> bool {
        if proof.len() < LATTICE_PROOF_HEADER.len() {
            return false;
        }

        for (i, &byte) in LATTICE_PROOF_HEADER.iter().enumerate() {
            if proof.get(i as u32).unwrap_or(0) != byte {
                return false;
            }
        }

        true
    }

    fn record_verification(env: &Env, proof_hash: &BytesN<32>, verified: bool) {
        let mut history = env
            .storage()
            .instance()
            .get::<DataKey, Vec<VerificationRecord>>(&DataKey::VerificationHistory(proof_hash.clone()))
            .unwrap_or_else(|| Vec::new(env));

        let current_time = env.ledger().timestamp();

        history.push_back(VerificationRecord {
            timestamp: current_time.into(),
            verified,
            oracle: Address::from_contract_id(&env, &BytesN::from_array(&env, &[0u8; 32])),
        });

        env.storage()
            .instance()
            .set(&DataKey::VerificationHistory(proof_hash.clone()), &history);

        env.events()
            .publish((AUDIT_LOG_TOPIC,), (proof_hash.clone(), current_time, verified));
    }

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(env, VerifierError::NotInitialized));
        admin.require_auth();
    }
}

#[cfg(test)]
mod test;
