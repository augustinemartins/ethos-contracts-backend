#![no_std]

pub mod compression;
use compression::{compress_proof as rle_compress, decompress_proof as rle_decompress};

use soroban_sdk::{
    contract, contracterror, contractimpl, panic_with_error, symbol_short, Address, Bytes, BytesN,
    Env,
};

pub const MAX_PROOF_SIZE: u32 = 4096;
pub const MAX_CLAIM_SIZE: u32 = 1024;

const VERIFY_CLAIM_TOPIC: soroban_sdk::Symbol = symbol_short!("vfy_claim");

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
}

/// Storage key discriminants.
mod keys {
    use soroban_sdk::{contracttype, Address, BytesN};

    #[contracttype]
    pub enum DataKey {
        Admin,
        Oracle(Address),
        /// Attestation: (proof_sha256, claim_sha256) -> attesting oracle
        Attestation(BytesN<32>, BytesN<32>),
    }
}

use keys::DataKey;

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

    // ---- Proof compression (#64) ────────────────────────────────────────────

    /// Compress a proof using RLE to reduce storage and transmission costs.
    ///
    /// Returns the compressed bytes.  The first byte of the result is always
    /// the `0xC0` magic sentinel so that callers can detect compressed streams.
    ///
    /// Panics with [`VerifierError::EmptyProof`] if `proof` is empty.
    pub fn compress_proof(env: Env, proof: Bytes) -> Bytes {
        if proof.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }
        match rle_compress(&env, &proof) {
            Ok(compressed) => compressed,
            Err(_) => panic_with_error!(&env, VerifierError::EmptyProof),
        }
    }

    /// Decompress a proof previously compressed with [`compress_proof`].
    ///
    /// `max_size` caps decompressed output to prevent decompression bombs;
    /// pass [`MAX_PROOF_SIZE`] (4096) for normal proof payloads.
    ///
    /// Panics with [`VerifierError::ProofTooLarge`] when the result would
    /// exceed `max_size`, or [`VerifierError::EmptyProof`] for empty / corrupt
    /// input.
    pub fn decompress_proof(env: Env, proof: Bytes, max_size: u32) -> Bytes {
        if proof.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }
        match rle_decompress(&env, &proof, max_size) {
            Ok(decompressed) => decompressed,
            Err(compression::CompressionError::OutputTooLarge) => {
                panic_with_error!(&env, VerifierError::ProofTooLarge)
            }
            Err(_) => panic_with_error!(&env, VerifierError::EmptyProof),
        }
    }
}

#[cfg(test)]
mod test;