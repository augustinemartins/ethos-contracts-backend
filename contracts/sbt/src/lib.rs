#![no_std]

use soroban_sdk::{contract, contracterror, contractimpl, panic_with_error, Address, Bytes, Env};

mod types;

use types::{
    DataKey, Sbt, CURRENT_SCHEMA_VERSION, INSTANCE_TTL_LEDGERS, INSTANCE_TTL_THRESHOLD,
    MAX_METADATA_SIZE, MINT_TOPIC, RECORD_TTL_LEDGERS, RECORD_TTL_THRESHOLD,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SbtError {
    /// Contract has already been initialized.
    AlreadyInitialized = 1,
    /// Contract has not been initialized.
    NotInitialized = 2,
    /// No SBT exists with the given id.
    SbtNotFound = 4,
    /// Metadata bytes were empty.
    EmptyMetadata = 5,
    /// Metadata bytes exceed MAX_METADATA_SIZE.
    MetadataTooLarge = 6,
}

#[contract]
pub struct SbtContract;

#[contractimpl]
impl SbtContract {
    // ---- core lifecycle ----

    /// Initialize the contract with an admin address. The admin is the sole
    /// issuer authority: only the admin can mint SBTs or manage the
    /// attestor registry used for identity linking.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(&env, SbtError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::NextSbtId, &0u64);
        Self::bump_instance(&env);
    }

    /// Mints a new soulbound token to `owner`. Admin only. SBTs are
    /// non-transferable by construction: there is no `transfer` function,
    /// and the only way a token's holder ever changes is through
    /// `recover_sbt_with_recovery_code` (issue #51).
    pub fn mint_sbt(env: Env, owner: Address, metadata: Bytes) -> u64 {
        Self::require_admin(&env);
        if metadata.is_empty() {
            panic_with_error!(&env, SbtError::EmptyMetadata);
        }
        if metadata.len() > MAX_METADATA_SIZE {
            panic_with_error!(&env, SbtError::MetadataTooLarge);
        }

        let sbt_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextSbtId)
            .unwrap_or(0);

        let sbt = Sbt {
            owner: owner.clone(),
            metadata,
            schema_version: CURRENT_SCHEMA_VERSION,
            issued_at: env.ledger().timestamp(),
        };
        Self::save_sbt(&env, sbt_id, &sbt);

        env.storage()
            .instance()
            .set(&DataKey::NextSbtId, &(sbt_id + 1));
        Self::bump_instance(&env);

        env.events().publish((MINT_TOPIC, sbt_id), owner);
        sbt_id
    }

    /// Returns the current holder of an SBT.
    pub fn get_holder(env: Env, sbt_id: u64) -> Address {
        Self::load_sbt(&env, sbt_id).owner
    }

    /// Returns the raw metadata bytes currently stored for an SBT.
    pub fn get_metadata(env: Env, sbt_id: u64) -> Bytes {
        Self::load_sbt(&env, sbt_id).metadata
    }

    /// Returns the metadata schema version an SBT is currently encoded at.
    pub fn get_schema_version(env: Env, sbt_id: u64) -> u32 {
        Self::load_sbt(&env, sbt_id).schema_version
    }

    // ---- internal helpers ----

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(env, SbtError::NotInitialized));
        admin.require_auth();
    }

    fn bump_instance(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_LEDGERS);
    }

    fn load_sbt(env: &Env, sbt_id: u64) -> Sbt {
        env.storage()
            .persistent()
            .get(&DataKey::Sbt(sbt_id))
            .unwrap_or_else(|| panic_with_error!(env, SbtError::SbtNotFound))
    }

    fn save_sbt(env: &Env, sbt_id: u64, sbt: &Sbt) {
        let key = DataKey::Sbt(sbt_id);
        env.storage().persistent().set(&key, sbt);
        env.storage()
            .persistent()
            .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_LEDGERS);
    }
}
