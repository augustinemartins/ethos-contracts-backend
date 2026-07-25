#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, panic_with_error, Address, Bytes, BytesN, Env,
};

mod types;

use types::{
    CacheStats, DataKey, HolderCacheEntry, IdentityLink, Sbt, CURRENT_SCHEMA_VERSION,
    HOLDER_CACHE_TTL_SECONDS, IDENTITY_LINKED_TOPIC, IDENTITY_UNLINKED_TOPIC,
    INSTANCE_TTL_LEDGERS, INSTANCE_TTL_THRESHOLD, MAX_IDENTITY_PROOF_SIZE, MAX_METADATA_SIZE,
    METADATA_MIGRATED_TOPIC, MINT_TOPIC, RECORD_TTL_LEDGERS, RECORD_TTL_THRESHOLD,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SbtError {
    /// Contract has already been initialized.
    AlreadyInitialized = 1,
    /// Contract has not been initialized.
    NotInitialized = 2,
    /// Caller is not a registered identity attestor.
    NotAttestor = 3,
    /// No SBT exists with the given id.
    SbtNotFound = 4,
    /// Metadata bytes were empty.
    EmptyMetadata = 5,
    /// Metadata bytes exceed MAX_METADATA_SIZE.
    MetadataTooLarge = 6,
    /// Proof bytes were empty.
    EmptyProof = 7,
    /// Proof bytes exceed MAX_IDENTITY_PROOF_SIZE.
    ProofTooLarge = 8,
    /// The SBT already has a linked identity; unlink before relinking.
    IdentityAlreadyLinked = 9,
    /// The SBT has no linked identity to unlink.
    NoIdentityLinked = 10,
    /// No attestation matches the given (identity_hash, proof) pair.
    AttestationNotFound = 11,
    /// Requested schema version is not a valid forward migration target.
    InvalidSchemaTransition = 12,
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

    // ---- issue #48: identity linkage ----
    //
    // Privacy model: raw real-world identity data is never sent to, or
    // stored on, the contract. An attestor (e.g. a KYC provider) that has
    // verified an individual off-chain publishes a *commitment* on-chain:
    // `sha256(proof)` keyed by `identity_hash` (itself a hash the individual
    // controls, e.g. `sha256(document_id || salt)`). The SBT owner later
    // reveals `proof` to `link_sbt_to_identity`; the contract re-hashes it
    // and checks it matches the attestor's commitment. Only `identity_hash`
    // is written to the link record — the proof and any underlying PII stay
    // off-chain for the lifetime of the contract.

    /// Admin grants `attestor` the ability to publish identity attestations.
    pub fn add_attestor(env: Env, attestor: Address) {
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::Attestor(attestor), &true);
        Self::bump_instance(&env);
    }

    /// Admin revokes an attestor. Existing links made through this attestor
    /// remain in place (see `link_sbt_to_identity` for why), but the
    /// attestor can no longer register new commitments.
    pub fn remove_attestor(env: Env, attestor: Address) {
        Self::require_admin(&env);
        env.storage().instance().remove(&DataKey::Attestor(attestor));
        Self::bump_instance(&env);
    }

    /// Returns whether `attestor` is currently trusted.
    pub fn is_attestor(env: Env, attestor: Address) -> bool {
        env.storage()
            .instance()
            .get::<DataKey, bool>(&DataKey::Attestor(attestor))
            .unwrap_or(false)
    }

    /// An attestor commits that `identity_hash` is backed by a valid,
    /// off-chain-verified `proof`, without revealing `proof` itself. Only
    /// `sha256(proof)` is stored.
    pub fn register_identity_attestation(
        env: Env,
        attestor: Address,
        identity_hash: BytesN<32>,
        proof: Bytes,
    ) {
        if proof.is_empty() {
            panic_with_error!(&env, SbtError::EmptyProof);
        }
        if proof.len() > MAX_IDENTITY_PROOF_SIZE {
            panic_with_error!(&env, SbtError::ProofTooLarge);
        }
        if !Self::is_attestor(env.clone(), attestor.clone()) {
            panic_with_error!(&env, SbtError::NotAttestor);
        }
        attestor.require_auth();

        let proof_hash: BytesN<32> = env.crypto().sha256(&proof).into();
        let key = DataKey::IdentityAttestation(identity_hash, proof_hash);
        env.storage().persistent().set(&key, &attestor);
        env.storage()
            .persistent()
            .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_LEDGERS);
    }

    /// The SBT owner reveals `proof` to link their token to `identity_hash`.
    /// Requires a matching attestation previously registered by an attestor
    /// that is *still* currently trusted (revoked attestors' outstanding
    /// commitments can no longer be redeemed — same revocation semantics as
    /// `zk_verifier::verify_claim`).
    pub fn link_sbt_to_identity(env: Env, sbt_id: u64, identity_hash: BytesN<32>, proof: Bytes) {
        let sbt = Self::load_sbt(&env, sbt_id);
        sbt.owner.require_auth();

        if proof.is_empty() {
            panic_with_error!(&env, SbtError::EmptyProof);
        }
        if env.storage().persistent().has(&DataKey::IdentityLink(sbt_id)) {
            panic_with_error!(&env, SbtError::IdentityAlreadyLinked);
        }

        let proof_hash: BytesN<32> = env.crypto().sha256(&proof).into();
        let attestation_key =
            DataKey::IdentityAttestation(identity_hash.clone(), proof_hash);
        let attestor: Address = env
            .storage()
            .persistent()
            .get(&attestation_key)
            .unwrap_or_else(|| panic_with_error!(&env, SbtError::AttestationNotFound));

        if !Self::is_attestor(env.clone(), attestor.clone()) {
            panic_with_error!(&env, SbtError::AttestationNotFound);
        }

        let link = IdentityLink {
            identity_hash,
            attestor,
            linked_at: env.ledger().timestamp(),
        };
        let link_key = DataKey::IdentityLink(sbt_id);
        env.storage().persistent().set(&link_key, &link);
        env.storage()
            .persistent()
            .extend_ttl(&link_key, RECORD_TTL_THRESHOLD, RECORD_TTL_LEDGERS);

        env.events().publish((IDENTITY_LINKED_TOPIC, sbt_id), ());
    }

    /// Removes the identity link from an SBT. Owner only.
    pub fn unlink_sbt_identity(env: Env, sbt_id: u64) {
        let sbt = Self::load_sbt(&env, sbt_id);
        sbt.owner.require_auth();

        let link_key = DataKey::IdentityLink(sbt_id);
        if !env.storage().persistent().has(&link_key) {
            panic_with_error!(&env, SbtError::NoIdentityLinked);
        }
        env.storage().persistent().remove(&link_key);
        env.events().publish((IDENTITY_UNLINKED_TOPIC, sbt_id), ());
    }

    /// Returns whether an SBT currently has a linked identity.
    pub fn is_identity_linked(env: Env, sbt_id: u64) -> bool {
        env.storage().persistent().has(&DataKey::IdentityLink(sbt_id))
    }

    /// Returns the linked identity's hash, if any. Never returns raw
    /// identity data or the proof — neither is ever stored on-chain.
    pub fn get_linked_identity_hash(env: Env, sbt_id: u64) -> Option<BytesN<32>> {
        env.storage()
            .persistent()
            .get::<DataKey, IdentityLink>(&DataKey::IdentityLink(sbt_id))
            .map(|link| link.identity_hash)
    }

    // ---- issue #49: holder verification cache ----
    //
    // `get_holder` already does a single storage read, but callers that
    // verify the same SBT's holder repeatedly within a short window (e.g. a
    // gating check run on every request) can skip re-reading the canonical
    // record by going through this cache instead. Entries expire after
    // `HOLDER_CACHE_TTL_SECONDS` and are eagerly invalidated whenever a
    // holder actually changes (see `recover_sbt_with_recovery_code`).

    /// Verifies whether `claimed_holder` currently holds `sbt_id`, serving
    /// the answer from a short-lived cache when possible. Returns the same
    /// result `get_holder(sbt_id) == claimed_holder` would, just faster on
    /// a cache hit.
    pub fn verify_holder_cached(env: Env, sbt_id: u64, claimed_holder: Address) -> bool {
        let now = env.ledger().timestamp();
        let cache_key = DataKey::HolderCache(sbt_id);

        if let Some(entry) = env
            .storage()
            .persistent()
            .get::<DataKey, HolderCacheEntry>(&cache_key)
        {
            if entry.expires_at > now {
                Self::record_cache_stat(&env, true);
                return entry.holder == claimed_holder;
            }
        }

        Self::record_cache_stat(&env, false);
        let holder = Self::load_sbt(&env, sbt_id).owner;
        let entry = HolderCacheEntry {
            holder: holder.clone(),
            cached_at: now,
            expires_at: now + HOLDER_CACHE_TTL_SECONDS,
        };
        env.storage().persistent().set(&cache_key, &entry);
        env.storage()
            .persistent()
            .extend_ttl(&cache_key, RECORD_TTL_THRESHOLD, RECORD_TTL_LEDGERS);

        holder == claimed_holder
    }

    /// Manually evicts the cached holder entry for an SBT. Admin only;
    /// normal invalidation on holder change happens automatically.
    pub fn invalidate_holder_cache(env: Env, sbt_id: u64) {
        Self::require_admin(&env);
        Self::evict_holder_cache(&env, sbt_id);
    }

    /// Returns cumulative cache hit/miss counters since the contract was
    /// initialized. Used to benchmark cache effectiveness off-chain: divide
    /// `hits` by `hits + misses` for the hit rate, or call
    /// `cache_hit_rate_bps`.
    pub fn get_cache_stats(env: Env) -> CacheStats {
        Self::load_cache_stats(&env)
    }

    /// Cache hit rate in basis points (0-10000), computed from
    /// `get_cache_stats`. Returns 0 if `verify_holder_cached` has never
    /// been called.
    pub fn cache_hit_rate_bps(env: Env) -> u32 {
        let stats = Self::load_cache_stats(&env);
        let total = stats.hits + stats.misses;
        if total == 0 {
            return 0;
        }
        ((stats.hits * 10_000) / total) as u32
    }

    // ---- issue #50: metadata schema versioning ----
    //
    // Migrations are applied one version step at a time, in order, so a
    // multi-version jump (e.g. v1 -> v3) replays v1 -> v2 then v2 -> v3.
    // Each step is a pure function of `(from_version, metadata)` defined in
    // `apply_schema_migration`. Bumping `CURRENT_SCHEMA_VERSION` and adding
    // a new arm there is the only change needed to support a future schema
    // revision; existing SBTs stay on their current version until this
    // function is called for them.

    /// Migrates an SBT's metadata forward to `new_schema_version`. Owner
    /// only. Returns `true` if the migration was applied, `false` if
    /// `new_schema_version` is not a valid forward migration target (at or
    /// below the current version, or beyond `CURRENT_SCHEMA_VERSION`).
    pub fn migrate_sbt_metadata(env: Env, sbt_id: u64, new_schema_version: u32) -> bool {
        let mut sbt = Self::load_sbt(&env, sbt_id);
        sbt.owner.require_auth();

        if new_schema_version <= sbt.schema_version || new_schema_version > CURRENT_SCHEMA_VERSION
        {
            return false;
        }

        let mut version = sbt.schema_version;
        let mut metadata = sbt.metadata.clone();
        while version < new_schema_version {
            metadata = Self::apply_schema_migration(&env, version, metadata);
            version += 1;
        }

        sbt.metadata = metadata;
        sbt.schema_version = version;
        Self::save_sbt(&env, sbt_id, &sbt);

        env.events()
            .publish((METADATA_MIGRATED_TOPIC, sbt_id), new_schema_version);
        true
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

    fn evict_holder_cache(env: &Env, sbt_id: u64) {
        env.storage()
            .persistent()
            .remove(&DataKey::HolderCache(sbt_id));
    }

    fn load_cache_stats(env: &Env) -> CacheStats {
        env.storage()
            .instance()
            .get(&DataKey::CacheStats)
            .unwrap_or(CacheStats { hits: 0, misses: 0 })
    }

    fn record_cache_stat(env: &Env, hit: bool) {
        let mut stats = Self::load_cache_stats(env);
        if hit {
            stats.hits += 1;
        } else {
            stats.misses += 1;
        }
        env.storage().instance().set(&DataKey::CacheStats, &stats);
    }

    /// Applies a single schema migration step. Panics on an unrecognized
    /// `from_version`; unreachable in practice because
    /// `migrate_sbt_metadata` only ever calls this with versions in
    /// `[sbt.schema_version, CURRENT_SCHEMA_VERSION)`, which is always
    /// exactly `{1}` today. The panic exists so a future version bump that
    /// forgets to add a matching arm here fails loudly instead of silently
    /// truncating metadata.
    fn apply_schema_migration(env: &Env, from_version: u32, metadata: Bytes) -> Bytes {
        match from_version {
            // v1 -> v2: v1 metadata was an opaque blob with no
            // self-describing format. v2 prefixes a 1-byte schema tag so
            // downstream readers can identify the encoding without an
            // external version lookup.
            1 => {
                let mut migrated = Bytes::new(env);
                migrated.push_back(2u8);
                migrated.append(&metadata);
                migrated
            }
            _ => panic_with_error!(env, SbtError::InvalidSchemaTransition),
        }
    }
}

#[cfg(test)]
mod test;
