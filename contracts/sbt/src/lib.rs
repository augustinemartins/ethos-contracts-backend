#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, panic_with_error, Address, Bytes, BytesN, Env, Vec,
};

mod types;

use types::{
    CacheStats, DataKey, HolderCacheEntry, IdentityLink, RecoveryAttemptState, Sbt,
    CURRENT_SCHEMA_VERSION, HOLDER_CACHE_TTL_SECONDS, IDENTITY_LINKED_TOPIC,
    IDENTITY_UNLINKED_TOPIC, INSTANCE_TTL_LEDGERS, INSTANCE_TTL_THRESHOLD,
    MAX_IDENTITY_PROOF_SIZE, MAX_METADATA_SIZE, METADATA_MIGRATED_TOPIC, MINT_TOPIC,
    RECORD_TTL_LEDGERS, RECORD_TTL_THRESHOLD, RECOVERY_ATTEMPT_WINDOW_SECONDS,
    RECOVERY_CODES_GENERATED_TOPIC, RECOVERY_CODE_COUNT, RECOVERY_MAX_ATTEMPTS,
    RECOVERY_RATE_LIMITED_TOPIC, RECOVERY_SUCCEEDED_TOPIC,
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
    /// SBT has no unused recovery codes; generate new ones first.
    NoRecoveryCodes = 13,
    /// Recovery attempts have exceeded the allowed rate for the current window.
    RecoveryRateLimited = 14,
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

    // ---- issue #51: recovery code system ----
    //
    // Recovery codes let a lost SBT be reclaimed without the original
    // owner's signature (the whole point of a recovery flow is that the
    // owner can no longer sign). Only `sha256(code)` is ever stored; the
    // plaintext codes are returned once, at generation time, and the caller
    // is responsible for storing them off-chain. Regenerating replaces (and
    // so invalidates) any previously issued, unused codes.
    //
    // `recover_sbt_with_recovery_code` takes an explicit `new_holder`
    // address rather than relying on an implicit caller identity: Soroban
    // has no `msg.sender` equivalent, so the address regaining control must
    // be passed and authorized explicitly. This is the one place this
    // contract's API intentionally departs from the issue's suggested
    // signature.
    //
    // Security note: recovery codes are generated with `env.prng()`, which
    // the Soroban SDK documents as unsuitable for secrets in applications
    // with low risk tolerance. This is acceptable for the scope of this
    // issue but should be revisited (e.g. moving to an off-chain-generated,
    // on-chain-committed scheme) before using this contract to guard
    // high-value identities.

    /// Generates `RECOVERY_CODE_COUNT` fresh one-time recovery codes for
    /// `sbt_id`, returning the plaintext codes. Only their SHA-256 hashes
    /// are persisted. Owner only.
    pub fn generate_sbt_recovery_codes(env: Env, sbt_id: u64) -> Vec<BytesN<32>> {
        let sbt = Self::load_sbt(&env, sbt_id);
        sbt.owner.require_auth();

        let prng = env.prng();
        let mut plaintext_codes: Vec<BytesN<32>> = Vec::new(&env);
        let mut hashed_codes: Vec<BytesN<32>> = Vec::new(&env);

        for _ in 0..RECOVERY_CODE_COUNT {
            let raw: [u8; 32] = prng.gen();
            let code = BytesN::from_array(&env, &raw);
            let code_bytes: Bytes = code.clone().into();
            let hash: BytesN<32> = env.crypto().sha256(&code_bytes).into();
            plaintext_codes.push_back(code);
            hashed_codes.push_back(hash);
        }

        let codes_key = DataKey::RecoveryCodes(sbt_id);
        env.storage().persistent().set(&codes_key, &hashed_codes);
        env.storage()
            .persistent()
            .extend_ttl(&codes_key, RECORD_TTL_THRESHOLD, RECORD_TTL_LEDGERS);

        env.events().publish(
            (RECOVERY_CODES_GENERATED_TOPIC, sbt_id),
            hashed_codes.len(),
        );
        plaintext_codes
    }

    /// Reclaims `sbt_id` for `new_holder` by redeeming a still-unused
    /// recovery code. `new_holder` must authorize the call. Rate limited to
    /// `RECOVERY_MAX_ATTEMPTS` attempts per `RECOVERY_ATTEMPT_WINDOW_SECONDS`
    /// per SBT, counting both successful and failed attempts. Returns
    /// `true` and reassigns the holder on success; `false` if the code does
    /// not match any unused, stored hash.
    pub fn recover_sbt_with_recovery_code(
        env: Env,
        sbt_id: u64,
        recovery_code: Bytes,
        new_holder: Address,
    ) -> bool {
        new_holder.require_auth();

        let mut sbt = Self::load_sbt(&env, sbt_id);
        Self::enforce_recovery_rate_limit(&env, sbt_id);

        let codes_key = DataKey::RecoveryCodes(sbt_id);
        let mut hashed_codes: Vec<BytesN<32>> = env
            .storage()
            .persistent()
            .get(&codes_key)
            .unwrap_or_else(|| panic_with_error!(&env, SbtError::NoRecoveryCodes));

        let submitted_hash: BytesN<32> = env.crypto().sha256(&recovery_code).into();
        let Some(index) = hashed_codes.first_index_of(submitted_hash) else {
            return false;
        };

        hashed_codes.remove(index);
        env.storage().persistent().set(&codes_key, &hashed_codes);

        sbt.owner = new_holder.clone();
        Self::save_sbt(&env, sbt_id, &sbt);
        Self::evict_holder_cache(&env, sbt_id);

        env.events()
            .publish((RECOVERY_SUCCEEDED_TOPIC, sbt_id), new_holder);
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

    fn enforce_recovery_rate_limit(env: &Env, sbt_id: u64) {
        let now = env.ledger().timestamp();
        let key = DataKey::RecoveryAttempts(sbt_id);
        let mut state = env
            .storage()
            .persistent()
            .get::<DataKey, RecoveryAttemptState>(&key)
            .unwrap_or(RecoveryAttemptState {
                attempt_count: 0,
                window_start: now,
            });

        if now.saturating_sub(state.window_start) >= RECOVERY_ATTEMPT_WINDOW_SECONDS {
            state.window_start = now;
            state.attempt_count = 0;
        }

        if state.attempt_count >= RECOVERY_MAX_ATTEMPTS {
            env.events()
                .publish((RECOVERY_RATE_LIMITED_TOPIC, sbt_id), state.attempt_count);
            panic_with_error!(env, SbtError::RecoveryRateLimited);
        }

        state.attempt_count += 1;
        env.storage().persistent().set(&key, &state);
        env.storage()
            .persistent()
            .extend_ttl(&key, RECORD_TTL_THRESHOLD, RECORD_TTL_LEDGERS);
    }
}

#[cfg(test)]
mod test;
