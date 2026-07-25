use soroban_sdk::{contracttype, symbol_short, Address, Bytes, BytesN, Symbol};

/// Current metadata schema version newly minted SBTs are issued at.
///
/// Bumping this constant does not retroactively upgrade existing SBTs —
/// callers must invoke `migrate_sbt_metadata` explicitly. See that function's
/// docs for the migration strategy.
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

pub const MAX_METADATA_SIZE: u32 = 4096;
pub const MAX_IDENTITY_PROOF_SIZE: u32 = 4096;

/// How long a cached holder lookup is considered fresh.
pub const HOLDER_CACHE_TTL_SECONDS: u64 = 300;

pub const INSTANCE_TTL_THRESHOLD: u32 = 17280; // ~1 day of ledgers at 5s/ledger
pub const INSTANCE_TTL_LEDGERS: u32 = 518_400; // ~30 days
pub const RECORD_TTL_THRESHOLD: u32 = 17280;
pub const RECORD_TTL_LEDGERS: u32 = 518_400;

pub const MINT_TOPIC: Symbol = symbol_short!("sbt_mint");
pub const IDENTITY_LINKED_TOPIC: Symbol = symbol_short!("id_link");
pub const IDENTITY_UNLINKED_TOPIC: Symbol = symbol_short!("id_unlink");
pub const METADATA_MIGRATED_TOPIC: Symbol = symbol_short!("md_migr");

#[contracttype]
pub enum DataKey {
    Admin,
    NextSbtId,
    /// Core SBT record.
    Sbt(u64),
    /// Registered identity attestors (KYC/identity oracles). issue #48.
    Attestor(Address),
    /// Attestor-published commitment: (identity_hash, sha256(proof)) -> attestor.
    /// issue #48.
    IdentityAttestation(BytesN<32>, BytesN<32>),
    /// sbt_id -> linked identity, once revealed via `link_sbt_to_identity`. issue #48.
    IdentityLink(u64),
    /// sbt_id -> cached holder lookup. issue #49.
    HolderCache(u64),
    /// Global cache hit/miss counters. issue #49.
    CacheStats,
}

#[contracttype]
#[derive(Clone)]
pub struct Sbt {
    pub owner: Address,
    pub metadata: Bytes,
    pub schema_version: u32,
    pub issued_at: u64,
}

/// A revealed identity link. Only the SHA-256 hash of the underlying
/// identity is ever stored — see `link_sbt_to_identity` for the privacy
/// rationale.
#[contracttype]
#[derive(Clone)]
pub struct IdentityLink {
    pub identity_hash: BytesN<32>,
    pub attestor: Address,
    pub linked_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct HolderCacheEntry {
    pub holder: Address,
    pub cached_at: u64,
    pub expires_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
}
