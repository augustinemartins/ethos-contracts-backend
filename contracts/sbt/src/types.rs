use soroban_sdk::{contracttype, symbol_short, Address, Bytes, Symbol};

/// Current metadata schema version newly minted SBTs are issued at.
///
/// Bumping this constant does not retroactively upgrade existing SBTs —
/// callers must invoke `migrate_sbt_metadata` explicitly. See that function's
/// docs for the migration strategy.
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

pub const MAX_METADATA_SIZE: u32 = 4096;

pub const INSTANCE_TTL_THRESHOLD: u32 = 17280; // ~1 day of ledgers at 5s/ledger
pub const INSTANCE_TTL_LEDGERS: u32 = 518_400; // ~30 days
pub const RECORD_TTL_THRESHOLD: u32 = 17280;
pub const RECORD_TTL_LEDGERS: u32 = 518_400;

pub const MINT_TOPIC: Symbol = symbol_short!("sbt_mint");

#[contracttype]
pub enum DataKey {
    Admin,
    NextSbtId,
    /// Core SBT record.
    Sbt(u64),
}

#[contracttype]
#[derive(Clone)]
pub struct Sbt {
    pub owner: Address,
    pub metadata: Bytes,
    pub schema_version: u32,
    pub issued_at: u64,
}
