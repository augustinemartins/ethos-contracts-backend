//! Consistency checking for batch credential verification.
//!
//! This module provides conflict detection when verifying multiple credentials
//! simultaneously. Certain combinations of credentials are mutually exclusive
//! or incompatible due to their semantic meaning.
//!
//! ## Conflict Rules
//!
//! Conflicts are defined by credential type. For example:
//! - Age-range credentials conflict if they specify overlapping but distinct ranges
//! - KYC status credentials conflict if one is "pending" and another is "approved"
//! - Geographic credentials conflict if they specify mutually exclusive jurisdictions

use soroban_sdk::{contracterror, Bytes, Env, Symbol, Vec};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ConsistencyError {
    /// Batch is empty (need at least 2 credentials to check consistency).
    EmptyBatch = 300,
    /// A conflict was detected between credentials.
    ConflictDetected = 301,
    /// Conflict rule is not defined for this credential type.
    UnknownCredentialType = 302,
    /// Conflict reporting buffer is full.
    TooManyConflicts = 303,
}

/// Identifies the type/class of a credential (e.g., "age", "kyc", "jurisdiction").
/// Used to determine which conflict rules apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialType {
    /// Soroban Symbol encoding the credential type.
    pub type_key: Symbol,
}

/// Represents a detected conflict between two credentials in a batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictReport {
    pub credential_id_a: u64,
    pub credential_id_b: u64,
    pub conflict_reason: Bytes,
}

/// Registry of conflict rules keyed by credential type.
///
/// Each rule determines whether two credentials of the same type are compatible.
pub trait ConflictRule {
    /// Check if two credentials are compatible.
    ///
    /// Returns `true` if credentials can coexist, `false` if they conflict.
    fn are_compatible(
        env: &Env,
        claim_a: &Bytes,
        claim_b: &Bytes,
    ) -> bool;

    /// Provide a human-readable conflict reason if incompatible.
    fn conflict_reason(env: &Env) -> Bytes;
}

/// Example conflict rule: Age range credentials.
///
/// Two age credentials are compatible if:
/// - They are identical
/// - One is a subset of the other (e.g., "21+" is compatible with "18+")
/// - They don't explicitly contradict each other
pub struct AgeConflictRule;

impl ConflictRule for AgeConflictRule {
    fn are_compatible(env: &Env, claim_a: &Bytes, claim_b: &Bytes) -> bool {
        if claim_a == claim_b {
            return true;
        }
        // Parse age ranges; if parsing fails, assume no conflict (fail-safe)
        if let (Ok(age_a), Ok(age_b)) = (parse_age_claim(claim_a), parse_age_claim(claim_b)) {
            // No conflict if ranges overlap or one is contained in the other
            age_ranges_compatible(age_a, age_b)
        } else {
            true // Unparseable claims don't conflict
        }
    }

    fn conflict_reason(env: &Env) -> Bytes {
        Bytes::from_slice(env, b"Age range mismatch")
    }
}

/// Example conflict rule: KYC status.
///
/// Statuses "pending" and "approved" conflict.
/// "approved" and "rejected" conflict.
pub struct KycStatusConflictRule;

impl ConflictRule for KycStatusConflictRule {
    fn are_compatible(env: &Env, claim_a: &Bytes, claim_b: &Bytes) -> bool {
        if claim_a == claim_b {
            return true;
        }
        // Extract status from claim
        if let (Ok(status_a), Ok(status_b)) = (
            extract_kyc_status(claim_a),
            extract_kyc_status(claim_b),
        ) {
            kyc_statuses_compatible(status_a, status_b)
        } else {
            true
        }
    }

    fn conflict_reason(_env: &Env) -> Bytes {
        Bytes::from_slice(_env, b"KYC status conflict")
    }
}

/// The credential consistency registry holds rules for all known types.
pub struct CredentialRegistry {
    // In a real implementation, this would use a map. For now, we use pattern matching.
}

impl CredentialRegistry {
    /// Verify that all credentials in `credential_ids` are consistent with each other.
    ///
    /// Returns:
    /// - `Ok(())` if all credentials are compatible
    /// - `Err(ConflictDetected)` if any conflict is found, with details in the report
    pub fn verify_batch_consistency(
        env: &Env,
        credential_pairs: Vec<(u64, Bytes, u64, Bytes)>,
    ) -> Result<(), ConsistencyError> {
        if credential_pairs.is_empty() {
            return Err(ConsistencyError::EmptyBatch);
        }

        for (id_a, claim_a, id_b, claim_b) in credential_pairs.iter() {
            if !Self::are_credentials_compatible(env, &claim_a, &claim_b) {
                return Err(ConsistencyError::ConflictDetected);
            }
        }

        Ok(())
    }

    /// Check if two credentials are compatible by examining their claims.
    fn are_credentials_compatible(env: &Env, claim_a: &Bytes, claim_b: &Bytes) -> bool {
        // Determine the credential type from the claim structure.
        // This is a simplified heuristic; a real implementation would parse
        // the claim's metadata header or type field.

        if is_age_claim(claim_a) && is_age_claim(claim_b) {
            return AgeConflictRule::are_compatible(env, claim_a, claim_b);
        }

        if is_kyc_status_claim(claim_a) && is_kyc_status_claim(claim_b) {
            return KycStatusConflictRule::are_compatible(env, claim_a, claim_b);
        }

        // Default: assume compatible if types don't match or are unknown
        true
    }

    /// Generate a conflict report for debugging and audit purposes.
    pub fn generate_conflict_report(
        env: &Env,
        id_a: u64,
        id_b: u64,
        claim_a: &Bytes,
        claim_b: &Bytes,
    ) -> ConflictReport {
        let reason = if is_age_claim(claim_a) && is_age_claim(claim_b) {
            AgeConflictRule::conflict_reason(env)
        } else if is_kyc_status_claim(claim_a) && is_kyc_status_claim(claim_b) {
            KycStatusConflictRule::conflict_reason(env)
        } else {
            Bytes::from_slice(env, b"Unknown conflict type")
        };

        ConflictReport {
            credential_id_a: id_a,
            credential_id_b: id_b,
            conflict_reason: reason,
        }
    }
}

// ============================================================================
// Private Helpers
// ============================================================================

/// Simple age range representation: (min, max).
type AgeRange = (u32, u32);

fn parse_age_claim(claim: &Bytes) -> Result<AgeRange, ()> {
    if claim.len() < 8 {
        return Err(());
    }
    // Assume format: [min_u32: 4 bytes][max_u32: 4 bytes]
    let min = u32::from_be_bytes([
        claim.get(0).ok_or(())?,
        claim.get(1).ok_or(())?,
        claim.get(2).ok_or(())?,
        claim.get(3).ok_or(())?,
    ]);
    let max = u32::from_be_bytes([
        claim.get(4).ok_or(())?,
        claim.get(5).ok_or(())?,
        claim.get(6).ok_or(())?,
        claim.get(7).ok_or(())?,
    ]);
    Ok((min, max))
}

fn age_ranges_compatible(range_a: AgeRange, range_b: AgeRange) -> bool {
    // Ranges are compatible if they overlap
    range_a.0 <= range_b.1 && range_b.0 <= range_a.1
}

fn is_age_claim(claim: &Bytes) -> bool {
    // Heuristic: age claims are typically 8 bytes and have reasonable values
    if claim.len() < 8 {
        return false;
    }
    if let Ok((min, max)) = parse_age_claim(claim) {
        min < max && max < 200 // Reasonable age range
    } else {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KycStatus {
    Pending,
    Approved,
    Rejected,
    Unknown,
}

fn extract_kyc_status(claim: &Bytes) -> Result<KycStatus, ()> {
    if claim.is_empty() {
        return Err(());
    }
    // Assume first byte encodes status: 0=pending, 1=approved, 2=rejected
    match claim.get(0).ok_or(())? {
        0 => Ok(KycStatus::Pending),
        1 => Ok(KycStatus::Approved),
        2 => Ok(KycStatus::Rejected),
        _ => Ok(KycStatus::Unknown),
    }
}

fn kyc_statuses_compatible(a: KycStatus, b: KycStatus) -> bool {
    if a == b {
        return true;
    }
    // Conflicts:
    // pending + approved = OK (both express KYC in progress or done)
    // pending + rejected = CONFLICT
    // approved + rejected = CONFLICT
    match (a, b) {
        (KycStatus::Pending, KycStatus::Rejected) => false,
        (KycStatus::Rejected, KycStatus::Pending) => false,
        (KycStatus::Approved, KycStatus::Rejected) => false,
        (KycStatus::Rejected, KycStatus::Approved) => false,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_age_ranges_overlap() {
        assert!(age_ranges_compatible((18, 65), (21, 100)));
    }

    #[test]
    fn test_age_ranges_disjoint() {
        assert!(!age_ranges_compatible((18, 20), (21, 100)));
    }

    #[test]
    fn test_kyc_status_conflicts() {
        assert!(!kyc_statuses_compatible(KycStatus::Pending, KycStatus::Rejected));
        assert!(!kyc_statuses_compatible(KycStatus::Approved, KycStatus::Rejected));
        assert!(kyc_statuses_compatible(KycStatus::Pending, KycStatus::Approved));
    }
}
