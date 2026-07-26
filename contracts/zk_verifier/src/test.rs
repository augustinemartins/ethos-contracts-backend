#![cfg(test)]

use super::*;
use soroban_sdk::{
    bytes,
    testutils::{Address as _, Events as _},
    Bytes, Env,
};

fn setup() -> (Env, Address, ZkVerifierContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register_contract(None, ZkVerifierContract);
    let client = ZkVerifierContractClient::new(&env, &id);
    client.initialize(&admin);
    let client: ZkVerifierContractClient<'static> = unsafe { core::mem::transmute(client) };
    (env, admin, client)
}

// ---- existing interface: empty inputs still panic ----

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn test_malformed_empty_proof_panics() {
    let (env, _, client) = setup();
    let proof = bytes!(&env,);
    let claim = bytes!(&env, 0xcafebabe);
    client.verify_claim(&proof, &claim);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn test_malformed_empty_claim_panics() {
    let (env, _, client) = setup();
    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env,);
    client.verify_claim(&proof, &claim);
}

// ---- oracle model tests ----

/// An unattested (proof, claim) pair — never attested by any oracle — must
/// return `false`, not panic.
#[test]
fn test_unattested_proof_returns_false() {
    let (env, _, client) = setup();
    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    assert!(!client.verify_claim(&proof, &claim));
}

// ── Existing correctness tests ────────────────────────────────────────────────

/// A (proof, claim) pair attested by a currently-registered oracle — must
/// return true.
#[test]
fn test_attested_proof_returns_true() {
    let (env, _, client) = setup();
    let oracle = Address::generate(&env);
    client.register_oracle(&oracle);

    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    client.attest(&oracle, &proof, &claim);

    assert!(client.verify_claim(&proof, &claim));
}

/// Attesting one proof does not validate a different, unattested proof for
/// the same claim.
#[test]
fn test_different_proof_not_validated_after_attestation() {
    let (env, _, client) = setup();
    let oracle = Address::generate(&env);
    client.register_oracle(&oracle);

    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    client.attest(&oracle, &proof, &claim);

    let other_proof = bytes!(&env, 0x1234);
    assert!(!client.verify_claim(&other_proof, &claim));
}

/// Once the attesting oracle is revoked, its previously-stored attestation
/// must no longer be honored — `verify_claim` returns `false`, not panic.
#[test]
fn test_revoked_oracle_attestation_no_longer_accepted() {
    let (env, _, client) = setup();
    let oracle = Address::generate(&env);
    client.register_oracle(&oracle);

    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    client.attest(&oracle, &proof, &claim);

    // Attestation is honored while the oracle remains registered.
    assert!(client.verify_claim(&proof, &claim));

    // Revoking the oracle does not delete the stored attestation record, but
    // verify_claim must stop honoring it since the attesting oracle is no
    // longer currently registered.
    client.revoke_oracle(&oracle);
    assert!(!client.is_oracle(&oracle));
    assert!(!client.verify_claim(&proof, &claim));
}

#[test]
#[should_panic(expected = "Error(Contract, #7)")]
fn test_unregistered_oracle_cannot_attest() {
    let (env, _, client) = setup();
    let rogue = Address::generate(&env);

    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    client.attest(&rogue, &proof, &claim);
}

#[test]
fn test_register_and_is_oracle() {
    let (env, _, client) = setup();
    let oracle = Address::generate(&env);

    assert!(!client.is_oracle(&oracle));
    client.register_oracle(&oracle);
    assert!(client.is_oracle(&oracle));
    client.revoke_oracle(&oracle);
    assert!(!client.is_oracle(&oracle));
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn test_double_initialize_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register_contract(None, ZkVerifierContract);
    let client = ZkVerifierContractClient::new(&env, &id);
    client.initialize(&admin);
    client.initialize(&admin);
}

// ── #817: Input size limit tests ──────────────────────────────────────────────

/// Proof at exactly MAX_PROOF_SIZE — must pass validation (no panic) and,
/// once attested by a registered oracle, must verify as true.
#[test]
fn test_proof_at_max_size_succeeds() {
    let (env, _, client) = setup();
    let oracle = Address::generate(&env);
    client.register_oracle(&oracle);

    let data = [0xffu8; MAX_PROOF_SIZE as usize];
    let proof = Bytes::from_slice(&env, &data);
    let claim = bytes!(&env, 0xcafebabe);

    // Unattested: passes validation, but returns false.
    assert!(!client.verify_claim(&proof, &claim));

    client.attest(&oracle, &proof, &claim);
    assert!(client.verify_claim(&proof, &claim));
}

/// Proof one byte over MAX_PROOF_SIZE — must panic with ProofTooLarge (#3).
#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_proof_exceeds_max_size_panics() {
    let (env, _, client) = setup();
    let data = [0xffu8; MAX_PROOF_SIZE as usize + 1];
    let proof = Bytes::from_slice(&env, &data);
    let claim = bytes!(&env, 0xcafebabe);
    client.verify_claim(&proof, &claim);
}

/// Claim at exactly MAX_CLAIM_SIZE — must pass validation (no panic) and,
/// once attested by a registered oracle, must verify as true.
#[test]
fn test_claim_at_max_size_succeeds() {
    let (env, _, client) = setup();
    let oracle = Address::generate(&env);
    client.register_oracle(&oracle);

    let proof = bytes!(&env, 0xdeadbeef);
    let data = [0xaau8; MAX_CLAIM_SIZE as usize];
    let claim = Bytes::from_slice(&env, &data);

    // Unattested: passes validation, but returns false.
    assert!(!client.verify_claim(&proof, &claim));

    client.attest(&oracle, &proof, &claim);
    assert!(client.verify_claim(&proof, &claim));
}

/// Claim one byte over MAX_CLAIM_SIZE — must panic with ClaimTooLarge (#4).
#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn test_claim_exceeds_max_size_panics() {
    let (env, _, client) = setup();
    let proof = bytes!(&env, 0xdeadbeef);
    let data = [0xaau8; MAX_CLAIM_SIZE as usize + 1];
    let claim = Bytes::from_slice(&env, &data);
    client.verify_claim(&proof, &claim);
}

// ── #818: Event emission tests ────────────────────────────────────────────────

/// verify_claim with an attested proof must emit exactly one vfy_claim event.
#[test]
fn test_verify_claim_emits_event_on_true_result() {
    let (env, _, client) = setup();
    let oracle = Address::generate(&env);
    client.register_oracle(&oracle);

    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    client.attest(&oracle, &proof, &claim);

    // attest() does not itself publish any events, so verify_claim() is the
    // only event source here.
    let result = client.verify_claim(&proof, &claim);
    assert!(result);
    assert_eq!(env.events().all().len(), 1);
}

/// verify_claim with an unattested proof must emit exactly one vfy_claim
/// event even when the result is false.
#[test]
fn test_verify_claim_emits_event_on_false_result() {
    let (env, _, client) = setup();
    let proof = bytes!(&env, 0xdeadbeef); // never attested → result = false
    let claim = bytes!(&env, 0xcafebabe);
    let result = client.verify_claim(&proof, &claim);
    assert!(!result);
    assert_eq!(env.events().all().len(), 1);
}

// ── Credential dispute tests ──────────────────────────────────────────────────

/// Registers `n` fresh oracles and returns them.
fn register_oracles(env: &Env, client: &ZkVerifierContractClient<'static>, n: u32) -> Vec<Address> {
    let mut oracles = Vec::new(env);
    for _ in 0..n {
        let oracle = Address::generate(env);
        client.register_oracle(&oracle);
        oracles.push_back(oracle);
    }
    oracles
}

/// attest() returns a stable credential_id, starting at 1.
#[test]
fn test_attest_returns_credential_id() {
    let (env, _, client) = setup();
    let oracle = Address::generate(&env);
    client.register_oracle(&oracle);

    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    let credential_id = client.attest(&oracle, &proof, &claim);
    assert_eq!(credential_id, 1);

    // Re-attesting the same (proof, claim) reuses the same credential id.
    let credential_id_again = client.attest(&oracle, &proof, &claim);
    assert_eq!(credential_id_again, 1);

    // A distinct (proof, claim) pair gets a new id.
    let other_claim = bytes!(&env, 0x1234);
    let other_id = client.attest(&oracle, &proof, &other_claim);
    assert_eq!(other_id, 2);
}

/// Disputing a credential id that was never attested must panic.
#[test]
#[should_panic(expected = "Error(Contract, #8)")]
fn test_dispute_unknown_credential_panics() {
    let (env, _, client) = setup();
    let initiator = Address::generate(&env);
    let reason = bytes!(&env, 0xaa);
    client.initiate_credential_dispute(&999u64, &initiator, &reason);
}

/// An empty dispute reason must panic.
#[test]
#[should_panic(expected = "Error(Contract, #13)")]
fn test_dispute_empty_reason_panics() {
    let (env, _, client) = setup();
    let oracle = Address::generate(&env);
    client.register_oracle(&oracle);
    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    let credential_id = client.attest(&oracle, &proof, &claim);

    let initiator = Address::generate(&env);
    let reason = bytes!(&env,);
    client.initiate_credential_dispute(&credential_id, &initiator, &reason);
}

/// Filing a second dispute while one is still open must panic.
#[test]
#[should_panic(expected = "Error(Contract, #12)")]
fn test_duplicate_open_dispute_panics() {
    let (env, _, client) = setup();
    let oracle = Address::generate(&env);
    client.register_oracle(&oracle);
    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    let credential_id = client.attest(&oracle, &proof, &claim);

    let initiator = Address::generate(&env);
    let reason = bytes!(&env, 0xaa);
    client.initiate_credential_dispute(&credential_id, &initiator, &reason);
    client.initiate_credential_dispute(&credential_id, &initiator, &reason);
}

/// A non-oracle address must not be able to vote.
#[test]
#[should_panic(expected = "Error(Contract, #7)")]
fn test_non_oracle_cannot_vote() {
    let (env, _, client) = setup();
    let oracle = Address::generate(&env);
    client.register_oracle(&oracle);
    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    let credential_id = client.attest(&oracle, &proof, &claim);

    let initiator = Address::generate(&env);
    let reason = bytes!(&env, 0xaa);
    let dispute_id = client.initiate_credential_dispute(&credential_id, &initiator, &reason);

    let rogue = Address::generate(&env);
    client.vote_on_dispute(&dispute_id, &rogue, &true);
}

/// The same oracle voting twice on one dispute must panic.
#[test]
#[should_panic(expected = "Error(Contract, #11)")]
fn test_double_vote_panics() {
    let (env, _, client) = setup();
    let oracle = Address::generate(&env);
    client.register_oracle(&oracle);
    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    let credential_id = client.attest(&oracle, &proof, &claim);

    let initiator = Address::generate(&env);
    let reason = bytes!(&env, 0xaa);
    let dispute_id = client.initiate_credential_dispute(&credential_id, &initiator, &reason);

    client.vote_on_dispute(&dispute_id, &oracle, &true);
    client.vote_on_dispute(&dispute_id, &oracle, &false);
}

/// Voting on an already-resolved dispute must panic.
#[test]
#[should_panic(expected = "Error(Contract, #10)")]
fn test_vote_after_resolution_panics() {
    let (env, _, client) = setup();
    let oracles = register_oracles(&env, &client, 3);
    let attester = oracles.get(0).unwrap();
    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    let credential_id = client.attest(&attester, &proof, &claim);

    let initiator = Address::generate(&env);
    let reason = bytes!(&env, 0xaa);
    let dispute_id = client.initiate_credential_dispute(&credential_id, &initiator, &reason);

    for oracle in oracles.iter() {
        client.vote_on_dispute(&dispute_id, &oracle, &true);
    }
    assert_eq!(client.get_dispute(&dispute_id).status, DisputeStatus::Upheld);

    // A fourth registered oracle tries to vote after resolution.
    let late_oracle = Address::generate(&env);
    client.register_oracle(&late_oracle);
    client.vote_on_dispute(&dispute_id, &late_oracle, &true);
}

/// Reaching the "invalid" vote threshold upholds the dispute, invalidates
/// the credential, and verify_claim must flip to false even though the
/// original attesting oracle is still registered.
#[test]
fn test_dispute_upheld_invalidates_credential() {
    let (env, _, client) = setup();
    let oracles = register_oracles(&env, &client, 3);
    let attester = oracles.get(0).unwrap();
    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    let credential_id = client.attest(&attester, &proof, &claim);
    assert!(client.verify_claim(&proof, &claim));

    let initiator = Address::generate(&env);
    let reason = bytes!(&env, 0xaa);
    let dispute_id = client.initiate_credential_dispute(&credential_id, &initiator, &reason);

    for oracle in oracles.iter() {
        client.vote_on_dispute(&dispute_id, &oracle, &true);
    }

    let dispute = client.get_dispute(&dispute_id);
    assert_eq!(dispute.status, DisputeStatus::Upheld);
    assert_eq!(dispute.votes_for, 3);
    assert!(client.is_credential_invalidated(&credential_id));
    // The attester was never revoked, but the dispute still invalidates it.
    assert!(client.is_oracle(&attester));
    assert!(!client.verify_claim(&proof, &claim));
}

/// Reaching the "valid" vote threshold rejects the dispute and leaves the
/// credential honored by verify_claim.
#[test]
fn test_dispute_rejected_credential_stays_valid() {
    let (env, _, client) = setup();
    let oracles = register_oracles(&env, &client, 3);
    let attester = oracles.get(0).unwrap();
    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    let credential_id = client.attest(&attester, &proof, &claim);

    let initiator = Address::generate(&env);
    let reason = bytes!(&env, 0xaa);
    let dispute_id = client.initiate_credential_dispute(&credential_id, &initiator, &reason);

    for oracle in oracles.iter() {
        client.vote_on_dispute(&dispute_id, &oracle, &false);
    }

    let dispute = client.get_dispute(&dispute_id);
    assert_eq!(dispute.status, DisputeStatus::Rejected);
    assert!(!client.is_credential_invalidated(&credential_id));
    assert!(client.verify_claim(&proof, &claim));
}

/// A resolved dispute clears the "open dispute" lock, and dispute history
/// for the credential accumulates every filed dispute.
#[test]
fn test_credential_dispute_history_tracks_all_disputes() {
    let (env, _, client) = setup();
    let oracles = register_oracles(&env, &client, 3);
    let attester = oracles.get(0).unwrap();
    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    let credential_id = client.attest(&attester, &proof, &claim);

    let initiator = Address::generate(&env);
    let reason = bytes!(&env, 0xaa);

    let first = client.initiate_credential_dispute(&credential_id, &initiator, &reason);
    for oracle in oracles.iter() {
        client.vote_on_dispute(&first, &oracle, &false);
    }

    let second = client.initiate_credential_dispute(&credential_id, &initiator, &reason);

    let history = client.get_credential_disputes(&credential_id);
    assert_eq!(history.len(), 2);
    assert_eq!(history.get(0).unwrap(), first);
    assert_eq!(history.get(1).unwrap(), second);
}

/// Admin can lower the dispute threshold so fewer votes are needed to
/// resolve; a non-default threshold of 1 resolves on the first vote.
#[test]
fn test_admin_configurable_dispute_threshold() {
    let (env, _admin, client) = setup();
    client.set_dispute_threshold(&1u32);
    assert_eq!(client.dispute_threshold(), 1u32);

    let oracle = Address::generate(&env);
    client.register_oracle(&oracle);
    let proof = bytes!(&env, 0xdeadbeef);
    let claim = bytes!(&env, 0xcafebabe);
    let credential_id = client.attest(&oracle, &proof, &claim);

    let initiator = Address::generate(&env);
    let reason = bytes!(&env, 0xaa);
    let dispute_id = client.initiate_credential_dispute(&credential_id, &initiator, &reason);

    client.vote_on_dispute(&dispute_id, &oracle, &true);
    assert_eq!(client.get_dispute(&dispute_id).status, DisputeStatus::Upheld);
}

/// A zero threshold is rejected.
#[test]
#[should_panic(expected = "Error(Contract, #15)")]
fn test_zero_threshold_rejected() {
    let (_, _, client) = setup();
    client.set_dispute_threshold(&0u32);
}
