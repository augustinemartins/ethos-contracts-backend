#![cfg(test)]

extern crate alloc;

use super::*;
use soroban_sdk::{testutils::Address as _, token::StellarAssetClient, vec, Address, Env};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn setup() -> (
    Env,
    Address, // owner
    Address, // admin
    TtlVaultContractClient<'static>,
    u64, // vault_id
) {
    let env = Env::default();
    env.mock_all_auths();

    let owner = Address::generate(&env);
    let beneficiary = Address::generate(&env);
    let admin = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let token_address = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    StellarAssetClient::new(&env, &token_address).mint(&owner, &10_000_000);

    let contract_address = env.register_contract(None, TtlVaultContract);
    let client = TtlVaultContractClient::new(&env, &contract_address);
    client.initialize(&token_address, &admin);

    let vault_id = client.create_vault(&owner, &beneficiary, &1_000u64, &None);

    let client: TtlVaultContractClient<'static> = unsafe { core::mem::transmute(client) };
    (env, owner, admin, client, vault_id)
}

// ── record_attestor_performance ───────────────────────────────────────────────

#[test]
fn test_record_performance_creates_entry() {
    let (env, owner, _admin, client, vault_id) = setup();
    let attestor = Address::generate(&env);
    let slice_id = 1u64;

    // No data initially.
    assert!(client
        .get_attestor_performance(&slice_id, &attestor)
        .is_none());

    // Record a successful response (Soroban client panics on Err, returns () on Ok).
    client.record_attestor_performance(&vault_id, &owner, &slice_id, &attestor, &true, &50u64);

    let m = client
        .get_attestor_performance(&slice_id, &attestor)
        .unwrap();
    assert_eq!(m.total_responses, 1);
    assert_eq!(m.successful_responses, 1);
    assert_eq!(m.total_response_time_ms, 50);
}

#[test]
fn test_record_performance_accumulates() {
    let (env, owner, _admin, client, vault_id) = setup();
    let attestor = Address::generate(&env);
    let slice_id = 2u64;

    client.record_attestor_performance(&vault_id, &owner, &slice_id, &attestor, &true, &100u64);
    client.record_attestor_performance(&vault_id, &owner, &slice_id, &attestor, &false, &200u64);
    client.record_attestor_performance(&vault_id, &owner, &slice_id, &attestor, &true, &150u64);

    let m = client
        .get_attestor_performance(&slice_id, &attestor)
        .unwrap();
    assert_eq!(m.total_responses, 3);
    assert_eq!(m.successful_responses, 2);
    assert_eq!(m.total_response_time_ms, 450);
}

#[test]
fn test_record_performance_rejects_non_owner() {
    let (env, _owner, _admin, client, vault_id) = setup();
    let intruder = Address::generate(&env);
    let attestor = Address::generate(&env);

    let result = client
        .try_record_attestor_performance(&vault_id, &intruder, &1u64, &attestor, &true, &10u64);
    assert!(result.is_err());
}

// ── calculate_optimal_weights ─────────────────────────────────────────────────

#[test]
fn test_weights_equal_when_no_data() {
    let (env, _owner, _admin, client, _vault_id) = setup();
    let slice_id = 10u64;
    let a1 = Address::generate(&env);
    let a2 = Address::generate(&env);
    let a3 = Address::generate(&env);
    let attestors = vec![&env, a1.clone(), a2.clone(), a3.clone()];

    let weights = client.calculate_optimal_weights(&slice_id, &attestors);
    assert_eq!(weights.len(), 3);
    // Without data the total BPS must sum to 10 000.
    let total: u32 = weights.iter().map(|w| w.weight_bps).sum();
    assert_eq!(total, 10_000);
}

#[test]
fn test_weights_reflect_performance() {
    let (env, owner, _admin, client, vault_id) = setup();
    let slice_id = 20u64;
    let a1 = Address::generate(&env);
    let a2 = Address::generate(&env);

    // a1: 10/10 successes, 10 ms avg → high score
    for _ in 0..10 {
        client.record_attestor_performance(&vault_id, &owner, &slice_id, &a1, &true, &10u64);
    }
    // a2: 1/10 successes, 100 ms avg → low score
    client.record_attestor_performance(&vault_id, &owner, &slice_id, &a2, &true, &100u64);
    for _ in 0..9 {
        client.record_attestor_performance(&vault_id, &owner, &slice_id, &a2, &false, &100u64);
    }

    let attestors = vec![&env, a1.clone(), a2.clone()];
    let weights = client.calculate_optimal_weights(&slice_id, &attestors);
    assert_eq!(weights.len(), 2);

    let total: u32 = weights.iter().map(|w| w.weight_bps).sum();
    assert_eq!(total, 10_000);

    // a1 should have a significantly higher weight than a2.
    let w1 = weights.get(0).unwrap().weight_bps;
    let w2 = weights.get(1).unwrap().weight_bps;
    assert!(w1 > w2, "a1 weight ({w1}) should exceed a2 weight ({w2})");
}

#[test]
fn test_weights_single_attestor_gets_full_bps() {
    let (env, owner, _admin, client, vault_id) = setup();
    let slice_id = 30u64;
    let a1 = Address::generate(&env);

    client.record_attestor_performance(&vault_id, &owner, &slice_id, &a1, &true, &20u64);

    let attestors = vec![&env, a1.clone()];
    let weights = client.calculate_optimal_weights(&slice_id, &attestors);
    assert_eq!(weights.len(), 1);
    assert_eq!(weights.get(0).unwrap().weight_bps, 10_000);
}

// ── reweight_slice ────────────────────────────────────────────────────────────

#[test]
fn test_reweight_slice_persists_and_retrieves() {
    let (env, owner, _admin, client, vault_id) = setup();
    let slice_id = 40u64;
    let a1 = Address::generate(&env);
    let a2 = Address::generate(&env);

    client.record_attestor_performance(&vault_id, &owner, &slice_id, &a1, &true, &10u64);
    client.record_attestor_performance(&vault_id, &owner, &slice_id, &a2, &true, &100u64);

    let attestors = vec![&env, a1.clone(), a2.clone()];
    // reweight_slice returns Vec<AttestorWeight> directly (Soroban strips Result wrapper).
    let computed = client.reweight_slice(&vault_id, &owner, &slice_id, &attestors);

    let persisted = client.get_slice_weights(&slice_id).unwrap();
    assert_eq!(computed.len(), persisted.len());
    let total: u32 = persisted.iter().map(|w| w.weight_bps).sum();
    assert_eq!(total, 10_000);
}

#[test]
fn test_reweight_slice_rejects_non_owner() {
    let (env, _owner, _admin, client, vault_id) = setup();
    let intruder = Address::generate(&env);
    let a1 = Address::generate(&env);
    let attestors = vec![&env, a1];

    let result = client.try_reweight_slice(&vault_id, &intruder, &1u64, &attestors);
    assert!(result.is_err());
}
