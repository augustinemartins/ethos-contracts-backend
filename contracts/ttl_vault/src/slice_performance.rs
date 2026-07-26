/// Issue #36 — Slice Performance-Based Weighting
///
/// Tracks per-attestor performance metrics (response time, success rate) for
/// vault slices and uses them to compute optimal BPS weights.  Weights are
/// stored persistently and can be reapplied via `reweight_slice`.
///
/// # Algorithm
/// Each attestor accumulates:
/// - `total_responses` — number of recorded observations
/// - `successful_responses` — how many returned success
/// - `total_response_time_ms` — cumulative response latency in milliseconds
///
/// The optimal weight for attestor *i* is calculated as:
///
/// ```text
/// score_i  = success_rate_i × (1 / avg_latency_i)
/// weight_i = (score_i / sum_of_all_scores) × 10_000   [BPS]
/// ```
///
/// If an attestor has zero responses the score defaults to zero and the BPS
/// weight is set to 0.  If **all** attestors have zero score (e.g. no data
/// yet) each attestor is assigned an equal share so that BPS always sums to
/// 10 000.  Any rounding remainder is absorbed by the first attestor.
use soroban_sdk::{contracttype, symbol_short, Address, Env, Vec};

// ── Event topics ─────────────────────────────────────────────────────────────

pub const ATTESTOR_PERF_RECORDED_TOPIC: soroban_sdk::Symbol = symbol_short!("atst_rec");
pub const SLICE_REWEIGHTED_TOPIC: soroban_sdk::Symbol = symbol_short!("sl_rewt");

// ── Storage key ──────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum SlicePerfKey {
    /// Performance record for a single attestor on a given slice.
    AttestorPerf(u64, Address),
    /// Latest computed BPS weights for a slice.
    SliceWeights(u64),
}

// ── Types ─────────────────────────────────────────────────────────────────────

/// Accumulated performance data for one attestor on one slice.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct PerformanceMetrics {
    /// Total number of observed responses (success + failure).
    pub total_responses: u64,
    /// Number of responses counted as successful.
    pub successful_responses: u64,
    /// Cumulative response latency in milliseconds.
    pub total_response_time_ms: u64,
    /// Ledger timestamp of the last recorded observation.
    pub last_recorded_at: u64,
}

/// BPS weight assigned to one attestor for a slice.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct AttestorWeight {
    pub attestor: Address,
    /// Basis-points allocation (sum across all attestors for a slice == 10 000).
    pub weight_bps: u32,
}

// ── Events ────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug)]
pub struct AttestorPerfRecordedEvent {
    pub slice_id: u64,
    pub attestor: Address,
    pub success: bool,
    pub response_time_ms: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct SliceReweightedEvent {
    pub slice_id: u64,
    /// Number of attestors that received updated weights.
    pub attestor_count: u32,
}

// ── Core functions ────────────────────────────────────────────────────────────

/// Record one performance observation for `attestor` on `slice_id`.
///
/// - `caller` must be the vault owner (auth enforced by the outer
///   `TtlVaultContract` wrapper before calling this helper).
/// - `success` — whether the attestor responded correctly.
/// - `response_time_ms` — round-trip latency in milliseconds.
pub fn record_attestor_performance(
    env: &Env,
    slice_id: u64,
    attestor: &Address,
    success: bool,
    response_time_ms: u64,
) {
    let key = SlicePerfKey::AttestorPerf(slice_id, attestor.clone());

    let mut metrics: PerformanceMetrics =
        env.storage()
            .persistent()
            .get(&key)
            .unwrap_or(PerformanceMetrics {
                total_responses: 0,
                successful_responses: 0,
                total_response_time_ms: 0,
                last_recorded_at: 0,
            });

    metrics.total_responses = metrics.total_responses.saturating_add(1);
    if success {
        metrics.successful_responses = metrics.successful_responses.saturating_add(1);
    }
    metrics.total_response_time_ms = metrics
        .total_response_time_ms
        .saturating_add(response_time_ms);
    metrics.last_recorded_at = env.ledger().timestamp();

    env.storage().persistent().set(&key, &metrics);
    env.storage().persistent().extend_ttl(
        &key,
        crate::VAULT_TTL_THRESHOLD,
        crate::VAULT_TTL_LEDGERS,
    );

    env.events().publish(
        (ATTESTOR_PERF_RECORDED_TOPIC, slice_id),
        AttestorPerfRecordedEvent {
            slice_id,
            attestor: attestor.clone(),
            success,
            response_time_ms,
        },
    );
}

/// Retrieve the current performance metrics for a single attestor on a slice.
/// Returns `None` if no data has been recorded yet.
pub fn get_attestor_performance(
    env: &Env,
    slice_id: u64,
    attestor: &Address,
) -> Option<PerformanceMetrics> {
    let key = SlicePerfKey::AttestorPerf(slice_id, attestor.clone());
    env.storage().persistent().get(&key)
}

/// Compute optimal BPS weights for all `attestors` on `slice_id` based on
/// their stored performance data.
///
/// Returns a `Vec<AttestorWeight>` in the same order as `attestors`.
pub fn calculate_optimal_weights(
    env: &Env,
    slice_id: u64,
    attestors: &Vec<Address>,
) -> Vec<AttestorWeight> {
    // ── 1. Gather raw scores (u64 fixed-point: score × 1 000 000) ────────────
    // score = success_rate × (1 000 000 / avg_latency_ms)
    // Both numerator components are scaled to avoid floating point.

    let mut scores: Vec<u64> = Vec::new(env);
    let mut score_sum: u64 = 0u64;

    for attestor in attestors.iter() {
        let key = SlicePerfKey::AttestorPerf(slice_id, attestor.clone());
        let score = if let Some(m) = env
            .storage()
            .persistent()
            .get::<SlicePerfKey, PerformanceMetrics>(&key)
        {
            // success_rate_scaled = (successful_responses * 1_000_000) / total_responses
            // avg_latency_ms — floor at 1 to avoid zero denominator
            // score = success_rate_scaled / avg_latency
            let success_rate_scaled = m
                .successful_responses
                .saturating_mul(1_000_000)
                .checked_div(m.total_responses)
                .unwrap_or(0);
            let avg_latency = m
                .total_response_time_ms
                .checked_div(m.total_responses)
                .unwrap_or(0)
                .max(1);
            success_rate_scaled.checked_div(avg_latency).unwrap_or(0)
        } else {
            0u64
        };

        scores.push_back(score);
        score_sum = score_sum.saturating_add(score);
    }

    // ── 2. Convert scores → BPS weights ──────────────────────────────────────
    let mut weights: Vec<AttestorWeight> = Vec::new(env);
    let count = attestors.len();

    if count == 0 {
        return weights;
    }

    if score_sum == 0 {
        // No performance data yet — distribute equally.
        let equal_bps = 10_000u32 / count;
        let remainder = 10_000u32 - equal_bps * count;
        for (idx, attestor) in attestors.iter().enumerate() {
            let w = if idx == 0 {
                equal_bps + remainder
            } else {
                equal_bps
            };
            weights.push_back(AttestorWeight {
                attestor,
                weight_bps: w,
            });
        }
    } else {
        let mut bps_assigned: u32 = 0u32;
        let last_idx = count - 1;
        for (idx, (attestor, score)) in attestors.iter().zip(scores.iter()).enumerate() {
            let bps = if idx as u32 == last_idx {
                // absorb rounding remainder in the last attestor
                10_000u32.saturating_sub(bps_assigned)
            } else {
                let raw = score
                    .saturating_mul(10_000)
                    .checked_div(score_sum)
                    .unwrap_or(0);
                raw.min(10_000u64) as u32
            };
            bps_assigned = bps_assigned.saturating_add(bps);
            weights.push_back(AttestorWeight {
                attestor,
                weight_bps: bps,
            });
        }
    }

    weights
}

/// Persist the optimal weights for `slice_id` and emit a `SliceReweightedEvent`.
///
/// Call this after `calculate_optimal_weights` to make the new weights durable.
pub fn reweight_slice(env: &Env, slice_id: u64, weights: Vec<AttestorWeight>) {
    let count = weights.len();
    let key = SlicePerfKey::SliceWeights(slice_id);
    env.storage().persistent().set(&key, &weights);
    env.storage().persistent().extend_ttl(
        &key,
        crate::VAULT_TTL_THRESHOLD,
        crate::VAULT_TTL_LEDGERS,
    );

    env.events().publish(
        (SLICE_REWEIGHTED_TOPIC, slice_id),
        SliceReweightedEvent {
            slice_id,
            attestor_count: count,
        },
    );
}

/// Retrieve the latest persisted BPS weights for `slice_id`.
pub fn get_slice_weights(env: &Env, slice_id: u64) -> Option<Vec<AttestorWeight>> {
    let key = SlicePerfKey::SliceWeights(slice_id);
    env.storage().persistent().get(&key)
}
