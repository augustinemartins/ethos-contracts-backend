# Slice Performance-Based Weighting & Composition Validation Rules Engine

This document covers two related features added to the `ttl-vault` Soroban contract:

- **Issue #36** — Attestor performance tracking and dynamic slice weight calculation
- **Issue #44** — Configurable rules engine for slice composition validation

---

## Issue #36 — Slice Performance-Based Weighting

### Motivation

Previously, attestor weights within a vault slice were static.  Dynamic weighting
based on measured performance (response latency and success rate) lets the system
favour reliable, fast attestors and deprioritise under-performing ones automatically.

### Data Model

Each `(slice_id, attestor)` pair accumulates a `PerformanceMetrics` record stored
in persistent contract storage:

```
PerformanceMetrics {
    total_responses:       u64,   // observations recorded
    successful_responses:  u64,   // of which were successes
    total_response_time_ms: u64,  // cumulative latency in ms
    last_recorded_at:      u64,   // ledger timestamp of latest observation
}
```

Optimal weights are stored as `Vec<AttestorWeight>` keyed by `slice_id`:

```
AttestorWeight {
    attestor:   Address,
    weight_bps: u32,   // basis points — all attestors in a slice sum to 10 000
}
```

### Weighting Algorithm

For each attestor *i* with at least one observation:

```
success_rate_i   = successful_responses_i / total_responses_i
avg_latency_i    = total_response_time_ms_i / total_responses_i   (floor 1 ms)
score_i          = success_rate_i × (1 / avg_latency_i)
weight_bps_i     = round( score_i / Σ score_j × 10 000 )
```

- All arithmetic is integer-only (no floating point) using a 1 000 000× scaling
  factor to preserve precision.
- Rounding remainder is absorbed by the last attestor so the BPS total is
  always exactly 10 000.
- If no performance data exists for any attestor, equal weights are assigned
  (10 000 / N per attestor, remainder to the first).

### Contract API

| Function | Auth | Description |
|---|---|---|
| `record_attestor_performance(vault_id, caller, slice_id, attestor, success, response_time_ms)` | owner | Record one observation |
| `get_attestor_performance(slice_id, attestor)` | — | Read metrics (returns `Option<PerformanceMetrics>`) |
| `calculate_optimal_weights(slice_id, attestors)` | — | Compute weights without persisting |
| `reweight_slice(vault_id, caller, slice_id, attestors)` | owner | Compute + persist weights |
| `get_slice_weights(slice_id)` | — | Read latest persisted weights |

### Events

| Topic | Payload | When |
|---|---|---|
| `atst_rec` | `AttestorPerfRecordedEvent` | After each `record_attestor_performance` call |
| `sl_rewt` | `SliceReweightedEvent` | After `reweight_slice` persists new weights |

### Example

```rust
// Record 3 observations for attestor_a on slice 1
contract.record_attestor_performance(vault_id, owner, 1, attestor_a, true, 20);
contract.record_attestor_performance(vault_id, owner, 1, attestor_a, true, 25);
contract.record_attestor_performance(vault_id, owner, 1, attestor_a, false, 200);

// Record 1 low-quality observation for attestor_b
contract.record_attestor_performance(vault_id, owner, 1, attestor_b, true, 500);

// Compute and persist optimal weights
let weights = contract.reweight_slice(vault_id, owner, 1, vec![attestor_a, attestor_b]);
// attestor_a will receive a significantly higher BPS than attestor_b
```

---

## Issue #44 — Slice Composition Validation Rules Engine

### Motivation

Composition validation was previously hard-coded.  A rules engine allows
operators to define, prioritise, and dynamically reconfigure validation policies
without redeploying the contract.

### Architecture

Rules are stored on-chain as `CompositionRule` records containing:

```
CompositionRule {
    rule_id:    u64,     // auto-assigned, monotonically increasing
    rule_bytes: Bytes,   // opaque policy payload
    priority:   u32,     // 0 == highest priority
    tag:        u32,     // numeric category label
    enabled:    bool,
    updated_at: u64,     // ledger timestamp
}
```

Each `slice_id` has an associated ordered list of `rule_id`s (`Vec<u64>`) stored
separately, so one rule can be referenced by multiple slices.

### On-Chain Validation Predicate

Rules are evaluated deterministically using a **prefix-match** predicate:

> A rule **passes** when `slice_data` starts with `rule_bytes`, or when
> `rule_bytes` is empty (unconditional pass).

This keeps evaluation entirely on-chain without an interpreter.  Richer
validation logic (JSON schema, regex, semantic checks) is expected to be
performed **off-chain** by indexers that read `rule_bytes` from the chain and
subscribe to `SliceValidated` events.

### Conflict Detection

Two rules **conflict** when they share the same `priority` and produce opposite
outcomes for the same `slice_data`.  Conflicts are surfaced in
`ValidationResult::conflicts` (pairs of `rule_id`s) and set `overall_valid =
false`.

### Contract API

| Function | Auth | Description |
|---|---|---|
| `register_composition_rule(caller, rule_bytes, priority, tag)` | admin | Register a new rule; returns `rule_id` |
| `set_rule_enabled(caller, rule_id, enabled)` | admin | Enable or disable a rule |
| `set_slice_rules(vault_id, caller, slice_id, rule_ids)` | owner | Associate rules with a slice |
| `get_slice_rule_ids(slice_id)` | — | List rule IDs for a slice |
| `get_composition_rule(rule_id)` | — | Retrieve a rule by ID |
| `validate_slice_with_rules(slice_id, slice_data)` | — | Run validation; returns `ValidationResult` |

### `ValidationResult` Structure

```
ValidationResult {
    slice_id:      u64,
    overall_valid: bool,              // true iff all enabled rules passed with no conflicts
    outcomes:      Vec<RuleOutcome>,  // per-rule pass/fail in priority order
    conflicts:     Vec<u64>,          // pairs of conflicting rule IDs (groups of 2)
    validated_at:  u64,               // ledger timestamp
}

RuleOutcome {
    rule_id:  u64,
    priority: u32,
    passed:   bool,
}
```

### Events

| Topic | Payload | When |
|---|---|---|
| `rl_reg` | `RuleRegisteredEvent` | After `register_composition_rule` |
| `rl_upd` | `RuleUpdatedEvent` | After `set_rule_enabled` |
| `sl_val` | `SliceValidatedEvent` | After `validate_slice_with_rules` |

### Rule Priority & Conflict Example

```rust
// Register two rules at the same priority that produce opposite results
let r_pass = contract.register_composition_rule(admin, b"ok", 5, 0);   // passes for "ok_data"
let r_fail = contract.register_composition_rule(admin, b"bad", 5, 0);  // fails for "ok_data"

contract.set_slice_rules(vault_id, owner, slice_id, vec![r_pass, r_fail]);

let result = contract.validate_slice_with_rules(slice_id, b"ok_data");
// result.overall_valid == false  (conflict detected)
// result.conflicts == [r_pass, r_fail]
```

### Disabling a Rule

```rust
// Disable a rule without deleting it
contract.set_rule_enabled(admin, rule_id, false);
// Subsequent validate_slice_with_rules calls skip disabled rules entirely
```

---

## Storage Keys

Both features add new entries to persistent contract storage (not to instance
storage, so they participate in Soroban state archival and have their TTL
extended on every write).

| Key | Type | Description |
|---|---|---|
| `SlicePerfKey::AttestorPerf(slice_id, attestor)` | `PerformanceMetrics` | Attestor observation data |
| `SlicePerfKey::SliceWeights(slice_id)` | `Vec<AttestorWeight>` | Latest computed weights |
| `RulesEngineKey::Rule(rule_id)` | `CompositionRule` | Rule record |
| `RulesEngineKey::RuleCount` | `u64` | Next rule ID counter |
| `RulesEngineKey::SliceRules(slice_id)` | `Vec<u64>` | Rule IDs for a slice |

## Error Codes

| Code | Variant | Description |
|---|---|---|
| 114 | `RuleNotFound` | `set_rule_enabled` called with unknown `rule_id` |
