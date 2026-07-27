//! Feature flag storage and evaluation (trunk-based development support).
//!
//! Features are built directly on `main` behind flags instead of long-lived
//! branches. This module provides:
//!
//! - Flag storage (in-memory, versioned on every mutation)
//! - Flag evaluation (global on/off + percentage-based gradual rollout)
//! - `POST /admin/flags` to create/update a flag
//! - `GET /admin/flags` to list all flags
//! - `GET /admin/flags/:key` to fetch a single flag
//! - `POST /admin/flags/:key/evaluate` to evaluate a flag for a given subject
//!
//! # Gradual rollout
//!
//! Each flag has a `rollout_percentage` (0-100). Evaluation hashes the
//! `(flag_key, subject_id)` pair into a stable bucket in `[0, 100)` so the
//! same subject always gets the same result for a given rollout percentage,
//! and increasing the percentage only ever adds subjects (never removes
//! ones that were previously enabled).
//!
//! # Versioning
//!
//! Every update to a flag increments its `version` and appends the previous
//! state to `history`, so changes can be audited or rolled back.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single historical snapshot of a flag, recorded before an update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagVersionSnapshot {
    pub version: u32,
    pub enabled: bool,
    pub rollout_percentage: u8,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<String>,
}

/// A feature flag definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlag {
    pub key: String,
    pub description: Option<String>,
    pub enabled: bool,
    /// Percentage (0-100) of subjects that should see the flag as enabled
    /// when `enabled` is true. 100 means fully rolled out.
    pub rollout_percentage: u8,
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub history: Vec<FlagVersionSnapshot>,
}

/// Request body for `POST /admin/flags`.
#[derive(Debug, Deserialize)]
pub struct UpsertFlagRequest {
    pub key: String,
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_rollout")]
    pub rollout_percentage: u8,
    pub updated_by: Option<String>,
}

fn default_rollout() -> u8 {
    100
}

/// Request body for `POST /admin/flags/:key/evaluate`.
#[derive(Debug, Deserialize)]
pub struct EvaluateFlagRequest {
    pub subject_id: String,
}

/// Result of evaluating a flag for a subject.
#[derive(Debug, Serialize)]
pub struct FlagEvaluation {
    pub key: String,
    pub subject_id: String,
    pub enabled: bool,
    pub reason: String,
    pub flag_version: u32,
}

pub type FlagStore = Arc<Mutex<HashMap<String, FeatureFlag>>>;

pub fn create_flag_store() -> FlagStore {
    Arc::new(Mutex::new(HashMap::new()))
}

#[derive(Clone)]
pub struct FlagState {
    pub store: FlagStore,
}

impl FlagState {
    pub fn new() -> Self {
        Self {
            store: create_flag_store(),
        }
    }
}

impl Default for FlagState {
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministically hash `(key, subject_id)` into a bucket in `[0, 100)`.
///
/// Uses a simple FNV-1a style hash so evaluation has no external
/// dependencies and is stable across process restarts.
fn bucket_for(key: &str, subject_id: &str) -> u8 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in key.as_bytes().iter().chain(b":").chain(subject_id.as_bytes()) {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash % 100) as u8
}

/// Evaluate whether `flag` is enabled for `subject_id`.
pub fn evaluate_flag(flag: &FeatureFlag, subject_id: &str) -> FlagEvaluation {
    let enabled = if !flag.enabled {
        false
    } else if flag.rollout_percentage >= 100 {
        true
    } else if flag.rollout_percentage == 0 {
        false
    } else {
        bucket_for(&flag.key, subject_id) < flag.rollout_percentage
    };

    let reason = if !flag.enabled {
        "flag disabled".to_string()
    } else if flag.rollout_percentage >= 100 {
        "fully rolled out".to_string()
    } else {
        format!("gradual rollout at {}%", flag.rollout_percentage)
    };

    FlagEvaluation {
        key: flag.key.clone(),
        subject_id: subject_id.to_string(),
        enabled,
        reason,
        flag_version: flag.version,
    }
}

/// `POST /admin/flags` — create or update a feature flag.
pub async fn upsert_flag(
    State(state): State<Arc<FlagState>>,
    Json(body): Json<UpsertFlagRequest>,
) -> Result<(StatusCode, Json<FeatureFlag>), (StatusCode, Json<serde_json::Value>)> {
    if body.key.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "key must not be empty" })),
        ));
    }
    if body.rollout_percentage > 100 {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "rollout_percentage must be 0-100" })),
        ));
    }

    let mut store = state.store.lock().unwrap();
    let now = Utc::now();

    let flag = match store.get_mut(&body.key) {
        Some(existing) => {
            existing.history.push(FlagVersionSnapshot {
                version: existing.version,
                enabled: existing.enabled,
                rollout_percentage: existing.rollout_percentage,
                updated_at: existing.updated_at,
                updated_by: body.updated_by.clone(),
            });
            existing.description = body.description.or_else(|| existing.description.clone());
            existing.enabled = body.enabled;
            existing.rollout_percentage = body.rollout_percentage;
            existing.version += 1;
            existing.updated_at = now;
            existing.clone()
        }
        None => {
            let flag = FeatureFlag {
                key: body.key.clone(),
                description: body.description,
                enabled: body.enabled,
                rollout_percentage: body.rollout_percentage,
                version: 1,
                created_at: now,
                updated_at: now,
                history: Vec::new(),
            };
            store.insert(body.key.clone(), flag.clone());
            flag
        }
    };

    Ok((StatusCode::OK, Json(flag)))
}

/// `GET /admin/flags` — list all flags.
pub async fn list_flags(State(state): State<Arc<FlagState>>) -> Json<Vec<FeatureFlag>> {
    let store = state.store.lock().unwrap();
    Json(store.values().cloned().collect())
}

/// `GET /admin/flags/:key` — fetch a single flag.
pub async fn get_flag(
    State(state): State<Arc<FlagState>>,
    Path(key): Path<String>,
) -> Result<Json<FeatureFlag>, StatusCode> {
    let store = state.store.lock().unwrap();
    store
        .get(&key)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

/// `POST /admin/flags/:key/evaluate` — evaluate a flag for a subject.
pub async fn evaluate_flag_handler(
    State(state): State<Arc<FlagState>>,
    Path(key): Path<String>,
    Json(body): Json<EvaluateFlagRequest>,
) -> Result<Json<FlagEvaluation>, StatusCode> {
    let store = state.store.lock().unwrap();
    let flag = store.get(&key).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(evaluate_flag(flag, &body.subject_id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_flag(rollout: u8) -> FeatureFlag {
        FeatureFlag {
            key: "new-checkout".to_string(),
            description: None,
            enabled: true,
            rollout_percentage: rollout,
            version: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            history: Vec::new(),
        }
    }

    #[test]
    fn disabled_flag_never_enabled() {
        let mut flag = sample_flag(100);
        flag.enabled = false;
        let eval = evaluate_flag(&flag, "user-1");
        assert!(!eval.enabled);
    }

    #[test]
    fn full_rollout_always_enabled() {
        let flag = sample_flag(100);
        for i in 0..50 {
            let eval = evaluate_flag(&flag, &format!("user-{i}"));
            assert!(eval.enabled);
        }
    }

    #[test]
    fn zero_rollout_never_enabled() {
        let flag = sample_flag(0);
        let eval = evaluate_flag(&flag, "user-1");
        assert!(!eval.enabled);
    }

    #[test]
    fn evaluation_is_deterministic() {
        let flag = sample_flag(50);
        let first = evaluate_flag(&flag, "user-42");
        let second = evaluate_flag(&flag, "user-42");
        assert_eq!(first.enabled, second.enabled);
    }
}
