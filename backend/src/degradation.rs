//! Graceful degradation for missing or unhealthy features.
//!
//! Previously, a missing or failing feature (e.g. a downstream dependency
//! being unavailable) caused hard errors for the whole request. This module
//! lets capabilities be marked degraded or unavailable independently, so
//! clients can negotiate what's actually usable and fall back to reduced
//! functionality instead of failing outright.
//!
//! # Concepts
//!
//! - [`DegradationLevel`] — `Full`, `Degraded`, or `Unavailable` for a given
//!   named capability
//! - [`DegradationState`] — registry of capability -> status, defaulting to
//!   `Full` for anything not explicitly registered
//! - Capability negotiation — a client posts the capabilities it wants to
//!   use; the server reports which are fully available, degraded (usable
//!   with reduced functionality), or unavailable (client should use a
//!   fallback or skip that feature)
//!
//! # API
//!
//! - `POST /admin/capabilities` — set a capability's degradation level
//! - `GET /admin/capabilities` — list all registered capability statuses
//! - `POST /capabilities/negotiate` — negotiate a set of requested capabilities
//! - `GET /capabilities/:name/fallback` — fallback response for a capability

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// How usable a capability currently is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradationLevel {
    /// Fully functional.
    Full,
    /// Usable, but with reduced functionality (e.g. cached/stale data,
    /// slower path, or a subset of normal behavior).
    Degraded,
    /// Not usable at all right now; callers should use a fallback or skip it.
    Unavailable,
}

/// Current status of a named capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityStatus {
    pub name: String,
    pub level: DegradationLevel,
    pub reason: Option<String>,
    /// Whether a fallback endpoint/response exists for this capability.
    pub fallback_available: bool,
    pub updated_at: DateTime<Utc>,
}

/// Request body for `POST /admin/capabilities`.
#[derive(Debug, Deserialize)]
pub struct SetCapabilityRequest {
    pub name: String,
    pub level: DegradationLevel,
    pub reason: Option<String>,
    #[serde(default)]
    pub fallback_available: bool,
}

/// Request body for `POST /capabilities/negotiate`.
#[derive(Debug, Deserialize)]
pub struct NegotiateRequest {
    pub requested: Vec<String>,
}

/// Per-capability negotiation outcome.
#[derive(Debug, Serialize)]
pub struct NegotiatedCapability {
    pub name: String,
    pub level: DegradationLevel,
    pub reason: Option<String>,
    pub use_fallback: bool,
}

/// Result of negotiating a set of requested capabilities.
#[derive(Debug, Serialize)]
pub struct NegotiationResult {
    pub capabilities: Vec<NegotiatedCapability>,
    /// True if every requested capability is at least `Degraded` (i.e. the
    /// client can proceed in some form without hard failure).
    pub can_proceed: bool,
}

pub struct DegradationState {
    registry: Mutex<HashMap<String, CapabilityStatus>>,
}

impl DegradationState {
    pub fn new() -> Self {
        Self {
            registry: Mutex::new(HashMap::new()),
        }
    }

    /// Register or update a capability's degradation status.
    pub fn set_status(
        &self,
        name: &str,
        level: DegradationLevel,
        reason: Option<String>,
        fallback_available: bool,
    ) -> CapabilityStatus {
        let status = CapabilityStatus {
            name: name.to_string(),
            level,
            reason,
            fallback_available,
            updated_at: Utc::now(),
        };
        self.registry
            .lock()
            .unwrap()
            .insert(name.to_string(), status.clone());
        status
    }

    /// Look up a capability's status, defaulting to `Full` if unregistered.
    pub fn check(&self, name: &str) -> CapabilityStatus {
        self.registry.lock().unwrap().get(name).cloned().unwrap_or_else(|| {
            CapabilityStatus {
                name: name.to_string(),
                level: DegradationLevel::Full,
                reason: None,
                fallback_available: false,
                updated_at: Utc::now(),
            }
        })
    }

    pub fn list(&self) -> Vec<CapabilityStatus> {
        self.registry.lock().unwrap().values().cloned().collect()
    }

    /// Negotiate a set of requested capabilities against current status.
    pub fn negotiate(&self, requested: &[String]) -> NegotiationResult {
        let capabilities: Vec<NegotiatedCapability> = requested
            .iter()
            .map(|name| {
                let status = self.check(name);
                NegotiatedCapability {
                    name: status.name,
                    level: status.level,
                    reason: status.reason,
                    use_fallback: status.level != DegradationLevel::Full
                        && status.fallback_available,
                }
            })
            .collect();

        let can_proceed = capabilities
            .iter()
            .all(|c| c.level != DegradationLevel::Unavailable || c.use_fallback);

        NegotiationResult {
            capabilities,
            can_proceed,
        }
    }
}

impl Default for DegradationState {
    fn default() -> Self {
        Self::new()
    }
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

/// `POST /admin/capabilities` — set a capability's degradation level.
pub async fn set_capability(
    State(state): State<Arc<DegradationState>>,
    Json(body): Json<SetCapabilityRequest>,
) -> Result<Json<CapabilityStatus>, (StatusCode, Json<serde_json::Value>)> {
    if body.name.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "name must not be empty" })),
        ));
    }
    Ok(Json(state.set_status(
        &body.name,
        body.level,
        body.reason,
        body.fallback_available,
    )))
}

/// `GET /admin/capabilities` — list all registered capability statuses.
pub async fn list_capabilities(
    State(state): State<Arc<DegradationState>>,
) -> Json<Vec<CapabilityStatus>> {
    Json(state.list())
}

/// `POST /capabilities/negotiate` — negotiate a set of requested capabilities.
pub async fn negotiate_capabilities(
    State(state): State<Arc<DegradationState>>,
    Json(body): Json<NegotiateRequest>,
) -> Json<NegotiationResult> {
    Json(state.negotiate(&body.requested))
}

/// `GET /capabilities/:name/fallback` — reduced-functionality fallback
/// response for a capability that is degraded or unavailable.
pub async fn capability_fallback(
    State(state): State<Arc<DegradationState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let status = state.check(&name);
    if status.level == DegradationLevel::Full {
        return Err(StatusCode::NOT_FOUND);
    }
    if !status.fallback_available {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    Ok(Json(serde_json::json!({
        "capability": status.name,
        "level": status.level,
        "reason": status.reason,
        "message": "serving reduced-functionality fallback response",
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unregistered_capability_defaults_to_full() {
        let state = DegradationState::new();
        let status = state.check("payments");
        assert_eq!(status.level, DegradationLevel::Full);
    }

    #[test]
    fn negotiate_allows_proceeding_with_fallback() {
        let state = DegradationState::new();
        state.set_status(
            "search",
            DegradationLevel::Unavailable,
            Some("index rebuilding".to_string()),
            true,
        );

        let result = state.negotiate(&["search".to_string()]);
        assert!(result.can_proceed);
        assert!(result.capabilities[0].use_fallback);
    }

    #[test]
    fn negotiate_blocks_without_fallback() {
        let state = DegradationState::new();
        state.set_status("search", DegradationLevel::Unavailable, None, false);

        let result = state.negotiate(&["search".to_string()]);
        assert!(!result.can_proceed);
    }

    #[test]
    fn degraded_capability_can_proceed() {
        let state = DegradationState::new();
        state.set_status(
            "recommendations",
            DegradationLevel::Degraded,
            Some("stale cache".to_string()),
            false,
        );

        let result = state.negotiate(&["recommendations".to_string()]);
        assert!(result.can_proceed);
    }
}
