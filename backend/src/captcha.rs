// CAPTCHA challenge / verification module (#97)
//
// Provides a lightweight server-side CAPTCHA gate that is activated when a
// request IP is considered "suspicious" (exceeded a configurable threshold of
// recent events).  Trusted users are exempt.
//
// Google reCAPTCHA v2/v3 verification:
//   - Set RECAPTCHA_SITE_KEY   → sent to the frontend so it can render the widget.
//   - Set RECAPTCHA_SECRET_KEY → required for server-side token verification.
//
// The suspicious-activity threshold is controlled by the
// `CAPTCHA_SUSPICIOUS_THRESHOLD` env var (default: 10 events per window).
//
// These handlers are not yet registered in main.rs::build_router — see task
// instructions.  They follow the same axum pattern used throughout this crate:
//   `async fn foo(State(state): State<Arc<AppState>>, headers: HeaderMap, ...) -> Result<Json<T>, AppError>`
#![allow(clippy::unused_async)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;

use crate::{
    audit::authorize_admin,
    db::AppState,
    error::AppError,
    models::{
        AddTrustedUserRequest, CaptchaChallenge, CaptchaVerifyRequest, CaptchaVerifyResponse,
        TrustedUser,
    },
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default challenge lifetime in seconds (5 minutes).
const DEFAULT_CHALLENGE_TTL_SECS: i64 = 300;

/// Default number of events in a window before an IP is considered suspicious.
const DEFAULT_SUSPICIOUS_THRESHOLD: u32 = 10;

/// Default rolling window for suspicious-activity events (5 minutes).
const DEFAULT_SUSPICIOUS_WINDOW_SECS: i64 = 300;

/// Lifetime of the session token minted after a successful CAPTCHA (1 hour).
const SESSION_TOKEN_TTL_SECS: i64 = 3_600;

// ── Module-level in-memory stores ─────────────────────────────────────────────
//
// These are separate from AppState so that the captcha module can be used
// independently without modifying the AppState struct (which must stay
// unchanged per the task spec).

static CHALLENGE_STORE: std::sync::LazyLock<
    Arc<Mutex<HashMap<String, CaptchaChallenge>>>,
> = std::sync::LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

static TRUSTED_STORE: std::sync::LazyLock<Arc<Mutex<Vec<TrustedUser>>>> =
    std::sync::LazyLock::new(|| Arc::new(Mutex::new(Vec::new())));

/// Per-IP CAPTCHA failure tracking, used to detect automated bypass attempts
/// (#392): a client that repeatedly fails CAPTCHA and retries rapidly looks
/// like a bot rather than a confused human.
#[derive(Debug, Clone)]
struct FailureRecord {
    consecutive_failures: u32,
    last_failure_at: DateTime<Utc>,
    blocked_until: Option<DateTime<Utc>>,
}

static CAPTCHA_FAILURE_STORE: std::sync::LazyLock<Arc<Mutex<HashMap<String, FailureRecord>>>> =
    std::sync::LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Number of consecutive failures before progressive backoff kicks in.
const BACKOFF_FAILURE_THRESHOLD: u32 = 3;

/// Number of consecutive failures before the offending IP is flagged in the
/// IP-reputation subsystem (integration with #96, per #392's task list).
const REPUTATION_FLAG_THRESHOLD: u32 = 5;

/// Reputation score penalty applied each time the flag threshold is hit.
const REPUTATION_PENALTY: f64 = 15.0;

/// Base backoff duration in seconds; doubles for every failure past
/// `BACKOFF_FAILURE_THRESHOLD`, capped at `MAX_BACKOFF_SECS`.
const BASE_BACKOFF_SECS: i64 = 5;
const MAX_BACKOFF_SECS: i64 = 900;

/// Record a failed CAPTCHA verification attempt for `ip`.
///
/// Increments the consecutive-failure counter, applies progressive backoff
/// once `BACKOFF_FAILURE_THRESHOLD` is reached, and — once
/// `REPUTATION_FLAG_THRESHOLD` consecutive failures accumulate — flags the
/// IP in the IP-reputation subsystem so it carries elevated risk elsewhere
/// in the system too. Returns the updated consecutive-failure count.
pub fn record_captcha_failure(ip: &str) -> u32 {
    let now = Utc::now();
    let failures = {
        let mut store = CAPTCHA_FAILURE_STORE.lock().unwrap_or_else(|p| p.into_inner());
        let record = store.entry(ip.to_string()).or_insert(FailureRecord {
            consecutive_failures: 0,
            last_failure_at: now,
            blocked_until: None,
        });

        record.consecutive_failures += 1;
        record.last_failure_at = now;

        if record.consecutive_failures >= BACKOFF_FAILURE_THRESHOLD {
            let backoff_exponent = (record.consecutive_failures - BACKOFF_FAILURE_THRESHOLD).min(10);
            let backoff_secs = BASE_BACKOFF_SECS
                .saturating_mul(1i64 << backoff_exponent)
                .min(MAX_BACKOFF_SECS);
            record.blocked_until = Some(now + chrono::Duration::seconds(backoff_secs));
        }

        record.consecutive_failures
    };

    if failures >= REPUTATION_FLAG_THRESHOLD && failures % REPUTATION_FLAG_THRESHOLD == 0 {
        crate::ip_reputation::apply_local_penalty(
            ip,
            REPUTATION_PENALTY,
            "repeated CAPTCHA verification failures",
        );
    }

    failures
}

/// Clear the failure/backoff record for `ip`, called after a successful
/// CAPTCHA verification.
pub fn record_captcha_success(ip: &str) {
    let mut store = CAPTCHA_FAILURE_STORE.lock().unwrap_or_else(|p| p.into_inner());
    store.remove(ip);
}

/// Returns `true` if `ip` is currently within its progressive-backoff window
/// and should be rejected before attempting CAPTCHA verification at all.
pub fn is_backoff_active(ip: &str) -> bool {
    let store = CAPTCHA_FAILURE_STORE.lock().unwrap_or_else(|p| p.into_inner());
    store
        .get(ip)
        .and_then(|r| r.blocked_until)
        .map(|until| Utc::now() < until)
        .unwrap_or(false)
}

/// Current consecutive-failure count recorded for `ip` (0 if none).
pub fn consecutive_failures_for_ip(ip: &str) -> u32 {
    let store = CAPTCHA_FAILURE_STORE.lock().unwrap_or_else(|p| p.into_inner());
    store.get(ip).map(|r| r.consecutive_failures).unwrap_or(0)
}

// ── Helper: extract IP from request headers ───────────────────────────────────

fn extract_ip(headers: &HeaderMap, peer_ip: IpAddr) -> String {
    crate::audit::extract_client_ip(headers, Some(peer_ip))
}

/// Extract the optional `X-User-ID` header value.
fn extract_user_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

// ── Core logic functions ───────────────────────────────────────────────────────

/// Returns `true` if the given `user_id`/`ip` combination is in the trusted
/// store and the trust entry has not yet expired.
///
/// Note: `state` is accepted to keep the function signature consistent with the
/// rest of the codebase; the actual data comes from the module-level static
/// store so that no changes to `AppState` are required.
pub fn is_trusted_user(user_id: &str, ip: &str, _state: &AppState) -> bool {
    let now = Utc::now();
    let store = TRUSTED_STORE.lock().unwrap_or_else(|p| p.into_inner());
    store
        .iter()
        .any(|u| u.user_id == user_id && u.ip == ip && u.trusted_until > now)
}

/// Returns `true` if `ip` has exceeded the configured suspicious-activity
/// threshold.
///
/// The threshold is read from `CAPTCHA_SUSPICIOUS_THRESHOLD` (default 10).
/// Events are stored in the shared SQLite database over a rolling window.
pub fn is_suspicious(ip: &str, state: &AppState) -> Result<bool, rusqlite::Error> {
    let threshold = std::env::var("CAPTCHA_SUSPICIOUS_THRESHOLD")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(DEFAULT_SUSPICIOUS_THRESHOLD);

    let window_secs = std::env::var("CAPTCHA_SUSPICIOUS_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(DEFAULT_SUSPICIOUS_WINDOW_SECS);
    Ok(state.db.captcha_event_count(ip, window_secs)? >= threshold)
}

/// Increment the per-IP event counter (used by other modules to signal
/// potentially suspicious activity from an IP).
pub fn record_event_for_ip(ip: &str, state: &AppState) -> Result<u32, rusqlite::Error> {
    let window_secs = std::env::var("CAPTCHA_SUSPICIOUS_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(DEFAULT_SUSPICIOUS_WINDOW_SECS);
    state.db.record_captcha_event(ip, window_secs)
}

/// Reset the per-IP event counter (e.g. after a successful CAPTCHA verification
/// or when the observation window rolls over).
pub fn reset_event_counter_for_ip(ip: &str, state: &AppState) -> Result<(), rusqlite::Error> {
    state.db.reset_captcha_events(ip)
}

/// Generate a fresh `CaptchaChallenge`.
///
/// The `site_key` is read from the `RECAPTCHA_SITE_KEY` environment variable.
/// If the variable is absent an empty string is used (development / test mode).
///
/// The challenge is stored in the module-level `CHALLENGE_STORE` so that
/// `verify_captcha` can look it up later.
pub fn generate_challenge(_state: &AppState) -> CaptchaChallenge {
    let site_key = std::env::var("RECAPTCHA_SITE_KEY").unwrap_or_default();
    let challenge = CaptchaChallenge {
        id: Uuid::new_v4().to_string(),
        token: Uuid::new_v4().to_string(),
        expires_at: Utc::now() + chrono::Duration::seconds(DEFAULT_CHALLENGE_TTL_SECS),
        site_key,
    };

    // Persist the challenge so `verify_captcha` can validate it.
    {
        let mut store = CHALLENGE_STORE.lock().unwrap_or_else(|p| p.into_inner());
        // Opportunistically evict expired challenges.
        let now = Utc::now();
        store.retain(|_, v| v.expires_at > now);
        store.insert(challenge.id.clone(), challenge.clone());
    }

    challenge
}

fn recaptcha_secret_key() -> Result<String, String> {
    std::env::var("RECAPTCHA_SECRET_KEY")
        .map_err(|_| "RECAPTCHA_SECRET_KEY is not configured".to_string())
        .and_then(|secret| {
            let secret = secret.trim().to_string();
            if secret.is_empty() {
                Err("RECAPTCHA_SECRET_KEY is not configured".to_string())
            } else {
                Ok(secret)
            }
        })
}

/// Verify a CAPTCHA token against the Google reCAPTCHA API.
///
/// # Behaviour
/// A `POST` is sent to `https://www.google.com/recaptcha/api/siteverify` with
/// the configured secret key and user-supplied token. Missing configuration
/// is an error; it never accepts a token without verification.
///
/// # Errors
/// Returns `Err(String)` if the challenge is unknown / expired, or if the
/// reCAPTCHA API rejects the token.
pub async fn verify_captcha(
    req: &CaptchaVerifyRequest,
    _state: &AppState,
) -> Result<CaptchaVerifyResponse, String> {
    // 1. Look up and validate the challenge.
    let challenge = {
        let store = CHALLENGE_STORE.lock().unwrap_or_else(|p| p.into_inner());
        store.get(&req.challenge_id).cloned()
    };

    let challenge = challenge.ok_or_else(|| "challenge not found".to_string())?;

    if Utc::now() > challenge.expires_at {
        return Err("challenge has expired".to_string());
    }

    // 2. Validate against reCAPTCHA; missing configuration is a hard failure.
    let secret_key = recaptcha_secret_key()?;

    // 3. Real reCAPTCHA verification via reqwest.
    let client = reqwest::Client::new();
    let params = [
        ("secret", secret_key.as_str()),
        ("response", req.captcha_token.as_str()),
    ];

    let response = client
        .post("https://www.google.com/recaptcha/api/siteverify")
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("reCAPTCHA HTTP request failed: {e}"))?;

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("failed to parse reCAPTCHA response: {e}"))?;

    let success = body
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !success {
        let error_codes = body
            .get("error-codes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();

        return Ok(CaptchaVerifyResponse {
            verified: false,
            session_token: None,
            message: if error_codes.is_empty() {
                "CAPTCHA verification failed".to_string()
            } else {
                format!("CAPTCHA verification failed: {error_codes}")
            },
        });
    }

    // 4. Success — remove the used challenge and mint a session token.
    CHALLENGE_STORE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&req.challenge_id);

    let session_token = format!(
        "{}.{}",
        Uuid::new_v4(),
        (Utc::now() + chrono::Duration::seconds(SESSION_TOKEN_TTL_SECS)).timestamp()
    );

    Ok(CaptchaVerifyResponse {
        verified: true,
        session_token: Some(session_token),
        message: "CAPTCHA verified successfully".to_string(),
    })
}

// ── Route handlers ─────────────────────────────────────────────────────────────

/// `POST /captcha/challenge`
///
/// Uses the socket peer IP and honors forwarded headers only from a trusted
/// proxy. If the caller is a trusted user, returns `204 No Content` (no
/// challenge needed); otherwise, issues a challenge and returns `200 OK`.
pub async fn post_challenge_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let ip = extract_ip(&headers, peer.ip());
    let user_id = extract_user_id(&headers).unwrap_or_default();

    // Trusted users are exempt.
    if !user_id.is_empty() && is_trusted_user(&user_id, &ip, &state) {
        return Ok((StatusCode::NO_CONTENT, Json(json!(null))).into_response());
    }

    // Only issue a challenge when the IP looks suspicious (or when the user
    // has no recorded trust entry — i.e. unknown users always get a challenge
    // if the IP is flagged, and known users only if they are not trusted).
    if !user_id.is_empty() && !is_suspicious(&ip, &state)? {
        // Known, non-suspicious user — no challenge needed.
        return Ok((StatusCode::NO_CONTENT, Json(json!(null))).into_response());
    }

    let challenge = generate_challenge(&state);
    Ok((StatusCode::OK, Json(json!(challenge))).into_response())
}

/// `POST /captcha/verify`
///
/// Accepts a `CaptchaVerifyRequest` JSON body.  On success returns a
/// `CaptchaVerifyResponse` with a session token; on failure returns
/// `422 Unprocessable Entity`. An IP currently in its progressive-backoff
/// window (#392, see `is_backoff_active`) is rejected with
/// `429 Too Many Requests` before verification is even attempted.
pub async fn post_verify_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<CaptchaVerifyRequest>,
) -> Result<Json<CaptchaVerifyResponse>, AppError> {
    let ip = extract_ip(&headers, peer.ip());

    if is_backoff_active(&ip) {
        return Err(AppError::TooManyRequests(
            "too many failed CAPTCHA attempts; please wait before retrying".to_string(),
        ));
    }

    if let Err(error) = recaptcha_secret_key() {
        tracing::error!(%error, "CAPTCHA verification is unavailable");
        return Err(crate::error::ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "captcha_unavailable",
            "CAPTCHA verification is not configured",
        )
        .into());
    }

    match verify_captcha(&req, &state).await {
        Ok(resp) => {
            if resp.verified {
                // Successful verification clears the failure/backoff record
                // and the suspicious-activity counter for this IP so that
                // subsequent requests are not immediately flagged again.
                record_captcha_success(&ip);
                reset_event_counter_for_ip(&ip, &state)?;
                tracing::debug!(
                    challenge_id = %req.challenge_id,
                    ip = %ip,
                    "CAPTCHA verified successfully"
                );
            } else {
                let failures = record_captcha_failure(&ip);
                tracing::warn!(
                    ip = %ip,
                    consecutive_failures = failures,
                    "CAPTCHA verification failed"
                );
            }
            Ok(Json(resp))
        }
        Err(e) => {
            let failures = record_captcha_failure(&ip);
            tracing::warn!(
                ip = %ip,
                consecutive_failures = failures,
                error = %e,
                "CAPTCHA verification error"
            );
            Err(AppError::InvalidInput(e))
        }
    }
}

/// `GET /admin/captcha/trusted-users`
///
/// Returns the list of currently active (non-expired) trusted users.
/// Requires a valid admin API key (`Authorization: Bearer <key>`).
pub async fn get_trusted_users_handler(
    State(_state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<TrustedUser>>, impl IntoResponse> {
    if let Err(api_err) = authorize_admin(&headers) {
        return Err(api_err.into_response());
    }

    let now = Utc::now();
    let store = TRUSTED_STORE.lock().unwrap_or_else(|p| p.into_inner());
    let active: Vec<TrustedUser> = store
        .iter()
        .filter(|u| u.trusted_until > now)
        .cloned()
        .collect();

    Ok(Json(active))
}

/// `POST /admin/captcha/trusted-users`
///
/// Adds a new trusted user/IP entry.  Requires a valid admin API key.
pub async fn post_add_trusted_user_handler(
    State(_state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AddTrustedUserRequest>,
) -> Result<Json<TrustedUser>, impl IntoResponse> {
    if let Err(api_err) = authorize_admin(&headers) {
        return Err(api_err.into_response());
    }

    let duration_secs = req.trust_duration_secs.unwrap_or(86_400) as i64;
    let trusted_until = Utc::now() + chrono::Duration::seconds(duration_secs);

    let entry = TrustedUser {
        user_id: req.user_id.clone(),
        ip: req.ip.clone(),
        trusted_until,
    };

    {
        let mut store = TRUSTED_STORE.lock().unwrap_or_else(|p| p.into_inner());
        // Remove any existing entry for the same user_id + ip combination
        // before inserting the new one so there are no duplicates.
        store.retain(|u| !(u.user_id == req.user_id && u.ip == req.ip));
        store.push(entry.clone());
    }

    tracing::info!(
        user_id = %req.user_id,
        ip = %req.ip,
        trusted_until = %trusted_until,
        "trusted user added"
    );

    Ok(Json(entry))
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_state() -> AppState {
        use crate::batching::{AdaptiveBatcher, BatchConfig};
        use crate::consensus::NodeCache;
        use crate::db::{
            create_audit_store, create_event_store, create_share_store, create_share_token_store,
            create_vault_store, Db, PoolConfig,
        };
        use crate::deadlock::DeadlockDetector;
        use crate::degradation::DegradationState;
        use crate::event_sourcing::EventSourcingState;
        use crate::feature_flags::FlagState;
        use crate::graphql::build_schema;
        use crate::load_shedding::{LoadMonitor, LoadShedder, SheddingConfig};
        use crate::message_queue::MessageQueueState;
        use crate::metrics::Metrics;
        use crate::predictive_scaling::{
            ForecastModel, LoggingAutoscalerClient, PredictiveScaler, ScalingConfig,
        };
        use crate::priority::{PriorityConfig, PriorityEnforcer};
        use crate::query_cache::QueryCache;
        use crate::webhook::WebhookState;

        let db = Arc::new(
            Db::open_with_pool_config(":memory:", &PoolConfig::default())
                .expect("test db"),
        );
        db.migrate().expect("migrate");
        let vault_store = create_vault_store();
        let event_store = create_event_store();
        let graphql_schema = build_schema(Arc::clone(&vault_store), Arc::clone(&event_store));
        let flag_state = Arc::new(FlagState::new(Arc::clone(&db)));
        let degradation_state = Arc::new(DegradationState::new(Arc::clone(&db)));

        AppState {
            db: Arc::clone(&db),
            vault_store,
            event_store,
            audit_store: create_audit_store(),
            share_store: create_share_store(),
            share_token_store: create_share_token_store(),
            consensus: NodeCache::from_env(),
            webhook_state: Arc::new(WebhookState::new()),
            graphql_schema,
            metrics: Metrics::new(),
            priority_enforcer: Arc::new(PriorityEnforcer::new(PriorityConfig::default())),
            load_shedder: Arc::new(LoadShedder::new(
                LoadMonitor::new(),
                SheddingConfig::default(),
            )),
            batcher: Arc::new(AdaptiveBatcher::new(BatchConfig::default())),
            scaler: Arc::new(PredictiveScaler::new(
                10,
                ForecastModel::default(),
                ScalingConfig::default(),
                Box::new(LoggingAutoscalerClient),
            )),
            event_sourcing: Arc::new(EventSourcingState::with_db(Arc::clone(&db))),
            message_queue: Arc::new(
                MessageQueueState::new().expect("failed to initialize message queue"),
            ),
            degradation_state,
            flag_state,
            query_cache: Arc::new(QueryCache::new()),
            deadlock_detector: Arc::new(DeadlockDetector::new()),
        }
    }

    #[test]
    fn trusted_user_not_found_by_default() {
        let state = dummy_state();
        assert!(!is_trusted_user("alice", "1.2.3.4", &state));
    }

    #[test]
    fn trusted_user_found_after_insert() {
        let state = dummy_state();

        // Directly insert into the static store.
        {
            let mut store = TRUSTED_STORE.lock().unwrap();
            store.push(TrustedUser {
                user_id: "test-user-trusted".to_string(),
                ip: "10.0.0.1".to_string(),
                trusted_until: Utc::now() + chrono::Duration::hours(1),
            });
        }

        assert!(is_trusted_user("test-user-trusted", "10.0.0.1", &state));
        assert!(!is_trusted_user("test-user-trusted", "10.0.0.2", &state));

        // Clean up.
        TRUSTED_STORE
            .lock()
            .unwrap()
            .retain(|u| u.user_id != "test-user-trusted");
    }

    #[test]
    fn not_suspicious_below_threshold() {
        let state = dummy_state();
        // Use a unique IP to avoid interference from other tests.
        assert!(!is_suspicious("192.0.2.1", &state).unwrap());
    }

    #[test]
    fn suspicious_after_threshold_events() {
        let state = dummy_state();
        let ip = "192.0.2.2";
        // Default threshold is 10.
        for _ in 0..10 {
            record_event_for_ip(ip, &state).unwrap();
        }
        assert!(is_suspicious(ip, &state).unwrap());
        reset_event_counter_for_ip(ip, &state).unwrap();
        assert!(!is_suspicious(ip, &state).unwrap());
    }

    #[test]
    fn generate_challenge_returns_valid_challenge() {
        let state = dummy_state();
        let ch = generate_challenge(&state);
        assert!(!ch.id.is_empty());
        assert!(!ch.token.is_empty());
        assert!(ch.expires_at > Utc::now());
    }

    #[tokio::test]
    async fn verify_captcha_without_secret_fails_closed() {
        std::env::remove_var("RECAPTCHA_SECRET_KEY");

        let state = dummy_state();
        let challenge = generate_challenge(&state);

        let req = CaptchaVerifyRequest {
            challenge_id: challenge.id,
            captcha_token: "any-token".to_string(),
            user_token: "my-user-token".to_string(),
        };

        let result = verify_captcha(&req, &state).await;
        assert_eq!(
            result.unwrap_err(),
            "RECAPTCHA_SECRET_KEY is not configured"
        );
    }

    #[tokio::test]
    async fn post_verify_handler_reports_unavailable_without_secret() {
        std::env::remove_var("RECAPTCHA_SECRET_KEY");
        let state = Arc::new(dummy_state());
        let ip = "203.0.113.16";
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", ip.parse().unwrap());
        let req = CaptchaVerifyRequest {
            challenge_id: "unneeded".to_string(),
            captcha_token: "unneeded".to_string(),
            user_token: "unneeded".to_string(),
        };

        let result = post_verify_handler(
            State(state),
            headers,
            ConnectInfo("203.0.113.16:3000".parse().unwrap()),
            Json(req),
        )
        .await;
        match result {
            Err(AppError::Api(error)) => {
                assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
            }
            other => panic!("expected unavailable response, got {other:?}"),
        }
        assert_eq!(consecutive_failures_for_ip(ip), 0);
    }

    #[tokio::test]
    async fn verify_captcha_unknown_challenge_fails() {
        std::env::remove_var("RECAPTCHA_SECRET_KEY");

        let state = dummy_state();
        let req = CaptchaVerifyRequest {
            challenge_id: "non-existent-id".to_string(),
            captcha_token: "some-token".to_string(),
            user_token: "some-user".to_string(),
        };

        let result = verify_captcha(&req, &state).await;
        assert!(result.is_err());
    }

    // ── CAPTCHA bypass detection / backoff (#392) ────────────────────────────

    #[test]
    fn failure_count_tracks_and_resets_on_success() {
        let ip = "203.0.113.10";
        assert_eq!(consecutive_failures_for_ip(ip), 0);

        assert_eq!(record_captcha_failure(ip), 1);
        assert_eq!(record_captcha_failure(ip), 2);
        assert_eq!(consecutive_failures_for_ip(ip), 2);

        record_captcha_success(ip);
        assert_eq!(consecutive_failures_for_ip(ip), 0);
        assert!(!is_backoff_active(ip));
    }

    #[test]
    fn no_backoff_below_threshold() {
        let ip = "203.0.113.11";
        for _ in 0..(BACKOFF_FAILURE_THRESHOLD - 1) {
            record_captcha_failure(ip);
        }
        assert!(!is_backoff_active(ip));
        record_captcha_success(ip);
    }

    #[test]
    fn backoff_triggers_at_threshold_and_clears_on_success() {
        let ip = "203.0.113.12";
        for _ in 0..BACKOFF_FAILURE_THRESHOLD {
            record_captcha_failure(ip);
        }
        assert!(is_backoff_active(ip));

        record_captcha_success(ip);
        assert!(!is_backoff_active(ip));
        assert_eq!(consecutive_failures_for_ip(ip), 0);
    }

    #[test]
    fn backoff_window_grows_with_further_failures() {
        let ip = "203.0.113.13";
        for _ in 0..BACKOFF_FAILURE_THRESHOLD {
            record_captcha_failure(ip);
        }
        let blocked_until_first = {
            let store = CAPTCHA_FAILURE_STORE.lock().unwrap();
            store.get(ip).and_then(|r| r.blocked_until).unwrap()
        };

        record_captcha_failure(ip);
        let blocked_until_second = {
            let store = CAPTCHA_FAILURE_STORE.lock().unwrap();
            store.get(ip).and_then(|r| r.blocked_until).unwrap()
        };

        assert!(blocked_until_second > blocked_until_first);
        record_captcha_success(ip);
    }

    #[test]
    fn repeated_failures_flag_ip_in_reputation_store() {
        let ip = "203.0.113.14";
        crate::ip_reputation::IP_REPUTATION_STORE.lock().unwrap().remove(ip);

        for _ in 0..REPUTATION_FLAG_THRESHOLD {
            record_captcha_failure(ip);
        }

        let score = crate::ip_reputation::IP_REPUTATION_STORE
            .lock()
            .unwrap()
            .get(ip)
            .cloned()
            .expect("ip should have been flagged in the reputation store");
        assert!(score.score > 0.0);
        assert_eq!(score.source, "local-penalty");

        record_captcha_success(ip);
        crate::ip_reputation::IP_REPUTATION_STORE.lock().unwrap().remove(ip);
    }

    #[tokio::test]
    async fn post_verify_handler_rejects_backed_off_ip() {
        std::env::remove_var("RECAPTCHA_SECRET_KEY");

        let ip = "203.0.113.15";
        for _ in 0..BACKOFF_FAILURE_THRESHOLD {
            record_captcha_failure(ip);
        }

        let state = Arc::new(dummy_state());
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", ip.parse().unwrap());

        let req = CaptchaVerifyRequest {
            challenge_id: "irrelevant".to_string(),
            captcha_token: "irrelevant".to_string(),
            user_token: "irrelevant".to_string(),
        };

        let peer = ConnectInfo("203.0.113.15:3000".parse().unwrap());
        let result = post_verify_handler(State(state), headers, peer, Json(req)).await;
        match result {
            Err(AppError::TooManyRequests(_)) => {}
            other => panic!("expected TooManyRequests, got {other:?}"),
        }

        record_captcha_success(ip);
    }
}
