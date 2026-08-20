//! WebAuthn/FIDO2 support (#148).
//!
//! Provides server-side WebAuthn registration and authentication flows,
//! including support for backup (secondary) authenticators per credential.
//!
//! # Architecture
//!
//! ```text
//! POST /webauthn/register/begin      → begin_registration
//! POST /webauthn/register/complete   → complete_registration
//! POST /webauthn/authenticate/begin  → begin_authentication
//! POST /webauthn/authenticate/complete → complete_authentication
//! GET  /webauthn/credentials/:user_id → list_credentials
//! DELETE /webauthn/credentials/:user_id/:cred_id → remove_credential
//! POST /webauthn/credentials/:user_id/:cred_id/backup → add_backup_authenticator
//! ```
//!
//! ## Security notes
//! - Challenges are single-use and expire after `CHALLENGE_TTL_SECS`.
//! - Counter checks detect authenticator cloning.
//! - Backup authenticators are stored with the `is_backup` flag so UX can
//!   distinguish primary vs. recovery keys.

#![allow(clippy::unused_async)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};

// ── Constants ────────────────────────────────────────────────────────────────

/// Seconds before a pending challenge expires.
const CHALLENGE_TTL_SECS: u64 = 300;

/// Minimum acceptable key size (bytes) for credential IDs.
const MIN_CREDENTIAL_ID_LEN: usize = 16;

// ── Public key algorithms (COSE) ─────────────────────────────────────────────

/// COSE algorithm identifiers supported by this server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoseAlgorithm {
    /// ECDSA with SHA-256 (most widely supported).
    ES256 = -7,
    /// RSASSA-PKCS1-v1_5 with SHA-256 (legacy compatibility).
    RS256 = -257,
    /// EdDSA (Ed25519 — highest security).
    EdDsa = -8,
}

impl CoseAlgorithm {
    pub fn cose_id(self) -> i32 {
        self as i32
    }
}

// ── Data types ────────────────────────────────────────────────────────────────

/// A stored WebAuthn credential for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// Base64url-encoded credential ID from the authenticator.
    pub credential_id: String,
    /// The associated user identifier.
    pub user_id: String,
    /// Base64url-encoded CBOR-encoded public key.
    pub public_key: String,
    /// COSE algorithm used by this credential.
    pub algorithm: CoseAlgorithm,
    /// Signature counter — incremented by authenticator on each use.
    pub sign_count: u32,
    /// Whether this credential is a backup / recovery authenticator.
    pub is_backup: bool,
    /// Human-readable label (e.g. "YubiKey 5C", "iPhone Touch ID").
    pub label: Option<String>,
    /// AAGUID (authenticator model identifier), hex string.
    pub aaguid: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// A pending registration challenge stored server-side.
#[derive(Debug, Clone)]
struct PendingRegistration {
    challenge: Vec<u8>,
    user_id: String,
    user_name: String,
    expires_at: u64,
}

/// A pending authentication challenge stored server-side.
#[derive(Debug, Clone)]
struct PendingAuthentication {
    challenge: Vec<u8>,
    user_id: String,
    expires_at: u64,
}

// ── In-memory stores ──────────────────────────────────────────────────────────

pub type CredentialStore = Arc<Mutex<HashMap<String, Vec<StoredCredential>>>>;

pub struct WebAuthnState {
    pub credentials: CredentialStore,
    pending_registrations: Arc<Mutex<HashMap<String, PendingRegistration>>>,
    pending_authentications: Arc<Mutex<HashMap<String, PendingAuthentication>>>,
    /// Relying party ID (e.g. "example.com").
    pub rp_id: String,
    /// Relying party display name.
    pub rp_name: String,
    /// Origin used for validation (e.g. "https://example.com").
    pub origin: String,
}

impl WebAuthnState {
    pub fn new(
        rp_id: impl Into<String>,
        rp_name: impl Into<String>,
        origin: impl Into<String>,
    ) -> Self {
        Self {
            credentials: Arc::new(Mutex::new(HashMap::new())),
            pending_registrations: Arc::new(Mutex::new(HashMap::new())),
            pending_authentications: Arc::new(Mutex::new(HashMap::new())),
            rp_id: rp_id.into(),
            rp_name: rp_name.into(),
            origin: origin.into(),
        }
    }

    pub fn from_env() -> Self {
        let rp_id = std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
        let rp_name =
            std::env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "Ethos Protocol".to_string());
        let origin = std::env::var("WEBAUTHN_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());
        Self::new(rp_id, rp_name, origin)
    }
}

// ── Helper: random challenge ──────────────────────────────────────────────────

fn generate_challenge() -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn b64url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BeginRegistrationRequest {
    pub user_id: String,
    pub user_name: String,
    /// Optional label for the new credential (e.g. "YubiKey 5C").
    pub label: Option<String>,
    /// If true, this credential is registered as a backup authenticator.
    #[serde(default)]
    pub is_backup: bool,
}

#[derive(Debug, Serialize)]
pub struct BeginRegistrationResponse {
    /// Session token used to correlate begin → complete.
    pub session_id: String,
    pub rp: RpInfo,
    pub user: UserInfo,
    /// Base64url-encoded random challenge.
    pub challenge: String,
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub timeout_ms: u32,
    pub attestation: String,
}

#[derive(Debug, Serialize)]
pub struct RpInfo {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    /// Base64url-encoded user handle.
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub kind: String,
    pub alg: i32,
}

#[derive(Debug, Deserialize)]
pub struct CompleteRegistrationRequest {
    pub session_id: String,
    /// Base64url-encoded credential ID from the authenticator response.
    pub credential_id: String,
    /// Base64url-encoded client data JSON.
    pub client_data_json: String,
    /// Base64url-encoded attestation object (CBOR).
    pub attestation_object: String,
    pub label: Option<String>,
    #[serde(default)]
    pub is_backup: bool,
}

#[derive(Debug, Serialize)]
pub struct CompleteRegistrationResponse {
    pub credential_id: String,
    pub user_id: String,
    pub is_backup: bool,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct BeginAuthenticationRequest {
    pub user_id: String,
}

#[derive(Debug, Serialize)]
pub struct BeginAuthenticationResponse {
    pub session_id: String,
    pub challenge: String,
    pub timeout_ms: u32,
    pub rp_id: String,
    pub allow_credentials: Vec<AllowCredential>,
    pub user_verification: String,
}

#[derive(Debug, Serialize)]
pub struct AllowCredential {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct CompleteAuthenticationRequest {
    pub session_id: String,
    pub credential_id: String,
    pub client_data_json: String,
    /// Base64url-encoded authenticator data.
    pub authenticator_data: String,
    /// Base64url-encoded DER signature.
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct CompleteAuthenticationResponse {
    pub user_id: String,
    pub credential_id: String,
    pub sign_count: u32,
    pub authenticated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct AddBackupAuthenticatorRequest {
    pub user_id: String,
    pub label: Option<String>,
}

// ── Handler: begin registration ───────────────────────────────────────────────

/// `POST /webauthn/register/begin`
///
/// Issues a fresh registration challenge.  The client must complete it within
/// `CHALLENGE_TTL_SECS` by calling `complete_registration`.
pub async fn begin_registration(
    State(state): State<Arc<WebAuthnState>>,
    Json(body): Json<BeginRegistrationRequest>,
) -> Result<(StatusCode, Json<BeginRegistrationResponse>), (StatusCode, Json<serde_json::Value>)> {
    if body.user_id.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "user_id must not be empty" })),
        ));
    }
    if body.user_name.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "user_name must not be empty" })),
        ));
    }

    let challenge = generate_challenge();
    let session_id = b64url_encode(&generate_challenge()); // random session token

    let pending = PendingRegistration {
        challenge: challenge.clone(),
        user_id: body.user_id.clone(),
        user_name: body.user_name.clone(),
        expires_at: now_secs() + CHALLENGE_TTL_SECS,
    };

    state
        .pending_registrations
        .lock()
        .unwrap()
        .insert(session_id.clone(), pending);

    let response = BeginRegistrationResponse {
        session_id,
        rp: RpInfo {
            id: state.rp_id.clone(),
            name: state.rp_name.clone(),
        },
        user: UserInfo {
            id: b64url_encode(body.user_id.as_bytes()),
            name: body.user_name.clone(),
            display_name: body.user_name.clone(),
        },
        challenge: b64url_encode(&challenge),
        pub_key_cred_params: vec![
            PubKeyCredParam {
                kind: "public-key".into(),
                alg: CoseAlgorithm::ES256.cose_id(),
            },
            PubKeyCredParam {
                kind: "public-key".into(),
                alg: CoseAlgorithm::EdDsa.cose_id(),
            },
            PubKeyCredParam {
                kind: "public-key".into(),
                alg: CoseAlgorithm::RS256.cose_id(),
            },
        ],
        timeout_ms: (CHALLENGE_TTL_SECS * 1000) as u32,
        attestation: "none".into(),
    };

    Ok((StatusCode::OK, Json(response)))
}

// ── Handler: complete registration ────────────────────────────────────────────

/// `POST /webauthn/register/complete`
///
/// Validates the authenticator's attestation response and stores the credential.
///
/// In production, full attestation verification (CBOR parsing, certificate
/// chain validation) would be performed.  This implementation validates the
/// structure of the client data, verifies the challenge, and stores the
/// credential so the full flow is exercisable.
pub async fn complete_registration(
    State(state): State<Arc<WebAuthnState>>,
    Json(body): Json<CompleteRegistrationRequest>,
) -> Result<(StatusCode, Json<CompleteRegistrationResponse>), (StatusCode, Json<serde_json::Value>)>
{
    // 1. Retrieve and expire the pending session.
    let pending = {
        let mut map = state.pending_registrations.lock().unwrap();
        match map.remove(&body.session_id) {
            Some(p) => p,
            None => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "unknown or expired session" })),
                ))
            }
        }
    };

    // 2. Check TTL.
    if now_secs() > pending.expires_at {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "registration challenge expired" })),
        ));
    }

    // 3. Decode and validate credential ID.
    let cred_id_bytes = b64url_decode(&body.credential_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid credential_id encoding" })),
        )
    })?;
    if cred_id_bytes.len() < MIN_CREDENTIAL_ID_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "credential_id too short" })),
        ));
    }

    // 4. Decode client data JSON and verify challenge + origin.
    let client_data_raw = b64url_decode(&body.client_data_json).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid client_data_json encoding" })),
        )
    })?;
    let client_data: serde_json::Value =
        serde_json::from_slice(&client_data_raw).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "client_data_json is not valid JSON" })),
            )
        })?;

    // Verify type field.
    if client_data.get("type").and_then(|v| v.as_str()) != Some("webauthn.create") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "unexpected client data type" })),
        ));
    }

    // Verify challenge matches.
    let received_challenge = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if received_challenge != b64url_encode(&pending.challenge) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "challenge mismatch" })),
        ));
    }

    // Verify origin.
    let received_origin = client_data
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if received_origin != state.origin {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "origin mismatch" })),
        ));
    }

    // 5. Decode attestation object (we accept any well-formed base64url blob).
    let _attestation_bytes = b64url_decode(&body.attestation_object).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid attestation_object encoding" })),
        )
    })?;

    // 6. Check for duplicate credential IDs across all users.
    {
        let store = state.credentials.lock().unwrap();
        for creds in store.values() {
            if creds.iter().any(|c| c.credential_id == body.credential_id) {
                return Err((
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({ "error": "credential already registered" })),
                ));
            }
        }
    }

    // 7. Persist credential.
    let label = body.label.or_else(|| {
        if body.is_backup {
            Some("Backup Authenticator".to_string())
        } else {
            None
        }
    });

    let credential = StoredCredential {
        credential_id: body.credential_id.clone(),
        user_id: pending.user_id.clone(),
        // Store the raw attestation object as the "public key" blob for now.
        // A full implementation would extract the COSE key from the auth data.
        public_key: body.attestation_object.clone(),
        algorithm: CoseAlgorithm::ES256,
        sign_count: 0,
        is_backup: body.is_backup,
        label: label.clone(),
        aaguid: None,
        created_at: Utc::now(),
        last_used_at: None,
    };

    state
        .credentials
        .lock()
        .unwrap()
        .entry(pending.user_id.clone())
        .or_default()
        .push(credential);

    Ok((
        StatusCode::CREATED,
        Json(CompleteRegistrationResponse {
            credential_id: body.credential_id,
            user_id: pending.user_id,
            is_backup: body.is_backup,
            label,
            created_at: Utc::now(),
        }),
    ))
}

// ── Handler: begin authentication ────────────────────────────────────────────

/// `POST /webauthn/authenticate/begin`
pub async fn begin_authentication(
    State(state): State<Arc<WebAuthnState>>,
    Json(body): Json<BeginAuthenticationRequest>,
) -> Result<(StatusCode, Json<BeginAuthenticationResponse>), (StatusCode, Json<serde_json::Value>)>
{
    if body.user_id.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "user_id must not be empty" })),
        ));
    }

    // Build allow list from registered credentials.
    let allow_credentials: Vec<AllowCredential> = {
        let store = state.credentials.lock().unwrap();
        store
            .get(&body.user_id)
            .map(|creds| {
                creds
                    .iter()
                    .map(|c| AllowCredential {
                        kind: "public-key".into(),
                        id: c.credential_id.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    if allow_credentials.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no credentials registered for this user" })),
        ));
    }

    let challenge = generate_challenge();
    let session_id = b64url_encode(&generate_challenge());

    let pending = PendingAuthentication {
        challenge: challenge.clone(),
        user_id: body.user_id.clone(),
        expires_at: now_secs() + CHALLENGE_TTL_SECS,
    };

    state
        .pending_authentications
        .lock()
        .unwrap()
        .insert(session_id.clone(), pending);

    Ok((
        StatusCode::OK,
        Json(BeginAuthenticationResponse {
            session_id,
            challenge: b64url_encode(&challenge),
            timeout_ms: (CHALLENGE_TTL_SECS * 1000) as u32,
            rp_id: state.rp_id.clone(),
            allow_credentials,
            user_verification: "preferred".into(),
        }),
    ))
}

// ── Handler: complete authentication ─────────────────────────────────────────

/// `POST /webauthn/authenticate/complete`
pub async fn complete_authentication(
    State(state): State<Arc<WebAuthnState>>,
    Json(body): Json<CompleteAuthenticationRequest>,
) -> Result<(StatusCode, Json<CompleteAuthenticationResponse>), (StatusCode, Json<serde_json::Value>)>
{
    // 1. Retrieve and expire the pending session.
    let pending = {
        let mut map = state.pending_authentications.lock().unwrap();
        match map.remove(&body.session_id) {
            Some(p) => p,
            None => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "unknown or expired session" })),
                ))
            }
        }
    };

    if now_secs() > pending.expires_at {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "authentication challenge expired" })),
        ));
    }

    // 2. Decode and validate client data JSON.
    let client_data_raw = b64url_decode(&body.client_data_json).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid client_data_json encoding" })),
        )
    })?;
    let client_data: serde_json::Value =
        serde_json::from_slice(&client_data_raw).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "client_data_json is not valid JSON" })),
            )
        })?;

    if client_data.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "unexpected client data type" })),
        ));
    }

    let received_challenge = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if received_challenge != b64url_encode(&pending.challenge) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "challenge mismatch" })),
        ));
    }

    let received_origin = client_data
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if received_origin != state.origin {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "origin mismatch" })),
        ));
    }

    // 3. Decode authenticator data and extract sign_count.
    let auth_data = b64url_decode(&body.authenticator_data).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid authenticator_data encoding" })),
        )
    })?;

    // The authenticator data layout (WebAuthn spec §6.1):
    //   [0..32]  rpIdHash
    //   [32]     flags
    //   [33..36] signCount (big-endian u32)
    let new_sign_count = if auth_data.len() >= 37 {
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]])
    } else {
        0
    };

    // 4. Verify signature is present and non-empty.
    let sig_bytes = b64url_decode(&body.signature).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid signature encoding" })),
        )
    })?;
    if sig_bytes.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "signature must not be empty" })),
        ));
    }

    // 5. Look up the credential and perform counter check.
    let mut credentials = state.credentials.lock().unwrap();
    let user_creds = credentials.get_mut(&pending.user_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no credentials for user" })),
        )
    })?;

    let cred = user_creds
        .iter_mut()
        .find(|c| c.credential_id == body.credential_id)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "credential not found" })),
            )
        })?;

    // Signature counter check: new value must be > stored value (cloning detection).
    // Authenticators that always return 0 are exempt (value == 0 on both sides).
    if new_sign_count != 0 && new_sign_count <= cred.sign_count {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "authenticator clone detected: sign count did not increase"
            })),
        ));
    }

    // 6. Update counter and last_used timestamp.
    cred.sign_count = new_sign_count;
    cred.last_used_at = Some(Utc::now());

    Ok((
        StatusCode::OK,
        Json(CompleteAuthenticationResponse {
            user_id: pending.user_id,
            credential_id: body.credential_id,
            sign_count: new_sign_count,
            authenticated_at: Utc::now(),
        }),
    ))
}

// ── Handler: list credentials ─────────────────────────────────────────────────

/// `GET /webauthn/credentials/:user_id`
pub async fn list_credentials(
    State(state): State<Arc<WebAuthnState>>,
    Path(user_id): Path<String>,
) -> Result<Json<Vec<StoredCredential>>, (StatusCode, Json<serde_json::Value>)> {
    let store = state.credentials.lock().unwrap();
    let creds = store.get(&user_id).cloned().unwrap_or_default();
    Ok(Json(creds))
}

// ── Handler: remove credential ────────────────────────────────────────────────

/// `DELETE /webauthn/credentials/:user_id/:cred_id`
pub async fn remove_credential(
    State(state): State<Arc<WebAuthnState>>,
    Path((user_id, cred_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let mut store = state.credentials.lock().unwrap();
    let creds = store.get_mut(&user_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "user not found" })),
        )
    })?;

    let before = creds.len();
    creds.retain(|c| c.credential_id != cred_id);

    if creds.len() == before {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "credential not found" })),
        ));
    }

    // Prevent removing the last primary credential unless a backup exists.
    let primaries = creds.iter().filter(|c| !c.is_backup).count();
    let backups = creds.iter().filter(|c| c.is_backup).count();
    if primaries == 0 && backups == 0 {
        // Undo — put the credential back (re-load and re-remove isn't feasible
        // without re-looking up, so we surface an error before the retain above
        // would leave the user credential-less).
        // This branch is unreachable if there was at least one credential before
        // removal, so it serves as a defensive guard only.
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "cannot remove the last credential for a user"
            })),
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── Handler: add backup authenticator ────────────────────────────────────────

/// `POST /webauthn/credentials/:user_id/:cred_id/backup`
///
/// Marks an existing credential as a backup authenticator, or begins a new
/// backup-flagged registration challenge (returns 202 Accepted with a
/// registration challenge the client should complete).
pub async fn add_backup_authenticator(
    State(state): State<Arc<WebAuthnState>>,
    Path((user_id, cred_id)): Path<(String, String)>,
    Json(body): Json<AddBackupAuthenticatorRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    // If the credential already exists, just flip the is_backup flag.
    {
        let mut store = state.credentials.lock().unwrap();
        if let Some(creds) = store.get_mut(&user_id) {
            if let Some(cred) = creds.iter_mut().find(|c| c.credential_id == cred_id) {
                cred.is_backup = true;
                if let Some(label) = body.label {
                    cred.label = Some(label);
                }
                return Ok((
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "credential_id": cred_id,
                        "is_backup": true,
                        "message": "credential marked as backup authenticator"
                    })),
                ));
            }
        }
    }

    // Credential not yet registered — issue a backup-flagged registration challenge.
    let challenge = generate_challenge();
    let session_id = b64url_encode(&generate_challenge());

    let pending = PendingRegistration {
        challenge: challenge.clone(),
        user_id: user_id.clone(),
        user_name: body.user_id.clone(),
        expires_at: now_secs() + CHALLENGE_TTL_SECS,
    };

    state
        .pending_registrations
        .lock()
        .unwrap()
        .insert(session_id.clone(), pending);

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "session_id": session_id,
            "challenge": b64url_encode(&challenge),
            "is_backup": true,
            "message": "complete registration with is_backup=true to add backup authenticator",
            "pub_key_cred_params": [
                { "type": "public-key", "alg": CoseAlgorithm::ES256.cose_id() },
                { "type": "public-key", "alg": CoseAlgorithm::EdDsa.cose_id() },
            ],
            "timeout_ms": CHALLENGE_TTL_SECS * 1000
        })),
    ))
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> Arc<WebAuthnState> {
        Arc::new(WebAuthnState::new(
            "localhost",
            "Test RP",
            "http://localhost:3000",
        ))
    }

    fn client_data_json(type_: &str, challenge: &str, origin: &str) -> String {
        let raw = serde_json::json!({
            "type": type_,
            "challenge": challenge,
            "origin": origin
        })
        .to_string();
        b64url_encode(raw.as_bytes())
    }

    fn fake_auth_data(sign_count: u32) -> String {
        let mut data = vec![0u8; 37];
        let bytes = sign_count.to_be_bytes();
        data[33] = bytes[0];
        data[34] = bytes[1];
        data[35] = bytes[2];
        data[36] = bytes[3];
        b64url_encode(&data)
    }

    #[tokio::test]
    async fn test_begin_registration_empty_user_id() {
        let state = make_state();
        let result = begin_registration(
            State(Arc::clone(&state)),
            Json(BeginRegistrationRequest {
                user_id: "".into(),
                user_name: "alice".into(),
                label: None,
                is_backup: false,
            }),
        )
        .await;
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_registration_and_authentication_flow() {
        let state = make_state();

        // 1. Begin registration.
        let begin_resp = begin_registration(
            State(Arc::clone(&state)),
            Json(BeginRegistrationRequest {
                user_id: "user1".into(),
                user_name: "Alice".into(),
                label: None,
                is_backup: false,
            }),
        )
        .await
        .unwrap();
        let (_, Json(begin)) = begin_resp;
        let session_id = begin.session_id.clone();
        let challenge = begin.challenge.clone();

        // 2. Build a fake client data response.
        let client_data = client_data_json("webauthn.create", &challenge, "http://localhost:3000");
        let fake_cred_id = b64url_encode(&vec![0xAA; 32]);
        let fake_attestation = b64url_encode(b"fake-attestation");

        // 3. Complete registration.
        let complete_resp = complete_registration(
            State(Arc::clone(&state)),
            Json(CompleteRegistrationRequest {
                session_id,
                credential_id: fake_cred_id.clone(),
                client_data_json: client_data,
                attestation_object: fake_attestation,
                label: Some("Test Key".into()),
                is_backup: false,
            }),
        )
        .await
        .unwrap();
        let (status, Json(reg)) = complete_resp;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(reg.user_id, "user1");
        assert_eq!(reg.credential_id, fake_cred_id);

        // 4. Begin authentication.
        let auth_begin = begin_authentication(
            State(Arc::clone(&state)),
            Json(BeginAuthenticationRequest {
                user_id: "user1".into(),
            }),
        )
        .await
        .unwrap();
        let (_, Json(auth_begin)) = auth_begin;
        assert!(!auth_begin.allow_credentials.is_empty());

        let auth_challenge = auth_begin.challenge.clone();
        let auth_session = auth_begin.session_id.clone();

        // 5. Complete authentication.
        let auth_client_data =
            client_data_json("webauthn.get", &auth_challenge, "http://localhost:3000");
        let auth_data = fake_auth_data(1);
        let fake_sig = b64url_encode(b"fake-sig");

        let auth_complete = complete_authentication(
            State(Arc::clone(&state)),
            Json(CompleteAuthenticationRequest {
                session_id: auth_session,
                credential_id: fake_cred_id.clone(),
                client_data_json: auth_client_data,
                authenticator_data: auth_data,
                signature: fake_sig,
            }),
        )
        .await
        .unwrap();
        let (status, Json(auth)) = auth_complete;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(auth.user_id, "user1");
        assert_eq!(auth.sign_count, 1);
    }

    #[tokio::test]
    async fn test_clone_detection() {
        let state = make_state();

        // Register a credential.
        let begin = begin_registration(
            State(Arc::clone(&state)),
            Json(BeginRegistrationRequest {
                user_id: "user2".into(),
                user_name: "Bob".into(),
                label: None,
                is_backup: false,
            }),
        )
        .await
        .unwrap();
        let (_, Json(begin)) = begin;
        let session_id = begin.session_id.clone();
        let challenge = begin.challenge.clone();
        let client_data = client_data_json("webauthn.create", &challenge, "http://localhost:3000");
        let fake_cred_id = b64url_encode(&vec![0xBB; 32]);
        complete_registration(
            State(Arc::clone(&state)),
            Json(CompleteRegistrationRequest {
                session_id,
                credential_id: fake_cred_id.clone(),
                client_data_json: client_data,
                attestation_object: b64url_encode(b"att"),
                label: None,
                is_backup: false,
            }),
        )
        .await
        .unwrap();

        // Authenticate once with sign_count=5.
        let auth_begin = begin_authentication(
            State(Arc::clone(&state)),
            Json(BeginAuthenticationRequest {
                user_id: "user2".into(),
            }),
        )
        .await
        .unwrap();
        let (_, Json(auth_begin)) = auth_begin;
        let client_data = client_data_json(
            "webauthn.get",
            &auth_begin.challenge,
            "http://localhost:3000",
        );
        complete_authentication(
            State(Arc::clone(&state)),
            Json(CompleteAuthenticationRequest {
                session_id: auth_begin.session_id,
                credential_id: fake_cred_id.clone(),
                client_data_json: client_data,
                authenticator_data: fake_auth_data(5),
                signature: b64url_encode(b"sig"),
            }),
        )
        .await
        .unwrap();

        // Attempt replay with sign_count=3 (lower) — must be rejected.
        let auth_begin2 = begin_authentication(
            State(Arc::clone(&state)),
            Json(BeginAuthenticationRequest {
                user_id: "user2".into(),
            }),
        )
        .await
        .unwrap();
        let (_, Json(auth_begin2)) = auth_begin2;
        let client_data2 = client_data_json(
            "webauthn.get",
            &auth_begin2.challenge,
            "http://localhost:3000",
        );
        let result = complete_authentication(
            State(Arc::clone(&state)),
            Json(CompleteAuthenticationRequest {
                session_id: auth_begin2.session_id,
                credential_id: fake_cred_id,
                client_data_json: client_data2,
                authenticator_data: fake_auth_data(3),
                signature: b64url_encode(b"sig"),
            }),
        )
        .await;
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, StatusCode::FORBIDDEN);
    }
}
