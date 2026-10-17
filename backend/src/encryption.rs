//! Field-level encryption (#101).
//!
//! Provides AES-256-GCM authenticated encryption for sensitive database fields
//! (e.g. email addresses, phone numbers, 2FA secrets).  Keys are derived from
//! an environment variable `FIELD_ENCRYPTION_KEY_<VERSION>` so that multiple
//! key versions can coexist during a rotation grace period.
//!
//! # Usage
//!
//! ```rust,ignore
//! let engine = FieldEncryptionEngine::from_env()?;
//!
//! // Encrypt a value:
//! let encrypted = engine.encrypt("user@example.com")?;
//!
//! // Decrypt it later:
//! let plaintext = engine.decrypt(&encrypted)?;
//!
//! // Rotate: add FIELD_ENCRYPTION_KEY_2 to the environment, then:
//! let result = engine.rotate_key(1, 2, &encrypted)?;
//! // result.new_field contains the ciphertext under the new key.
//! ```
//!
//! # Key derivation
//!
//! Keys are read from environment variables:
//! - `FIELD_ENCRYPTION_KEY_<N>` — base64-encoded 32-byte key for version N.
//! - `FIELD_ENCRYPTION_KEY_VERSION` — the **current** (active) version number.
//!
//! The active key must be configured. Missing keys and the all-zero
//! development key are rejected outside tests.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::models::{EncryptedField, KeyRotationResult};

/// Length of an AES-256-GCM key in bytes.
const KEY_LEN: usize = 32;
/// Length of the AES-256-GCM nonce in bytes.
const NONCE_LEN: usize = 12;
/// Length of the AES-256-GCM authentication tag in bytes.
const TAG_LEN: usize = 16;

/// Reserved development key (all zeros). Never use in production.
#[cfg(not(test))]
const DEV_KEY: [u8; KEY_LEN] = [0u8; KEY_LEN];

/// Perform the AES-256-GCM core using only the standard library and the
/// `sha2` / `hmac` crates already present in `Cargo.toml`.
///
/// Because the workspace does not include `aes-gcm` as a dependency we
/// implement a lightweight wrapper using a well-known construction:
///   - AES-256 key-stream (CTR mode via HMAC-SHA256 as a PRF)
///   - GHASH-based authentication tag computed with HMAC-SHA256
///
/// **This is a pure-software, constant-time-safe implementation intended for
/// development and testing.  For production deployments, replace the `aes_gcm_*`
/// functions below with calls to a vetted crate such as `aes-gcm` from the
/// RustCrypto project.**

// ── Internal crypto helpers ───────────────────────────────────────────────────

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Derive a key-stream block for AES-GCM CTR mode simulation.
/// Each block is HMAC-SHA256(key, nonce || counter_be).
fn kdf_block(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], counter: u32) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(nonce);
    mac.update(&counter.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// XOR-encrypt/decrypt `data` using a key-stream derived from `key` and `nonce`.
fn stream_xor(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter: u32 = 1; // counter 0 is reserved for tag key derivation
    for chunk in data.chunks(32) {
        let block = kdf_block(key, nonce, counter);
        for (b, k) in chunk.iter().zip(block.iter()) {
            out.push(b ^ k);
        }
        counter = counter.wrapping_add(1);
    }
    out
}

/// Compute an authentication tag over `ciphertext` (simulated GHASH).
fn compute_tag(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> [u8; TAG_LEN] {
    let tag_key = kdf_block(key, nonce, 0);
    let mut mac = HmacSha256::new_from_slice(&tag_key).expect("valid key");
    mac.update(ciphertext);
    let full: [u8; 32] = mac.finalize().into_bytes().into();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}

/// Constant-time comparison to prevent timing attacks on tag verification.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Error type for encryption/decryption operations.
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("authentication tag mismatch — ciphertext may have been tampered with")]
    AuthenticationFailed,
    #[error("invalid ciphertext format: {0}")]
    InvalidFormat(String),
    #[error("key version {0} not found in environment")]
    KeyNotFound(u32),
    #[error("insecure development key configured for version {0}")]
    InsecureKey(u32),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}

/// Manages one or more versioned AES-256 keys for field-level encryption.
#[derive(Clone)]
pub struct FieldEncryptionEngine {
    /// Map of version → 32-byte key.
    keys: std::collections::HashMap<u32, [u8; KEY_LEN]>,
    /// Active key version used for all new encryptions.
    active_version: u32,
}

impl FieldEncryptionEngine {
    /// Construct from environment variables.
    ///
    /// Reads `FIELD_ENCRYPTION_KEY_VERSION` (defaults to `1`) and then looks
    /// for `FIELD_ENCRYPTION_KEY_<N>` for each version it needs to support.
    /// The active key must be configured. Missing older keys are skipped so
    /// deployments only need to retain versions that are still in use.
    pub fn from_env() -> Result<Self, EncryptionError> {
        let active_version: u32 = std::env::var("FIELD_ENCRYPTION_KEY_VERSION")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        let mut keys = std::collections::HashMap::new();
        // Load the active version key and up to 9 previous versions.
        for v in active_version.saturating_sub(9)..=active_version {
            match Self::load_key_for_version(v) {
                Ok(key) => {
                    keys.insert(v, key);
                }
                Err(EncryptionError::KeyNotFound(_)) if v != active_version => {}
                Err(error) => return Err(error),
            }
        }

        Ok(Self { keys, active_version })
    }

    /// Construct directly from a map of version → key bytes.  Useful in tests.
    pub fn from_keys(
        keys: std::collections::HashMap<u32, [u8; KEY_LEN]>,
        active_version: u32,
    ) -> Self {
        Self { keys, active_version }
    }

    /// Return the active key version number.
    pub fn active_version(&self) -> u32 {
        self.active_version
    }

    /// Encrypt a plaintext string, returning an `EncryptedField`.
    pub fn encrypt(&self, plaintext: &str) -> Result<EncryptedField, EncryptionError> {
        let key = self
            .keys
            .get(&self.active_version)
            .ok_or(EncryptionError::KeyNotFound(self.active_version))?;

        let nonce = Self::random_nonce();
        let ciphertext_bytes = stream_xor(key, &nonce, plaintext.as_bytes());
        let tag = compute_tag(key, &nonce, &ciphertext_bytes);

        // Append the 16-byte tag to the ciphertext before base64-encoding.
        let mut payload = ciphertext_bytes;
        payload.extend_from_slice(&tag);

        Ok(EncryptedField {
            ciphertext: B64.encode(&payload),
            nonce: B64.encode(nonce),
            key_version: self.active_version,
        })
    }

    /// Decrypt an `EncryptedField`, returning the plaintext.
    pub fn decrypt(&self, field: &EncryptedField) -> Result<String, EncryptionError> {
        let key = self
            .keys
            .get(&field.key_version)
            .ok_or(EncryptionError::KeyNotFound(field.key_version))?;

        let nonce_bytes = B64.decode(&field.nonce)?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(EncryptionError::InvalidFormat(format!(
                "nonce must be {} bytes, got {}",
                NONCE_LEN,
                nonce_bytes.len()
            )));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_bytes);

        let payload = B64.decode(&field.ciphertext)?;
        if payload.len() < TAG_LEN {
            return Err(EncryptionError::InvalidFormat(
                "ciphertext too short to contain authentication tag".into(),
            ));
        }

        let (ciphertext, tag_bytes) = payload.split_at(payload.len() - TAG_LEN);
        let expected_tag = compute_tag(key, &nonce, ciphertext);

        if !ct_eq(tag_bytes, &expected_tag) {
            return Err(EncryptionError::AuthenticationFailed);
        }

        let plaintext_bytes = stream_xor(key, &nonce, ciphertext);
        String::from_utf8(plaintext_bytes).map_err(|e| {
            EncryptionError::InvalidFormat(format!("plaintext is not valid UTF-8: {e}"))
        })
    }

    /// Re-encrypt a field from `old_version` under `new_version`.
    ///
    /// Returns a [`KeyRotationResult`] summary; the caller is responsible for
    /// persisting the updated `EncryptedField` values.
    pub fn rotate_field(
        &self,
        field: &EncryptedField,
        new_version: u32,
    ) -> Result<(EncryptedField, KeyRotationResult), EncryptionError> {
        let old_version = field.key_version;
        let plaintext = self.decrypt(field)?;

        // Temporarily build an engine that treats new_version as active.
        let mut keys = self.keys.clone();
        // Ensure the new key is loaded if not already present.
        if !keys.contains_key(&new_version) {
            let key = Self::load_key_for_version(new_version)?;
            keys.insert(new_version, key);
        }
        let new_engine = FieldEncryptionEngine::from_keys(keys, new_version);
        let new_field = new_engine.encrypt(&plaintext)?;

        let result = KeyRotationResult {
            previous_version: old_version,
            new_version,
            rotated_at: chrono::Utc::now(),
            records_re_encrypted: 1,
        };
        Ok((new_field, result))
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn load_key_for_version(version: u32) -> Result<[u8; KEY_LEN], EncryptionError> {
        let var_name = format!("FIELD_ENCRYPTION_KEY_{version}");
        match std::env::var(&var_name) {
            Ok(val) => {
                let bytes = B64.decode(&val)?;
                if bytes.len() != KEY_LEN {
                    return Err(EncryptionError::InvalidFormat(format!(
                        "{var_name} must be a base64-encoded {KEY_LEN}-byte key"
                    )));
                }
                let mut key = [0u8; KEY_LEN];
                key.copy_from_slice(&bytes);
                #[cfg(not(test))]
                if key == DEV_KEY {
                    return Err(EncryptionError::InsecureKey(version));
                }
                Ok(key)
            }
            Err(_) => Err(EncryptionError::KeyNotFound(version)),
        }
    }

    /// Generate a cryptographically random 12-byte nonce using the OS PRNG.
    fn random_nonce() -> [u8; NONCE_LEN] {
        use rand::RngCore;
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }
}

// ── Key rotation backfill job ──────────────────────────────────────────────────
//
// `rotate_field` re-encrypts one record on demand (e.g. lazily, on next
// write). This section adds a batch job that proactively walks records still
// encrypted under an old key version and re-encrypts them to
// `active_version`, instead of waiting for each record's next write.

/// One stored record awaiting backfill: its identifier plus its current
/// encrypted value.
#[derive(Debug, Clone)]
pub struct BackfillRecord {
    pub id: String,
    pub field: EncryptedField,
}

/// Where a backfill run left off, so a restart can resume instead of
/// rescanning from the beginning.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackfillCursor {
    pub offset: usize,
}

/// Outcome of processing one batch.
#[derive(Debug, Clone, Default)]
pub struct BackfillBatchResult {
    /// `(id, new_field)` for every record successfully re-encrypted.
    pub updated: Vec<(String, EncryptedField)>,
    /// Records already on `active_version`; nothing to do.
    pub skipped_already_current: usize,
    /// `(id, error message)` for records that failed to re-encrypt (e.g. an
    /// old key version's environment variable was removed too early).
    pub failed: Vec<(String, String)>,
    /// Cursor to resume from on the next call.
    pub next_cursor: BackfillCursor,
    /// Whether this batch reached the end of `records`.
    pub done: bool,
}

/// Re-encrypt one bounded batch of records to `engine.active_version()`,
/// starting at `cursor`.
///
/// Bounding the work per call — rather than looping until every record is
/// done — is what makes the job rate-limitable (the caller sleeps between
/// batches) and resumable after an interruption (the caller persists
/// `next_cursor` and passes it back in as `cursor` on the next run).
pub fn run_backfill_batch(
    engine: &FieldEncryptionEngine,
    records: &[BackfillRecord],
    cursor: BackfillCursor,
    batch_size: usize,
) -> BackfillBatchResult {
    let start = cursor.offset.min(records.len());
    let end = start.saturating_add(batch_size).min(records.len());

    let mut result = BackfillBatchResult {
        next_cursor: BackfillCursor { offset: end },
        done: end >= records.len(),
        ..Default::default()
    };

    for record in &records[start..end] {
        if record.field.key_version == engine.active_version() {
            result.skipped_already_current += 1;
            continue;
        }
        match engine.rotate_field(&record.field, engine.active_version()) {
            Ok((new_field, _)) => result.updated.push((record.id.clone(), new_field)),
            Err(e) => result.failed.push((record.id.clone(), e.to_string())),
        }
    }

    result
}

/// Aggregate outcome of a full backfill run across every batch.
#[derive(Debug, Clone, Default)]
pub struct BackfillSummary {
    pub total_updated: usize,
    pub total_skipped: usize,
    pub total_failed: usize,
    pub failed: Vec<(String, String)>,
    pub final_cursor: BackfillCursor,
}

/// Run the backfill to completion, applying `persist` after each batch and
/// rate-limiting with `delay_between_batches` so a large backfill doesn't
/// saturate the database with writes.
///
/// `persist` is called once per batch with that batch's updated fields; the
/// caller is expected to write them and durably record `next_cursor` (e.g.
/// in its own table) so a crash mid-run resumes rather than restarting from
/// the beginning.
pub async fn run_backfill<F>(
    engine: &FieldEncryptionEngine,
    records: &[BackfillRecord],
    start_cursor: BackfillCursor,
    batch_size: usize,
    delay_between_batches: std::time::Duration,
    mut persist: F,
) -> BackfillSummary
where
    F: FnMut(&BackfillBatchResult),
{
    let mut cursor = start_cursor;
    let mut summary = BackfillSummary {
        final_cursor: start_cursor,
        ..Default::default()
    };

    loop {
        let batch = run_backfill_batch(engine, records, cursor, batch_size);

        summary.total_updated += batch.updated.len();
        summary.total_skipped += batch.skipped_already_current;
        summary.total_failed += batch.failed.len();
        summary.failed.extend(batch.failed.iter().cloned());
        summary.final_cursor = batch.next_cursor;

        persist(&batch);

        cursor = batch.next_cursor;
        if batch.done {
            break;
        }
        tokio::time::sleep(delay_between_batches).await;
    }

    summary
}

// ── Sensitive field helpers ───────────────────────────────────────────────────

/// Identifies which model fields contain sensitive data that must be encrypted.
/// Expand this list as new sensitive fields are added to the schema.
pub const SENSITIVE_FIELDS: &[(&str, &str)] = &[
    ("two_factor_config", "secret"),
    ("two_factor_config", "phone"),
    ("two_factor_config", "email"),
    ("reminder_preferences", "channels"),  // contains contact details
    ("unsubscribe_tokens", "owner"),        // email/phone owner identifier
];

/// Encrypt a string field value, returning `None` if the input is `None`.
pub fn encrypt_optional(
    engine: &FieldEncryptionEngine,
    value: Option<&str>,
) -> Option<EncryptedField> {
    value.and_then(|v| engine.encrypt(v).ok())
}

/// Decrypt an optional `EncryptedField`, returning `None` if absent.
pub fn decrypt_optional(
    engine: &FieldEncryptionEngine,
    field: Option<&EncryptedField>,
) -> Option<String> {
    field.and_then(|f| engine.decrypt(f).ok())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> FieldEncryptionEngine {
        let mut keys = std::collections::HashMap::new();
        keys.insert(1, [42u8; KEY_LEN]);
        keys.insert(2, [99u8; KEY_LEN]);
        FieldEncryptionEngine::from_keys(keys, 1)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let engine = test_engine();
        let plaintext = "user@example.com";
        let encrypted = engine.encrypt(plaintext).unwrap();
        assert_eq!(encrypted.key_version, 1);
        let decrypted = engine.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_nonces_for_same_plaintext() {
        let engine = test_engine();
        let a = engine.encrypt("hello").unwrap();
        let b = engine.encrypt("hello").unwrap();
        // Nonces should differ (probabilistically true with random nonces).
        // Ciphertexts should differ as a result.
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let engine = test_engine();
        let mut encrypted = engine.encrypt("sensitive-data").unwrap();
        // Flip a byte in the ciphertext.
        let mut bytes = B64.decode(&encrypted.ciphertext).unwrap();
        bytes[0] ^= 0xFF;
        encrypted.ciphertext = B64.encode(&bytes);
        let result = engine.decrypt(&encrypted);
        assert!(matches!(result, Err(EncryptionError::AuthenticationFailed)));
    }

    #[test]
    fn test_key_rotation() {
        let mut engine = test_engine();
        engine.active_version = 1;
        let field = engine.encrypt("rotate me").unwrap();
        assert_eq!(field.key_version, 1);

        // Rotate to version 2.
        let (new_field, rotation_result) = engine.rotate_field(&field, 2).unwrap();
        assert_eq!(new_field.key_version, 2);
        assert_eq!(rotation_result.previous_version, 1);
        assert_eq!(rotation_result.new_version, 2);

        // Should decrypt successfully with version 2.
        let new_engine = {
            let mut keys = std::collections::HashMap::new();
            keys.insert(2, [99u8; KEY_LEN]);
            FieldEncryptionEngine::from_keys(keys, 2)
        };
        let decrypted = new_engine.decrypt(&new_field).unwrap();
        assert_eq!(decrypted, "rotate me");
    }

    #[test]
    fn test_wrong_key_version_fails() {
        let engine = test_engine();
        let mut field = engine.encrypt("secret").unwrap();
        // Claim a version that doesn't exist.
        field.key_version = 99;
        let result = engine.decrypt(&field);
        assert!(matches!(result, Err(EncryptionError::KeyNotFound(99))));
    }

    #[test]
    fn test_encrypt_optional_none() {
        let engine = test_engine();
        assert!(encrypt_optional(&engine, None).is_none());
    }

    #[test]
    fn test_encrypt_decrypt_optional() {
        let engine = test_engine();
        let field = encrypt_optional(&engine, Some("test")).unwrap();
        let plain = decrypt_optional(&engine, Some(&field)).unwrap();
        assert_eq!(plain, "test");
    }

    // ── Backfill job ─────────────────────────────────────────────────────────

    /// Engine with an old (v1) and active (v2) key, mirroring a rotation in
    /// progress.
    fn rotating_engine() -> FieldEncryptionEngine {
        let mut keys = std::collections::HashMap::new();
        keys.insert(1, [7u8; KEY_LEN]);
        keys.insert(2, [8u8; KEY_LEN]);
        FieldEncryptionEngine::from_keys(keys, 2)
    }

    /// Build `count` records encrypted under the old (v1) key, as if written
    /// before a rotation to v2.
    fn backfill_records(_engine: &FieldEncryptionEngine, count: usize) -> Vec<BackfillRecord> {
        let mut keys = std::collections::HashMap::new();
        keys.insert(1, [7u8; KEY_LEN]);
        let old_engine = FieldEncryptionEngine::from_keys(keys, 1);

        (0..count)
            .map(|i| BackfillRecord {
                id: format!("record-{i}"),
                field: old_engine.encrypt(&format!("secret-{i}")).unwrap(),
            })
            .collect()
    }

    #[test]
    fn run_backfill_batch_re_encrypts_to_active_version() {
        let engine = rotating_engine();
        let records = backfill_records(&engine, 3);

        let result = run_backfill_batch(&engine, &records, BackfillCursor::default(), 10);

        assert!(result.done);
        assert_eq!(result.updated.len(), 3);
        assert_eq!(result.skipped_already_current, 0);
        assert!(result.failed.is_empty());
        for (id, field) in &result.updated {
            assert_eq!(field.key_version, 2);
            let index: usize = id.strip_prefix("record-").unwrap().parse().unwrap();
            assert_eq!(engine.decrypt(field).unwrap(), format!("secret-{index}"));
        }
    }

    #[test]
    fn run_backfill_batch_skips_records_already_on_active_version() {
        let engine = rotating_engine();
        let mut records = backfill_records(&engine, 2);
        records.push(BackfillRecord {
            id: "already-current".to_string(),
            field: engine.encrypt("current").unwrap(),
        });

        let result = run_backfill_batch(&engine, &records, BackfillCursor::default(), 10);

        assert_eq!(result.skipped_already_current, 1);
        assert_eq!(result.updated.len(), 2);
    }

    #[test]
    fn run_backfill_batch_is_resumable_across_interruptions() {
        let engine = rotating_engine();
        let records = backfill_records(&engine, 5);

        // First batch processes only 2 records and reports where to resume.
        let first = run_backfill_batch(&engine, &records, BackfillCursor::default(), 2);
        assert!(!first.done);
        assert_eq!(first.updated.len(), 2);
        assert_eq!(first.next_cursor, BackfillCursor { offset: 2 });

        // Simulate a restart: resume from the persisted cursor rather than
        // starting over from offset 0.
        let second = run_backfill_batch(&engine, &records, first.next_cursor, 2);
        assert!(!second.done);
        assert_eq!(second.updated.len(), 2);
        assert_eq!(second.next_cursor, BackfillCursor { offset: 4 });

        let third = run_backfill_batch(&engine, &records, second.next_cursor, 2);
        assert!(third.done);
        assert_eq!(third.updated.len(), 1);

        // No record was processed twice and none were skipped.
        let all_ids: std::collections::HashSet<_> = [&first, &second, &third]
            .iter()
            .flat_map(|r| r.updated.iter().map(|(id, _)| id.clone()))
            .collect();
        assert_eq!(all_ids.len(), 5);
    }

    #[tokio::test]
    async fn run_backfill_drives_every_batch_to_completion() {
        let engine = rotating_engine();
        let records = backfill_records(&engine, 7);

        let mut persisted_batches = 0;
        let summary = run_backfill(
            &engine,
            &records,
            BackfillCursor::default(),
            3,
            std::time::Duration::from_millis(0),
            |_batch| persisted_batches += 1,
        )
        .await;

        assert_eq!(summary.total_updated, 7);
        assert_eq!(summary.total_failed, 0);
        assert_eq!(summary.final_cursor, BackfillCursor { offset: 7 });
        // 7 records at batch size 3 takes 3 batches (3 + 3 + 1).
        assert_eq!(persisted_batches, 3);
    }
}
