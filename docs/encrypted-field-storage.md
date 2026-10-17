# Encrypted Field Storage (#101)

Ethos-Protocol encrypts sensitive database fields at rest using AES-256-GCM
authenticated encryption.  Each encrypted value carries its key version so
that multiple key versions can coexist during a rotation grace period.

## Sensitive fields

The following fields are encrypted before storage:

| Table                   | Column     | Reason                              |
|-------------------------|------------|-------------------------------------|
| `two_factor_config`     | `secret`   | TOTP seed — highly sensitive        |
| `two_factor_config`     | `phone`    | PII — phone number                  |
| `two_factor_config`     | `email`    | PII — email address                 |
| `reminder_preferences`  | `channels` | Contact details (email/phone/push)  |
| `unsubscribe_tokens`    | `owner`    | Owner identifier (email/phone)      |

## Wire format

Encrypted values are stored as a JSON object:

```json
{
  "ciphertext": "<base64(ciphertext || 16-byte tag)>",
  "nonce":      "<base64(12-byte random nonce)>",
  "key_version": 1
}
```

The ciphertext blob includes a 16-byte HMAC-SHA256-based authentication tag
appended after the ciphertext bytes.  Decryption verifies the tag first using
a constant-time comparison before returning plaintext.

## Key management

Keys are loaded from environment variables:

```
FIELD_ENCRYPTION_KEY_VERSION=1
FIELD_ENCRYPTION_KEY_1=<base64-encoded 32-byte key>
```

Generate a key:

```bash
openssl rand -base64 32
```

### Key rotation

1. Generate a new key and set `FIELD_ENCRYPTION_KEY_2=<new key>`.
2. Set `FIELD_ENCRYPTION_KEY_VERSION=2`.
3. Keep `FIELD_ENCRYPTION_KEY_1` in the environment during the grace period
   so that existing ciphertexts (version 1) can still be decrypted.
4. Migrate stored ciphertexts with the backfill job (see below), or let
   individual records lazily migrate via `FieldEncryptionEngine::rotate_field`
   on their next write.
5. Once all records are migrated, record the key retirement via
   `GET /api/encryption/keys` and remove `FIELD_ENCRYPTION_KEY_1`.

Key version metadata is tracked in the `encryption_key_versions` table.

### Backfill job

Rather than waiting for every record to be rewritten naturally, a background
job proactively re-encrypts records still on an old key version to
`active_version`, in batches:

```rust
let summary = encryption::run_backfill(
    &engine,
    &records,           // Vec<encryption::BackfillRecord>
    cursor,              // encryption::BackfillCursor, persisted between runs
    batch_size,          // e.g. 200
    rate_limit_delay,    // sleep between batches, e.g. 1s
    |batch| persist_updated_fields(batch),
).await;
```

- **Batching & rate limiting** — `run_backfill` processes `batch_size`
  records at a time and sleeps `rate_limit_delay` between batches, so a large
  backfill doesn't saturate the database with writes.
- **Resumability** — each batch reports a `next_cursor`. The caller persists
  it after applying that batch's updates, so a crash or restart mid-run
  resumes from the last completed batch instead of rescanning every record.
  `run_backfill_batch` is the single-batch primitive this loop is built on,
  and is what a resumed run calls directly with the saved cursor.
- **Already-current records** are detected by comparing `key_version` against
  `engine.active_version()` and skipped without re-encrypting.

The core batching, rate-limiting, and resumability logic lives in
`backend/src/encryption.rs` (`run_backfill_batch`, `run_backfill`) and is
exercised by that module's tests. The scheduler wiring
(`run_encryption_backfill_job` in `backend/src/scheduler.rs`) runs this
hourly, but the current schema stores `two_factor_config`, `reminder_preferences`,
and `unsubscribe_tokens` fields as plain columns rather than `EncryptedField`
JSON blobs (see "Sensitive fields" above), so there is not yet a live query
that lists records needing backfill — the scheduled run currently exercises
the job over an empty record set. Wiring in a real source of records is
tracked as follow-up work once those columns store `EncryptedField` values.

## API

```
GET /api/encryption/keys           — list all key versions and statuses
```

Response:

```json
[
  { "version": 1, "status": "retiring", "created_at": "...", "rotated_at": "..." },
  { "version": 2, "status": "active",   "created_at": "...", "rotated_at": null  }
]
```

## Implementation

The engine lives in `backend/src/encryption.rs`.  Key helpers:

```rust
let engine = FieldEncryptionEngine::from_env()?;

// Encrypt a value:
let field: EncryptedField = engine.encrypt("user@example.com")?;

// Decrypt:
let plaintext: String = engine.decrypt(&field)?;

// Rotate a single field to the new key version:
let (new_field, result) = engine.rotate_field(&field, 2)?;
```

## Development / test mode

The active `FIELD_ENCRYPTION_KEY_<N>` must be configured; if it is missing,
engine initialization fails. Missing older keys are skipped, but any older
versions still needed to decrypt stored values must remain configured. Outside
tests, the all-zero development key is rejected as insecure.
