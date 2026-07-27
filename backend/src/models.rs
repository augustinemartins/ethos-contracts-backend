use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── WebSocket authentication ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthClaims {
    pub sub: String,
    pub vault_ids: Vec<String>,
    pub exp: usize,
}

// ── Locale support ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Locale {
    En,
    Es,
    Fr,
    De,
}

// ── Notification models ──────────────────────────────────────────────────────

// ── Legacy reminder API models (axum + Db contract) ───────────────────────

/// Reminder notification channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Email,
    Sms,
    Push,
}

/// Reminder frequency.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Frequency {
    Once,
    Daily,
    Weekly,
    Hourly,
    Monthly,
}

pub type VaultNotificationPreferences = NotificationPreferences;

/// Persisted reminder preferences stored by `Db`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReminderPreferences {
    pub vault_id: u64,
    pub channels: Vec<Channel>,
    pub hours_before_expiry: u32,
    pub frequency: Frequency,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Request body for setting reminder preferences.
#[derive(Debug, Deserialize, Clone)]
pub struct SetPreferencesRequest {
    pub channels: Vec<Channel>,
    pub hours_before_expiry: u32,
    pub frequency: Frequency,
}

/// Notification type sent to a device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationType {
    ExpiryWarning,
    CheckInReminder,
    VaultReleased,
    VaultPaused,
    /// A vault passkey is approaching its expiry timestamp (#560).
    PasskeyExpiringSoon,
    /// A vault passkey has already expired (#560).
    PasskeyExpired,
}

/// Delivery status of a single notification attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    Sent,
    Failed,
    Retrying,
}

/// A single attempt entry within a reminder delivery log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryAttempt {
    pub attempt: u32,
    pub attempted_at: DateTime<Utc>,
    pub error: String,
}

/// Per-notification retry log stored by notification ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReminderDeliveryLog {
    pub notification_id: String,
    pub vault_id: String,
    pub owner: String,
    pub status: DeliveryStatus,
    pub attempts: Vec<DeliveryAttempt>,
    /// When the next retry should fire (None if not retrying).
    pub next_retry_at: Option<DateTime<Utc>>,
}

/// A registered device push token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceToken {
    pub owner: String,
    pub token: String,
    /// "ios" | "android" | "web"
    pub platform: String,
    pub registered_at: DateTime<Utc>,
}

/// Per-owner notification preferences (used by legacy scheduler/reminder engine).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationPreferences {
    pub owner: String,
    pub expiry_warning_enabled: bool,
    pub check_in_reminder_enabled: bool,
    pub vault_released_enabled: bool,
    /// Hours before expiry to send the warning (default 24).
    pub warning_hours_before: u64,
    pub locale: Option<Locale>,
    pub preferred_channel: Option<NotificationChannel>,
    pub fallback_channel: Option<NotificationChannel>,
    pub unsubscribed: bool,
}

impl Default for NotificationPreferences {
    fn default() -> Self {
        Self {
            owner: String::new(),
            expiry_warning_enabled: true,
            check_in_reminder_enabled: true,
            vault_released_enabled: true,
            warning_hours_before: 24,
            locale: None,
            preferred_channel: None,
            fallback_channel: None,
            unsubscribed: false,
        }
    }
}

// ── Unsubscribe support (#828) ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsubscribeToken {
    pub token: String,
    pub owner: String,
    pub created_at: DateTime<Utc>,
}

// ── Channel fallback delivery log (#827) ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelDeliveryLog {
    pub notification_id: String,
    pub channel: NotificationChannel,
    pub status: DeliveryStatus,
    pub attempted_at: DateTime<Utc>,
    pub error: Option<String>,
}

/// A scheduled notification (pending delivery).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledNotification {
    pub id: String,
    pub vault_id: String,
    pub owner: String,
    pub notification_type: NotificationType,
    /// Unix timestamp when this should fire.
    pub scheduled_at: DateTime<Utc>,
    pub status: DeliveryStatus,
    pub max_retry_attempts: u32,
    pub sent_at: Option<DateTime<Utc>>,
    /// Set for `PasskeyExpiringSoon` / `PasskeyExpired` notifications — identifies
    /// which passkey this notification is about (#560).
    pub passkey_hash: Option<String>,
    /// Approximate hours remaining until expiry at scheduling time, used to
    /// populate the notification body (#560).
    pub ttl_hours: Option<u64>,
}

/// Delivery record written after each send attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryRecord {
    pub notification_id: String,
    pub vault_id: String,
    pub owner: String,
    pub notification_type: NotificationType,
    pub status: DeliveryStatus,
    pub sent_at: DateTime<Utc>,
    /// FCM message ID on success, error string on failure.
    pub provider_response: String,
}

/// Request body for `POST /notifications/register`.
#[derive(Debug, Deserialize)]
pub struct RegisterTokenRequest {
    pub owner: String,
    pub token: String,
    pub platform: String,
}

/// Request body for `PUT /notifications/preferences`.
#[derive(Debug, Deserialize)]
pub struct UpdatePreferencesRequest {
    pub owner: String,
    pub expiry_warning_enabled: Option<bool>,
    pub check_in_reminder_enabled: Option<bool>,
    pub vault_released_enabled: Option<bool>,
    pub warning_hours_before: Option<u64>,
    pub locale: Option<Locale>,
}

// ── Existing models (unchanged) ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub id: String,
    pub owner: String,
    pub beneficiary: String,
    pub balance: i128,
    pub check_in_interval: u64,
    pub last_check_in: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub status: VaultStatus,
    pub ttl_remaining: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum VaultStatus {
    Active,
    Expired,
    Released,
    Paused,
}

// ── TTL Insurance models ───────────────────────────────────────────────────

/// TTL insurance policy parameters purchased by a vault owner.
///
/// When enabled, the backend scheduler can automatically extend TTL once the
/// owner is considered inactive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlInsurancePolicy {
    /// Vault id (matches `Vault.id` semantics in this backend).
    pub vault_id: u64,
    /// How much TTL to extend when triggered.
    pub extension_seconds: u64,
    /// Consider the owner inactive if no proof-of-life/check-in was recorded
    /// within this window.
    pub inactivity_threshold_seconds: u64,
    /// Whether this policy is currently active.
    pub enabled: bool,
    pub purchased_at: DateTime<Utc>,
    pub last_extended_at: Option<DateTime<Utc>>,
}

/// Persisted owner activity signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerActivity {
    pub owner_id: u64,
    pub last_active_at: DateTime<Utc>,
}

/// POST body to purchase/enable a TTL insurance policy.
#[derive(Debug, Deserialize, Clone)]
pub struct PurchaseTtlInsuranceRequest {
    pub extension_seconds: u64,
    pub inactivity_threshold_seconds: u64,
}

/// POST body to record owner activity (proof-of-life).
#[derive(Debug, Deserialize, Clone)]
pub struct RecordOwnerActivityRequest {
    pub owner_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEvent {
    pub vault_id: String,
    pub event_type: EventType,
    pub timestamp: DateTime<Utc>,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    CheckIn,
    TtlUpdate,
    StatusChange,
    Deposit,
    Withdrawal,
    Release,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchQuery {
    pub owner: Option<String>,
    pub beneficiary: Option<String>,
    pub status: Option<VaultStatus>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResult {
    pub vaults: Vec<Vault>,
    pub total: u32,
    pub page: u32,
    pub limit: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComparisonResult {
    pub vaults: Vec<Vault>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportData {
    pub vault: Vault,
    pub history: Vec<VaultEvent>,
    pub audit_log: Vec<AuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub actor: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebSocketMessage {
    pub message_type: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub vault_id: String,
    pub owner: String,
    pub beneficiary: String,
    pub report_generated_at: DateTime<Utc>,
    pub fund_movements: Vec<FundMovement>,
    pub beneficiary_changes: Vec<BeneficiaryChange>,
    pub ttl_history: Vec<TtlEvent>,
    pub total_deposits: i128,
    pub total_withdrawals: i128,
    pub current_balance: i128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FundMovement {
    pub timestamp: DateTime<Utc>,
    pub movement_type: String,
    pub amount: i128,
    pub balance_after: i128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BeneficiaryChange {
    pub timestamp: DateTime<Utc>,
    pub old_beneficiary: String,
    pub new_beneficiary: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TtlEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub ttl_remaining: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub check_in_interval: u64,
    pub recommended_for: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultTemplateList {
    pub templates: Vec<VaultTemplate>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateVaultFromTemplate {
    pub template_id: String,
    pub owner: String,
    pub beneficiary: String,
}

// ── Task 1: Analytics ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultAnalytics {
    pub total_vaults: u64,
    pub active_vaults: u64,
    pub average_ttl_seconds: f64,
    pub release_rate: f64, // fraction of vaults that are Released
    pub time_series: Vec<TimeSeriesPoint>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub date: String, // ISO-8601 date (YYYY-MM-DD)
    pub vaults_created: u64,
    pub vaults_released: u64,
}

// ── Per-Vault Analytics (#959) ───────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultDetailAnalytics {
    pub vault_id: String,
    pub ttl_history: Vec<TtlHistoryPoint>,
    pub check_in_frequency: CheckInFrequency,
    pub withdrawal_trends: WithdrawalTrends,
    pub beneficiary_status: BeneficiaryStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TtlHistoryPoint {
    pub date: String,
    pub ttl_remaining_seconds: u64,
    pub event: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckInFrequency {
    pub average_interval_seconds: u64,
    pub total_check_ins: u64,
    pub next_deadline: String,
    pub days_until_deadline: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WithdrawalTrends {
    pub total_withdrawals: i128,
    pub withdrawal_count: u64,
    pub average_withdrawal_amount: f64,
    pub last_withdrawal_date: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BeneficiaryStatus {
    pub beneficiary_address: String,
    pub is_active: bool,
    pub vault_status: String,
    pub can_receive_funds: bool,
}

// ── Task 2: Backup & Recovery ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBackup {
    pub backup_id: String,
    pub vault_id: String,
    pub created_at: DateTime<Utc>,
    /// AES-GCM encrypted JSON of the vault state (base64-encoded)
    pub encrypted_payload: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RestoreRequest {
    pub backup_id: String,
    /// The same key used during backup (base64-encoded 32-byte key)
    pub encryption_key: String,
}

// ── Task 3: Sharing & Collaboration ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SharePermission {
    ViewOnly,
    Edit,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultShare {
    pub share_id: String,
    pub vault_id: String,
    pub shared_with: String, // address or email
    pub permission: SharePermission,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShareRequest {
    pub shared_with: String,
    pub permission: SharePermission,
}

// ── Share tokens (temporary access tokens for read-only sharing) ─────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareToken {
    pub token: String,
    pub share_id: String,
    pub vault_id: String,
    pub shared_with: String,
    pub permission: SharePermission,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Debug, Deserialize)]
pub struct GenerateTokenRequest {
    pub shared_with: String,
    pub permission: Option<SharePermission>,
    /// Seconds until the token expires (default 604800 = 7 days).
    pub expiry_seconds: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShareTokenResponse {
    pub share: VaultShare,
    pub token: ShareToken,
    pub access_url: String,
}

#[derive(Debug, Deserialize)]
pub struct RevokeTokenRequest {
    pub token: String,
}

// ── Task 4: Notification Preferences ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    Email,
    Sms,
    Push,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationFrequency {
    Daily,
    Weekly,
    Monthly,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NotificationPreferencesRequest {
    pub channels: Vec<NotificationChannel>,
    pub frequency: NotificationFrequency,
}

// ── Vault Notification Subscription System ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionChannel {
    Email,
    Sms,
    Webhook,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionFrequency {
    Once,
    Daily,
    Weekly,
    Hourly,
    Monthly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subscription {
    pub vault_id: u64,
    pub owner: String,
    pub channels: Vec<SubscriptionChannel>,
    pub frequency: SubscriptionFrequency,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SetSubscriptionRequest {
    pub owner: String,
    pub channels: Vec<SubscriptionChannel>,
    pub frequency: SubscriptionFrequency,
}

// ── Idempotency Key support (#825) ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    pub key: String,
    pub response_body: String,
    pub status_code: u16,
    pub created_at: DateTime<Utc>,
}

// ── Release Simulator models ─────────────────────────────────────────────────

/// The scenario to simulate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioType {
    /// Owner never checks in again — release is immediate at TTL expiry.
    NoCheckIns,
    /// Owner checks in consistently at their configured interval.
    ConsistentCheckIns,
    /// Owner misses one or more specific check-in dates before stopping.
    MissedCheckInDates,
}

impl std::fmt::Display for ScenarioType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScenarioType::NoCheckIns => write!(f, "no_check_ins"),
            ScenarioType::ConsistentCheckIns => write!(f, "consistent_check_ins"),
            ScenarioType::MissedCheckInDates => write!(f, "missed_check_in_dates"),
        }
    }
}

/// Query parameters for the simulate-release endpoint.
#[derive(Debug, Deserialize)]
pub struct SimulateReleaseQuery {
    /// Comma-separated list of scenarios to run.
    /// e.g. `scenarios=no_check_ins,consistent_check_ins`
    /// Defaults to all three scenarios if omitted.
    pub scenarios: Option<String>,
    /// For `missed_check_in_dates`: number of consecutive missed check-ins
    /// before the owner stops (defaults to 1).
    pub missed_count: Option<u32>,
}

/// Projected outcome for a single scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioResult {
    /// Which scenario this result belongs to.
    pub scenario: ScenarioType,
    /// Human-readable description of the scenario.
    pub description: String,
    /// Projected UTC timestamp when the vault will release.
    pub projected_release_at: DateTime<Utc>,
    /// Seconds from now until the projected release.
    pub seconds_until_release: i64,
    /// Confidence level: "high", "medium", or "low".
    pub confidence: String,
    /// Optional extra notes about this scenario's assumptions.
    pub notes: String,
}

/// Response body for GET /api/vaults/{id}/simulate-release.
#[derive(Debug, Serialize, Deserialize)]
pub struct SimulateReleaseResponse {
    pub vault_id: String,
    /// Current TTL remaining in seconds (None if already expired/released).
    pub current_ttl_remaining: Option<u64>,
    /// The vault's configured check-in interval in seconds.
    pub check_in_interval: u64,
    /// Timestamp of the last recorded check-in.
    pub last_check_in: DateTime<Utc>,
    /// Simulation results, one per requested scenario.
    pub scenarios: Vec<ScenarioResult>,
    /// When this simulation was generated.
    pub simulated_at: DateTime<Utc>,
}

// ── Audit Log persistence (#961) ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub action: String,
    pub resource: String,
    pub result: String,
    pub ip_address: String,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AuditLogQuery {
    pub user_id: Option<String>,
    pub action: Option<String>,
    pub resource: Option<String>,
    pub result: Option<String>,
    pub after: Option<DateTime<Utc>>,
    pub before: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ── Cache layer models ───────────────────────────────────────────────────────

/// Lightweight read-projection of a Vault, cached separately from the full
/// `Vault` struct to reduce allocation when only summary data is needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSummary {
    pub vault_id: String,
    pub owner: String,
    pub status: VaultStatus,
    pub ttl_remaining: Option<u64>,
    pub balance: i128,
}

impl From<&Vault> for VaultSummary {
    fn from(v: &Vault) -> Self {
        Self {
            vault_id: v.id.clone(),
            owner: v.owner.clone(),
            status: v.status.clone(),
            ttl_remaining: v.ttl_remaining,
            balance: v.balance,
        }
    }
}

/// Response body returned by `POST /api/cache/invalidate/{vault_id}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct CacheInvalidateResponse {
    pub vault_id: String,
    pub invalidated: bool,
}

// ── 2FA models (#965) ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TwoFactorMethod {
    Totp,
    Sms,
    Email,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorConfig {
    pub vault_id: String,
    pub method: TwoFactorMethod,
    pub enabled: bool,
    pub secret: Option<String>,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Enable2FARequest {
    pub method: TwoFactorMethod,
    pub phone: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Verify2FARequest {
    pub otp: String,
}

#[derive(Debug, Serialize)]
pub struct Enable2FAResponse {
    pub vault_id: String,
    pub method: TwoFactorMethod,
    pub secret: Option<String>,
    pub provisioning_uri: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TwoFactorStatusResponse {
    pub vault_id: String,
    pub enabled: bool,
    pub method: Option<TwoFactorMethod>,
    pub verified: bool,
    pub phone: Option<String>,
    pub email: Option<String>,
}

// ── #69: Multi-Tenancy Support ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTenantRequest {
    pub name: String,
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantBilling {
    pub tenant_id: String,
    pub monthly_charge: i128,
    pub billing_cycle_start: DateTime<Utc>,
    pub billing_cycle_end: DateTime<Utc>,
    pub total_vaults: u32,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TenantContext {
    pub tenant_id: String,
    pub user_id: String,
}

// ── #70: Real-Time Collaboration Features ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialUpdate {
    pub id: String,
    pub vault_id: String,
    pub user_id: String,
    pub field: String,
    pub old_value: serde_json::Value,
    pub new_value: serde_json::Value,
    pub timestamp: DateTime<Utc>,
    pub operation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationalTransform {
    pub id: String,
    pub vault_id: String,
    pub user_id: String,
    pub operation: String,
    pub position: u32,
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictResolution {
    pub conflict_id: String,
    pub vault_id: String,
    pub update1_id: String,
    pub update2_id: String,
    pub resolution_strategy: String,
    pub resolved_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPresence {
    pub user_id: String,
    pub vault_id: String,
    pub status: String,
    pub last_seen: DateTime<Utc>,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborativeSession {
    pub session_id: String,
    pub vault_id: String,
    pub created_at: DateTime<Utc>,
    pub participants: Vec<String>,
    pub is_active: bool,
}

// ── #71: Advanced Search with Full-Text Capabilities ──────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullTextSearchQuery {
    pub query: String,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub filters: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchFacet {
    pub name: String,
    pub values: Vec<FacetValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacetValue {
    pub value: String,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullTextSearchResult {
    pub id: String,
    pub vault_id: String,
    pub title: String,
    pub snippet: String,
    pub relevance_score: f32,
    pub matched_fields: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FullTextSearchResponse {
    pub results: Vec<FullTextSearchResult>,
    pub total: u32,
    pub facets: Vec<SearchFacet>,
    pub query_time_ms: u64,
}

// ── CAPTCHA / Suspicious-Activity models (#97) ───────────────────────────────

/// An issued CAPTCHA challenge, stored server-side until verified or expired.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptchaChallenge {
    /// Unique challenge identifier (UUID v4).
    pub id: String,
    /// Opaque server-generated token bound to this challenge.
    pub token: String,
    /// Wall-clock expiry; challenges are invalid after this instant.
    pub expires_at: DateTime<Utc>,
    /// reCAPTCHA site key sent to the client so it can render the widget.
    pub site_key: String,
}

/// Request body for `POST /captcha/verify`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaptchaVerifyRequest {
    /// The `CaptchaChallenge.id` issued by `/captcha/challenge`.
    pub challenge_id: String,
    /// The g-recaptcha-response token submitted by the user's browser.
    pub captcha_token: String,
    /// Caller's own session / bearer token (used to mint a new session on
    /// successful verification).
    pub user_token: String,
}

/// Response body for `POST /captcha/verify`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptchaVerifyResponse {
    /// Whether the CAPTCHA was successfully verified.
    pub verified: bool,
    /// New short-lived session token issued on success (`None` on failure).
    pub session_token: Option<String>,
    /// Human-readable status message.
    pub message: String,
}

/// A user/IP combination that has been explicitly trusted and is exempt from
/// CAPTCHA challenges until `trusted_until`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedUser {
    /// Application-level user identifier.
    pub user_id: String,
    /// IP address or CIDR block that is trusted.
    pub ip: String,
    /// After this instant the trust entry is no longer valid.
    pub trusted_until: DateTime<Utc>,
}

/// A detected suspicious-activity event used by the rate-based CAPTCHA trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousActivityEvent {
    /// Source IP address.
    pub ip: String,
    /// Optionally identifies the authenticated user behind the request.
    pub user_id: Option<String>,
    /// Category of event (e.g. `"login_attempt"`, `"vault_create"`).
    pub event_type: String,
    /// Number of events observed within `window_start..now`.
    pub count: u32,
    /// Start of the observation window.
    pub window_start: DateTime<Utc>,
}

/// Request body for `POST /admin/captcha/trusted-users`.
#[derive(Debug, Deserialize)]
pub struct AddTrustedUserRequest {
    pub user_id: String,
    pub ip: String,
    /// Seconds from now until the trust entry expires (default: 86 400 = 1 day).
    pub trust_duration_secs: Option<u64>,
}

// ── IP Reputation models (#96) ────────────────────────────────────────────────

/// Risk level derived from an IP's abuse confidence score.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Reputation score for a single IP address, optionally sourced from AbuseIPDB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputationScore {
    /// The IP address that was checked.
    pub ip: String,
    /// Abuse confidence score in the range `0.0..=100.0`.
    pub score: f64,
    /// Derived risk classification.
    pub risk_level: RiskLevel,
    /// Whether the IP is currently matched by a local block rule.
    pub is_blocked: bool,
    /// Wall-clock instant at which the check was last performed.
    pub last_checked: DateTime<Utc>,
    /// Data source (e.g. `"abuseipdb"`, `"stub"`, `"disabled"`).
    pub source: String,
    /// Raw response payload from the upstream provider (or a stub object).
    pub details: serde_json::Value,
}

/// A manually configured IP block rule stored in the in-memory rule list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBlockRule {
    /// UUID v4 identifier for this rule.
    pub id: String,
    /// Exact IP address or `/24` subnet prefix (e.g. `"192.168.1"`).
    pub ip_pattern: String,
    /// Human-readable reason for the block.
    pub reason: String,
    /// When this rule was created.
    pub created_at: DateTime<Utc>,
    /// Optional expiry; `None` means the rule never expires.
    pub expires_at: Option<DateTime<Utc>>,
    /// Identity of the admin who created the rule (derived from the Bearer token).
    pub created_by: String,
}

/// Request body for `POST /admin/ip-reputation/block`.
#[derive(Debug, Deserialize)]
pub struct IpBlockRequest {
    /// Exact IP or `/24` prefix to block.
    pub ip_pattern: String,
    /// Reason for the block (required).
    pub reason: String,
    /// If provided, the rule expires after this many hours.
    pub expires_in_hours: Option<u32>,
}

/// Global configuration for the IP reputation subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputationConfig {
    /// When `false`, all reputation checks return a stub `Low` score without
    /// calling any external API.
    pub check_enabled: bool,
    /// Abuse confidence score threshold above which an IP is considered `High`
    /// risk. Defaults to `50`.
    pub block_threshold: u8,
    /// Maximum age (in days) of data to consider when querying AbuseIPDB.
    pub max_age_days: u32,
}

impl Default for IpReputationConfig {
    fn default() -> Self {
        Self {
            check_enabled: true,
            block_threshold: 50,
            max_age_days: 90,
        }
    }
}

/// Request body for `POST /ip-reputation/check`.
#[derive(Debug, Deserialize)]
pub struct IpReputationCheckRequest {
    /// Optional explicit IP to check. Falls back to `X-Forwarded-For` /
    /// `X-Real-IP` headers when absent.
    pub ip: Option<String>,
}

// ── Compliance Audit Report models (#99) ─────────────────────────────────────

/// Pass/fail/warning status for a single compliance check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    Pass,
    Fail,
    Warning,
    NotApplicable,
}

impl std::fmt::Display for ComplianceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceStatus::Pass => write!(f, "pass"),
            ComplianceStatus::Fail => write!(f, "fail"),
            ComplianceStatus::Warning => write!(f, "warning"),
            ComplianceStatus::NotApplicable => write!(f, "not_applicable"),
        }
    }
}

/// A single evaluated compliance control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheck {
    /// Dot-separated identifier, e.g. `"gdpr.data_minimisation"`.
    pub id: String,
    /// Human-readable control name.
    pub name: String,
    /// Compliance framework this check belongs to (`"GDPR"`, `"SOC2"`,
    /// `"ISO27001"`).
    pub framework: String,
    /// Evaluation result.
    pub status: ComplianceStatus,
    /// Explanation of what was checked and what was found.
    pub description: String,
    /// Actionable guidance when `status` is `Fail` or `Warning`; empty when
    /// `Pass` or `NotApplicable`.
    pub remediation: String,
}

/// A complete compliance audit report for the current deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAuditReport {
    /// ISO-8601 timestamp of report generation.
    pub generated_at: DateTime<Utc>,
    /// Total number of checks evaluated.
    pub total_checks: usize,
    /// Number of checks that passed.
    pub passed: usize,
    /// Number of checks that failed.
    pub failed: usize,
    /// Number of checks with warnings.
    pub warnings: usize,
    /// Number of checks marked not applicable.
    pub not_applicable: usize,
    /// Individual check results.
    pub checks: Vec<ComplianceCheck>,
    /// Placeholder for a PDF export (see `generate_pdf_stub`).
    pub pdf_stub: serde_json::Value,
}

/// Outer wrapper returned by `GET /admin/compliance-report`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReportResponse {
    pub report: ComplianceAuditReport,
}
