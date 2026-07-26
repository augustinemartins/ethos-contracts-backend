use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderValue, Method, StatusCode},
    routing::{delete, get, post},
    Json, Router,
};
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

use ethos_protocol_backend::{
    consensus::NodeCache,
    contract_version_check::{check_contract_version, parse_min_contract_version},
    db::{
        create_audit_store, create_event_store, create_share_store, create_share_token_store,
        create_vault_store, AppState, Db, PoolConfig,
    },
    graphql::{build_schema, graphql_handler, graphql_playground},
    retention, routes, scheduler, secret_rotation,
    streaming::{stream_events, stream_vaults},
    webhook::{delete_webhook, list_webhooks, register_webhook, WebhookState},
};

#[cfg(test)]
mod tests;

fn build_cors_layer() -> CorsLayer {
    let allowed_origins = std::env::var("ALLOWED_ORIGINS").unwrap_or_default();
    if allowed_origins.is_empty() {
        return CorsLayer::new();
    }

    let origins: Vec<HeaderValue> = allowed_origins
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(tower_http::cors::Any)
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// GET /api/encryption/keys — list all known encryption key versions (#101).
async fn encryption_keys_handler(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.db.list_encryption_key_versions() {
        Ok(versions) => Ok(Json(serde_json::json!({ "keys": versions }))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn ready_handler(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.db.check_connectivity() {
        Ok(()) => Ok(Json(serde_json::json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "database": "connected",
        }))),
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

async fn consensus_health_handler(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.consensus.check_and_resolve() {
        Ok(report) => {
            let status = if report.consistent { "ok" } else { "degraded" };
            Ok(Json(serde_json::json!({
                "status": status,
                "cache_consistent": report.consistent,
                "node_id": report.node_id,
                "strategy": report.strategy,
                "conflicts_detected": report.conflicts.len(),
                "conflicts_resolved": report.conflicts_resolved,
                "keys_checked": report.keys_checked,
            })))
        }
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        // ── Health ──────────────────────────────────────────────────────────
        .route("/health", get(health_handler))
        .route("/health/consensus", get(consensus_health_handler))
        .route("/ready", get(ready_handler))
        // ── Legacy reminder / subscription routes ────────────────────────────
        .route(
            "/api/vaults/:vault_id/reminder-preferences",
            post(routes::set_preferences)
                .get(routes::get_preferences)
                .delete(routes::delete_preferences),
        )
        .route(
            "/api/vaults/:vault_id/subscriptions",
            post(routes::set_subscription).delete(routes::delete_subscription),
        )
        .route(
            "/api/vaults/:vault_id/reminders",
            get(routes::list_vault_reminders),
        )
        .route(
            "/api/vaults/:vault_id/simulate-release",
            get(routes::simulate_release),
        )
        // ── Webhook routes (#65) ─────────────────────────────────────────────
        .route("/webhooks", post(register_webhook).get(list_webhooks))
        .route("/webhooks/:id", delete(delete_webhook))
        // ── GraphQL routes (#66) ─────────────────────────────────────────────
        .route("/graphql", post(graphql_handler))
        .route("/graphql/playground", get(graphql_playground))
        // ── Streaming routes (#67) ───────────────────────────────────────────
        .route("/stream/vaults", get(stream_vaults))
        .route("/stream/events", get(stream_events))
        // ── #100: Data Retention Policies ────────────────────────────────────
        .route(
            "/api/retention/policies",
            get(retention::list_policies),
        )
        .route(
            "/api/retention/policies/:data_type",
            get(retention::get_policy).put(retention::upsert_policy),
        )
        .route(
            "/api/retention/purge/:data_type",
            post(retention::trigger_purge),
        )
        .route(
            "/api/retention/deletion-log",
            get(retention::get_deletion_log),
        )
        .route(
            "/api/retention/exceptions/:data_type",
            get(retention::list_exceptions).post(retention::add_exception),
        )
        // ── #101: Encryption key version metadata ────────────────────────────
        .route(
            "/api/encryption/keys",
            get(encryption_keys_handler),
        )
        .route(
            "/api/secret-rotation/policies",
            get(secret_rotation::list_policies),
        )
        .route(
            "/api/secret-rotation/policies/:secret_type",
            get(secret_rotation::get_policy).put(secret_rotation::upsert_policy),
        )
        .route(
            "/api/secret-rotation/status",
            get(secret_rotation::list_statuses),
        )
        .route(
            "/api/secret-rotation/:secret_type/status",
            get(secret_rotation::get_status),
        )
        .route(
            "/api/secret-rotation/:secret_type/rotate",
            post(secret_rotation::record_rotation),
        )
        .route(
            "/api/secret-rotation/:secret_type/history",
            get(secret_rotation::rotation_history),
        )
        .layer(build_cors_layer())
        .with_state(state)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Check contract version before proceeding with server startup
    let min_contract_version =
        parse_min_contract_version(std::env::var("MIN_CONTRACT_VERSION").ok());

    let version_result = check_contract_version(
        || async {
            // TODO: replace with real Soroban client call when available
            // For now, this is a stub that returns Ok(1) so startup proceeds
            Ok::<u32, String>(1)
        },
        min_contract_version,
    )
    .await;

    tracing::info!("{}", version_result);

    if let Some(err) = &version_result.error {
        tracing::error!("Contract version check failed: {}", err);
        std::process::exit(1);
    }

    if !version_result.compatible {
        tracing::error!("{}", version_result);
        std::process::exit(1);
    }

    let pool_config = PoolConfig::from_env();
    tracing::info!(
        min = pool_config.min,
        max = pool_config.max,
        timeout_secs = pool_config.timeout_secs,
        "database pool configuration"
    );

    let db =
        Arc::new(Db::open_with_pool_config(":memory:", &pool_config).expect("failed to open db"));
    db.migrate().expect("migration failed");

    let consensus = NodeCache::from_env();
    tracing::info!(
        node_id = consensus.node_id(),
        strategy = ?consensus.strategy(),
        "consensus cache initialized"
    );

    let scheduler_db = Arc::clone(&db);
    tokio::spawn(async move {
        scheduler::run(scheduler_db).await;
    });

    let vault_store = create_vault_store();
    let event_store = create_event_store();
    let graphql_schema = build_schema(Arc::clone(&vault_store), Arc::clone(&event_store));

    let state = AppState {
        db,
        vault_store,
        event_store,
        audit_store: create_audit_store(),
        share_store: create_share_store(),
        share_token_store: create_share_token_store(),
        consensus,
        webhook_state: Arc::new(WebhookState::new()),
        graphql_schema,
    };

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
