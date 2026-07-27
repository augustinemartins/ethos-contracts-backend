use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::State,
    http::{HeaderValue, Method, StatusCode},
    middleware,
    routing::{delete, get, post},
    Json, Router,
};
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

use ethos_protocol_backend::{
    batching::{AdaptiveBatcher, BatchConfig},
    consensus::NodeCache,
    contract_version_check::{check_contract_version, parse_min_contract_version},
    custom_metrics::{
        aggregate_custom_metric, create_dashboard_share, get_shared_dashboard,
        list_custom_metrics, list_dashboard_templates, record_custom_metric, CustomMetricsStore,
    },
    db::{
        create_audit_store, create_event_store, create_share_store, create_share_token_store,
        create_vault_store, AppState, Db, PoolConfig,
    },
    cost_tracking::{allocate_cost, get_cost_report, record_cost_entry, CostState},
    degradation::{
        capability_fallback, list_capabilities, negotiate_capabilities, set_capability,
        DegradationState,
    },
    feature_flags::{evaluate_flag_handler, get_flag, list_flags, upsert_flag, FlagState},
    graphql::{build_schema, graphql_handler, graphql_playground},
    load_shedding::{admission_middleware, LoadMonitor, LoadShedder, SheddingConfig},
    metrics::Metrics,
    predictive_scaling::{
        self, ForecastModel, LoggingAutoscalerClient, PredictiveScaler, ScalingConfig,
    },
    priority::{PriorityConfig, PriorityEnforcer},
    routes, scheduler,
    streaming::{stream_events, stream_vaults},
    timeout_policy::{self, TimeoutState},
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

/// Prometheus text-format metrics for scraping, combining base counters
/// with load shedding (#128), adaptive batching (#131) and predictive
/// scaling (#130) metrics.
async fn metrics_handler(State(state): State<AppState>) -> String {
    let mut out = state.metrics.render();
    out.push_str(&state.load_shedder.render_prometheus());
    out.push_str(&state.batcher.render_prometheus());
    out.push_str(&state.scaler.render_prometheus());
    out
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
    let retry_state = RetryPolicyState::new();
    let bulkhead_registry = Arc::new(BulkheadRegistry::new(BulkheadConfig::default()));
    let timeout_state = TimeoutState::new();

    Router::new()
        // ── Health ──────────────────────────────────────────────────────────
        .route("/health", get(health_handler))
        .route("/health/consensus", get(consensus_health_handler))
        .route("/ready", get(ready_handler))
        .route("/metrics", get(metrics_handler))
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
        // ── Request prioritization / load shedding (#128, #129) ──────────────
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admission_middleware,
        ))
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

    // ── Request prioritization / load shedding / batching / scaling ──────────
    // (#128, #129, #130, #131)
    let metrics = Metrics::new();
    let priority_enforcer = Arc::new(PriorityEnforcer::new(PriorityConfig::from_env()));
    let load_shedder = Arc::new(LoadShedder::new(LoadMonitor::new(), SheddingConfig::from_env()));
    let batcher = Arc::new(AdaptiveBatcher::new(BatchConfig::from_env()));
    let scaler = Arc::new(PredictiveScaler::new(
        288, // 24h of history at a 5-minute sampling interval
        ForecastModel::default(),
        ScalingConfig::from_env(),
        Box::new(LoggingAutoscalerClient),
    ));

    let scaling_metrics = Arc::clone(&metrics);
    let scaling_scaler = Arc::clone(&scaler);
    tokio::spawn(async move {
        predictive_scaling::run(scaling_scaler, scaling_metrics, Duration::from_secs(300)).await;
    });

    let state = AppState {
        db,
        vault_store,
        event_store,
        audit_store: create_audit_store(),
        share_store: create_share_store(),
        share_token_store: create_share_token_store(),
        consensus,
        webhook_state,
        graphql_schema,
        metrics,
        priority_enforcer,
        load_shedder,
        batcher,
        scaler,
    };

    // ── Dynamic ACL admin routes ─────────────────────────────────────────
    // Kept on their own small router (own state) and merged in, since the
    // ACL store is independent of AppState/Db.
    let acl_store = AclStore::new();
    let acl_router = Router::new()
        .route("/admin/acl", post(create_acl_rule).get(list_acl_rules))
        .route("/admin/acl/:id", delete(delete_acl_rule))
        .route("/admin/acl/audit", get(acl_audit_trail))
        .with_state(acl_store);

    // ── Custom metrics + Grafana dashboard routes ────────────────────────
    let custom_metrics_store = CustomMetricsStore::new();
    let custom_metrics_router = Router::new()
        .route(
            "/metrics/custom",
            post(record_custom_metric).get(list_custom_metrics),
        )
        .route(
            "/metrics/custom/:name/aggregate",
            get(aggregate_custom_metric),
        )
        .route("/dashboards/templates", get(list_dashboard_templates))
        .route("/dashboards/share", post(create_dashboard_share))
        .route("/dashboards/shared/:token", get(get_shared_dashboard))
        .with_state(custom_metrics_store);

    // ── Anomaly detection routes ──────────────────────────────────────────
    let anomaly_store = AnomalyStore::new();
    let anomaly_router = Router::new()
        .route("/anomaly/observe", post(observe_metric))
        .route("/anomaly/alerts", get(list_alerts))
        .route("/anomaly/baseline/:metric", get(get_baseline))
        .with_state(anomaly_store);

    // ── Structured log parsing / search routes ───────────────────────────
    let log_store = LogStore::new();
    let log_router = Router::new()
        .route("/logs/ingest", post(ingest_logs))
        .route("/logs/search", get(search_logs))
        .with_state(log_store);

    let app = build_router(state)
        .merge(acl_router)
        .merge(custom_metrics_router)
        .merge(anomaly_router)
        .merge(log_router);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
