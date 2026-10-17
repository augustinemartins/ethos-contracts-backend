use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use chrono::Utc;

use crate::{db::Db, error::ApiError, models::AuditLogEntry};

/// Axum middleware that logs every API request to the audit log.
pub async fn audit_middleware(
    State(db): State<Arc<Db>>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();

    // Skip internal routes to reduce noise and avoid recursion
    if path == "/health" || path == "/ready" || path.starts_with("/api/audit-logs") {
        return next.run(req).await;
    }

    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    let ip = extract_client_ip(req.headers(), peer_ip);
    let user_id = extract_user_id(req.headers());

    let response = next.run(req).await;
    let status = response.status();

    let result = if status.is_success() {
        "success"
    } else if status.is_server_error() {
        "error"
    } else {
        "failure"
    };

    // Only log API routes
    if path.starts_with("/api/") {
        let entry = AuditLogEntry {
            id: 0,
            timestamp: Utc::now(),
            user_id,
            action: method.to_string(),
            resource: path,
            result: result.to_string(),
            ip_address: ip,
            details: Some(serde_json::json!({
                "status_code": status.as_u16(),
            })),
        };

        if let Err(e) = db.insert_audit_log(&entry) {
            tracing::error!(error = %e, "failed to persist audit log entry");
        }
    }

    response
}

/// Helper: write a structured audit entry for state modifications.
pub fn log_state_modification(
    db: &Arc<Db>,
    action: &str,
    resource: &str,
    result: &str,
    headers: &HeaderMap,
    details: Option<serde_json::Value>,
) {
    let entry = AuditLogEntry {
        id: 0,
        timestamp: Utc::now(),
        user_id: extract_user_id(headers),
        action: action.to_string(),
        resource: resource.to_string(),
        result: result.to_string(),
        ip_address: extract_client_ip(headers, None),
        details,
    };
    if let Err(e) = db.insert_audit_log(&entry) {
        tracing::error!(error = %e, "failed to persist audit log entry");
    }
}

/// Check that the request carries a valid admin API key.
pub fn authorize_admin(headers: &HeaderMap) -> Result<(), ApiError> {
    let api_key = std::env::var("ADMIN_API_KEY").unwrap_or_default();
    if api_key.is_empty() {
        return Ok(());
    }
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match auth_header.strip_prefix("Bearer ") {
        Some(token) if token == api_key => Ok(()),
        _ => Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "valid admin API key required",
        )),
    }
}

pub fn extract_client_ip(headers: &HeaderMap, peer_ip: Option<IpAddr>) -> String {
    let trusted_proxies = std::env::var("TRUSTED_PROXY_IPS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|value| value.trim().parse::<IpAddr>().ok())
        .collect::<Vec<_>>();

    extract_client_ip_from_trusted_proxies(headers, peer_ip, &trusted_proxies)
}

fn extract_client_ip_from_trusted_proxies(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_proxies: &[IpAddr],
) -> String {
    let Some(peer_ip) = peer_ip else {
        return "unknown".to_string();
    };

    if trusted_proxies.contains(&peer_ip) {
        let forwarded = headers
            .get_all("x-forwarded-for")
            .iter()
            .map(|value| {
                value
                    .to_str()
                    .ok()?
                    .split(',')
                    .map(str::trim)
                    .map(str::parse::<IpAddr>)
                    .collect::<Result<Vec<_>, _>>()
                    .ok()
            })
            .collect::<Option<Vec<_>>>()
            .and_then(|chain| {
                chain
                    .into_iter()
                    .flatten()
                    .rev()
                    .find(|ip| !trusted_proxies.contains(ip))
            });
        if let Some(ip) = forwarded {
            return ip.to_string();
        }

        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
        {
            return ip.to_string();
        }
    }

    peer_ip.to_string()
}

fn extract_user_id(headers: &HeaderMap) -> String {
    headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_peer_cannot_spoof_client_ip_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.10".parse().unwrap());
        headers.insert("x-real-ip", "198.51.100.11".parse().unwrap());

        let client_ip = extract_client_ip_from_trusted_proxies(
            &headers,
            Some("203.0.113.1".parse().unwrap()),
            &["10.0.0.1".parse().unwrap()],
        );

        assert_eq!(client_ip, "203.0.113.1");
    }

    #[test]
    fn trusted_proxy_uses_first_untrusted_address_in_forwarded_chain() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.99, 192.0.2.45, 10.0.0.2"
                .parse()
                .unwrap(),
        );

        let client_ip = extract_client_ip_from_trusted_proxies(
            &headers,
            Some("10.0.0.1".parse().unwrap()),
            &["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()],
        );

        assert_eq!(client_ip, "192.0.2.45");
    }
}
