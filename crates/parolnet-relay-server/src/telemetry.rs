//! Client-reported telemetry counters + POST /client/telemetry handler.

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Deserialize)]
pub struct TelemetryEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    #[allow(dead_code)]
    pub ts: u64,
    #[allow(dead_code)]
    pub meta: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct TelemetryBatch {
    #[allow(dead_code)]
    pub ts: u64,
    pub events: Vec<TelemetryEvent>,
}

pub struct ClientStats {
    pub wasm_load_success: AtomicU64,
    pub wasm_load_fail: AtomicU64,
    pub relay_connects: AtomicU64,
    pub relay_disconnects: AtomicU64,
    pub webrtc_success: AtomicU64,
    pub webrtc_fail: AtomicU64,
    pub messages_sent: AtomicU64,
    pub messages_received: AtomicU64,
    pub sessions_established: AtomicU64,
    pub errors: AtomicU64,
    pub total_batches: AtomicU64,
}

impl ClientStats {
    pub fn new() -> Self {
        Self {
            wasm_load_success: AtomicU64::new(0),
            wasm_load_fail: AtomicU64::new(0),
            relay_connects: AtomicU64::new(0),
            relay_disconnects: AtomicU64::new(0),
            webrtc_success: AtomicU64::new(0),
            webrtc_fail: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            sessions_established: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            total_batches: AtomicU64::new(0),
        }
    }

    #[cfg(feature = "analytics")]
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"wasm_load_success":{},"wasm_load_fail":{},"relay_connects":{},"relay_disconnects":{},"webrtc_success":{},"webrtc_fail":{},"messages_sent":{},"messages_received":{},"sessions_established":{},"errors":{},"total_batches":{}}}"#,
            self.wasm_load_success.load(Ordering::Relaxed),
            self.wasm_load_fail.load(Ordering::Relaxed),
            self.relay_connects.load(Ordering::Relaxed),
            self.relay_disconnects.load(Ordering::Relaxed),
            self.webrtc_success.load(Ordering::Relaxed),
            self.webrtc_fail.load(Ordering::Relaxed),
            self.messages_sent.load(Ordering::Relaxed),
            self.messages_received.load(Ordering::Relaxed),
            self.sessions_established.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
            self.total_batches.load(Ordering::Relaxed),
        )
    }
}

pub async fn handle_telemetry(
    client_stats: Arc<ClientStats>,
    Json(batch): Json<TelemetryBatch>,
) -> impl IntoResponse {
    if batch.events.len() > 500 {
        return StatusCode::BAD_REQUEST;
    }

    client_stats.total_batches.fetch_add(1, Ordering::Relaxed);

    for event in &batch.events {
        match event.event_type.as_str() {
            "wasm_load_success" => {
                client_stats
                    .wasm_load_success
                    .fetch_add(1, Ordering::Relaxed);
            }
            "wasm_load_fail" => {
                client_stats.wasm_load_fail.fetch_add(1, Ordering::Relaxed);
            }
            "relay_connect" => {
                client_stats.relay_connects.fetch_add(1, Ordering::Relaxed);
            }
            "relay_disconnect" => {
                client_stats
                    .relay_disconnects
                    .fetch_add(1, Ordering::Relaxed);
            }
            "webrtc_connect_success" => {
                client_stats.webrtc_success.fetch_add(1, Ordering::Relaxed);
            }
            "webrtc_connect_fail" => {
                client_stats.webrtc_fail.fetch_add(1, Ordering::Relaxed);
            }
            "message_sent" => {
                client_stats.messages_sent.fetch_add(1, Ordering::Relaxed);
            }
            "message_received" => {
                client_stats
                    .messages_received
                    .fetch_add(1, Ordering::Relaxed);
            }
            "session_established" => {
                client_stats
                    .sessions_established
                    .fetch_add(1, Ordering::Relaxed);
            }
            "error" => {
                client_stats.errors.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    StatusCode::OK
}
