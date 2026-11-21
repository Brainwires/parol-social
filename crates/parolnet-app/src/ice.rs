//! ICE servers: STUN from the home relay's `/turn-credentials`, TURN only from the user.
//!
//! A signaling-only relay answers `/turn-credentials` with STUN URIs only. The app never
//! takes a TURN URI from a relay (even a relay-profile one): TURN is user-supplied
//! (plan section 2.3).

use std::time::Duration;

use serde::Deserialize;

/// A user-configured ICE server (their own TURN server, or extra STUN).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub credential: String,
}

#[derive(Deserialize)]
struct TurnCredentials {
    #[serde(default)]
    uris: Vec<String>,
    #[serde(default)]
    profile: Option<String>,
}

/// The HTTP(S) base of a relay's WebSocket URL (`wss://host/ws` → `https://host`).
pub fn http_base(relay_ws_url: &str) -> Option<String> {
    let rest = if let Some(r) = relay_ws_url.strip_prefix("wss://") {
        format!("https://{r}")
    } else if let Some(r) = relay_ws_url.strip_prefix("ws://") {
        format!("http://{r}")
    } else {
        return None;
    };
    let trimmed = rest.trim_end_matches('/');
    Some(trimmed.strip_suffix("/ws").unwrap_or(trimmed).to_owned())
}

/// STUN URIs from an answer of `/turn-credentials`; TURN URIs are dropped.
pub fn stun_uris_from_answer(json: &str) -> (Vec<String>, Option<String>) {
    let Ok(answer) = serde_json::from_str::<TurnCredentials>(json) else {
        return (Vec::new(), None);
    };
    let stun = answer
        .uris
        .into_iter()
        .filter(|u| u.to_ascii_lowercase().starts_with("stun:"))
        .collect();
    (stun, answer.profile)
}

/// Fetch the STUN URIs the relay announces. Empty on any failure (the app then has host
/// candidates only, which still connect peers on one network).
pub async fn fetch_stun(relay_ws_url: &str) -> Vec<String> {
    let Some(base) = http_base(relay_ws_url) else {
        return Vec::new();
    };
    crate::install_crypto_provider();
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(%e, "no HTTP client for /turn-credentials");
            return Vec::new();
        }
    };
    let url = format!("{base}/turn-credentials");
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.text().await {
            Ok(body) => {
                let (stun, profile) = stun_uris_from_answer(&body);
                tracing::info!(count = stun.len(), profile = ?profile, "STUN servers from the relay");
                stun
            }
            Err(e) => {
                tracing::warn!(%e, "reading /turn-credentials");
                Vec::new()
            }
        },
        Ok(resp) => {
            tracing::warn!(status = %resp.status(), "/turn-credentials refused");
            Vec::new()
        }
        Err(e) => {
            tracing::warn!(%e, "fetching /turn-credentials");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_base_from_ws_url() {
        assert_eq!(
            http_base("wss://parol.social/ws").as_deref(),
            Some("https://parol.social")
        );
        assert_eq!(
            http_base("ws://127.0.0.1:9/ws/").as_deref(),
            Some("http://127.0.0.1:9")
        );
        assert_eq!(http_base("ws://h:1").as_deref(), Some("http://h:1"));
        assert_eq!(http_base("https://h/ws"), None);
    }

    #[test]
    fn only_stun_is_taken_from_the_relay() {
        let (stun, profile) = stun_uris_from_answer(
            r#"{"username":"u","credential":"c","ttl":1,"uris":["stun:a:3478","turn:a:3478","turns:a:5349"],"profile":"relay"}"#,
        );
        assert_eq!(stun, vec!["stun:a:3478".to_owned()]);
        assert_eq!(profile.as_deref(), Some("relay"));
        let (stun, _) = stun_uris_from_answer("{}");
        assert!(stun.is_empty());
        let (stun, _) = stun_uris_from_answer("garbage");
        assert!(stun.is_empty());
    }
}
