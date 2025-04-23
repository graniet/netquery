use once_cell::sync::Lazy;
use phf::{phf_map, Map};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;
use tracing::{debug, error, info};

/// Static map of common ports to protocol names
static COMMON_PORTS: Map<u16, &'static str> = phf_map! {
    80u16 => "http",
    443u16 => "https",
    8080u16 => "http",
    8443u16 => "https",
    25u16 => "smtp",
    143u16 => "imap",
    110u16 => "pop3",
    587u16 => "submission",
    465u16 => "smtps",
    993u16 => "imaps",
    995u16 => "pop3s",
    53u16 => "dns",
    20u16 => "ftp-data",
    21u16 => "ftp",
    22u16 => "ssh",
    23u16 => "telnet",
    1433u16 => "mssql",
    3306u16 => "mysql",
    5432u16 => "postgresql",
    27017u16 => "mongodb",
    6379u16 => "redis",
    161u16 => "snmp",
    162u16 => "snmptrap",
    389u16 => "ldap",
    636u16 => "ldaps",
    3389u16 => "rdp",
    5900u16 => "vnc",
    123u16 => "ntp",
    67u16 => "dhcp-server",
    68u16 => "dhcp-client",
    9090u16 => "prometheus",
    9100u16 => "node-exporter",
    445u16 => "smb",
    139u16 => "netbios",
    137u16 => "netbios-ns",
    138u16 => "netbios-dgm",
};

/// Runtime cache for LLM-inferred protocols
static PROTOCOL_CACHE: Lazy<RwLock<HashMap<(u16, String), String>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Infers the protocol based on the port number and transport layer
///
/// Strategy:
/// 1. Check COMMON_PORTS for known port mappings
/// 2. Check the cache for previously inferred protocols
/// 3. Attempt to infer using LLM (if available)
/// 4. Fallback to basic protocol name if all else fails
pub async fn infer(port: u16, transport: &'static str) -> String {
    let cache_key = (port, transport.to_string());

    if let Some(protocol) = COMMON_PORTS.get(&port) {
        debug!("Protocol for port {port} ({transport}) from common list: {protocol}");
        return (*protocol).to_string();
    }

    {
        let cache = PROTOCOL_CACHE.read().unwrap();
        if let Some(protocol) = cache.get(&cache_key) {
            debug!("Protocol for port {port} ({transport}) from cache: {protocol}");
            return protocol.clone();
        }
    }

    if let Some(protocol) = infer_via_llm(port, transport).await {
        {
            let mut cache = PROTOCOL_CACHE.write().unwrap();
            cache.insert(cache_key, protocol.clone());
        }
        return protocol;
    }

    let default_protocol = if transport.to_lowercase() == "tcp" || transport.to_lowercase() == "udp"
    {
        transport.to_lowercase()
    } else {
        "unknown".to_string()
    };

    debug!("Using default protocol for port {port} ({transport}): {default_protocol}");
    default_protocol
}

/// Attempts to infer protocol using LLM
async fn infer_via_llm(port: u16, transport: &str) -> Option<String> {
    let api_key = match std::env::var("OPENAI_API_KEY") {
        Ok(key) => key,
        Err(_) => {
            debug!("OPENAI_API_KEY not set, skipping LLM inference");
            return None;
        }
    };

    let prompt = format!(
        "{} port {} protocol? Un seul mot.",
        transport.to_uppercase(),
        port
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;

    let request_body = serde_json::json!({
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are a network protocol expert. Respond with exactly one word - the name of the protocol that commonly uses the specified port."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.0,
        "max_tokens": 10
    });

    let response = match client
        .post("https://api.openai.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
    {
        Ok(res) => res,
        Err(e) => {
            error!("Failed to query OpenAI: {}", e);
            return None;
        }
    };

    if !response.status().is_success() {
        error!("OpenAI API error: {}", response.status());
        return None;
    }

    let response_json: serde_json::Value = match response.json().await {
        Ok(json) => json,
        Err(e) => {
            error!("Failed to parse OpenAI response: {}", e);
            return None;
        }
    };

    let protocol = response_json["choices"][0]["message"]["content"]
        .as_str()
        .map(|s| s.trim().to_lowercase());

    if let Some(protocol) = protocol {
        let protocol = protocol
            .split_whitespace()
            .next()
            .unwrap_or("unknown")
            .to_string();

        if protocol.len() > 2 && protocol.len() < 20 {
            info!("LLM inferred protocol for port {port} ({transport}): {protocol}");
            Some(protocol)
        } else {
            debug!("Invalid protocol name from LLM: {}", protocol);
            None
        }
    } else {
        error!("Failed to extract protocol from OpenAI response");
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito;
    use std::env;

    #[test]
    fn test_common_ports() {
        assert_eq!(infer_sync(80, "tcp"), "http");
        assert_eq!(infer_sync(443, "tcp"), "https");
        assert_eq!(infer_sync(53, "udp"), "dns");
        assert_eq!(infer_sync(22, "tcp"), "ssh");
    }

    fn infer_sync(port: u16, transport: &'static str) -> String {
        if let Some(protocol) = COMMON_PORTS.get(&port) {
            return (*protocol).to_string();
        }

        if transport.to_lowercase() == "tcp" || transport.to_lowercase() == "udp" {
            transport.to_lowercase()
        } else {
            "unknown".to_string()
        }
    }

    #[tokio::test]
    async fn test_cache() {
        {
            let mut cache = PROTOCOL_CACHE.write().unwrap();
            cache.insert((12345, "tcp".to_string()), "testproto".to_string());
        }

        let result = infer(12345, "tcp").await;
        assert_eq!(result, "testproto");
    }

    #[tokio::test]
    #[ignore]
    async fn test_llm_inference() {
        if env::var("OPENAI_API_KEY").is_err() {
            return;
        }

        let result = infer(8123, "tcp").await;
        assert_ne!(result, "unknown");
        assert_ne!(result, "tcp");
    }
}
