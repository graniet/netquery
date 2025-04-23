use anyhow::Result;
use nl_gateway::ElasticsearchQuery;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info};

use crate::{DaemonError, FlowData, FlowKey, FlowStats, IpEndpoint, QueryResult};

/// Elasticsearch search response
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct EsSearchResponse {
    pub took: i64,
    pub timed_out: bool,
    #[serde(rename = "_shards")]
    pub shards: EsShards,
    pub hits: EsHits,
    #[serde(default)]
    pub aggregations: Option<std::collections::HashMap<String, EsAggregationValue>>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct EsShards {
    pub total: i64,
    pub successful: i64,
    pub skipped: i64,
    pub failed: i64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct EsHits {
    pub total: EsTotal,
    pub max_score: Option<f64>,
    pub hits: Vec<EsHit>,
}

/// Elasticsearch aggregations
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct EsAggregations {
    #[serde(flatten)]
    pub aggregations: std::collections::HashMap<String, EsAggregationValue>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct EsAggregationValue {
    pub doc_count_error_upper_bound: Option<i64>,
    pub sum_other_doc_count: Option<i64>,
    pub buckets: Option<Vec<EsAggregationBucket>>,
    pub value: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct EsAggregationBucket {
    #[serde(deserialize_with = "deserialize_bucket_key")]
    pub key: String,
    pub doc_count: i64,
}

/// Deserializer for bucket key (string or number)
fn deserialize_bucket_key<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::String(s) => Ok(s),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        _ => Err(D::Error::custom("Expected string or number for bucket key")),
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct EsTotal {
    pub value: i64,
    pub relation: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct EsHit {
    #[serde(rename = "_index")]
    pub index: String,
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(rename = "_score")]
    pub score: Option<f64>,
    #[serde(rename = "_source")]
    pub source: EsFlowDoc,
}

/// Flow document from Elasticsearch
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct EsFlowDoc {
    #[serde(rename = "@timestamp")]
    pub timestamp: String,
    pub bucket_start: String,
    pub bucket_end: String,
    pub src: EsIpField,
    pub dst: EsIpField,
    pub protocol: String,
    pub bytes: u64,
    pub packets: u64,
    pub flags: Option<u8>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub struct EsIpField {
    pub ip: String,
    pub port: Option<u16>,
}

/// Scroll request for Elasticsearch pagination
#[derive(Debug, Serialize)]
pub struct EsScrollRequest {
    pub scroll: String,
    pub scroll_id: String,
}

fn get_client() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client")
    })
}

fn parse_timestamp(timestamp_str: &str) -> SystemTime {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(timestamp_str) {
        let seconds = dt.timestamp();
        let nanos = dt.timestamp_subsec_nanos();
        return UNIX_EPOCH + std::time::Duration::new(seconds as u64, nanos);
    }
    error!("Failed to parse timestamp: {}", timestamp_str);
    SystemTime::now()
}

fn convert_es_hit_to_flow(hit: &EsHit) -> FlowData {
    let src_ip =
        IpAddr::from_str(&hit.source.src.ip).unwrap_or_else(|_| IpAddr::from([0, 0, 0, 0]));

    let dst_ip =
        IpAddr::from_str(&hit.source.dst.ip).unwrap_or_else(|_| IpAddr::from([0, 0, 0, 0]));

    let key = match (hit.source.src.port, hit.source.dst.port) {
        (Some(src_port), Some(dst_port)) => FlowKey::IpPortPair(
            IpEndpoint {
                addr: src_ip,
                port: src_port,
            },
            IpEndpoint {
                addr: dst_ip,
                port: dst_port,
            },
        ),
        (Some(port), None) | (None, Some(port)) => FlowKey::Port(port),
        (None, None) => FlowKey::IpPair(src_ip, dst_ip),
    };

    let start_time = parse_timestamp(&hit.source.bucket_start);
    let last_time = parse_timestamp(&hit.source.bucket_end);

    let stats = FlowStats {
        bytes: hit.source.bytes,
        packets: hit.source.packets,
        start_time,
        last_time,
    };

    FlowData { key, stats }
}

/// Execute Elasticsearch query with a specific search URL
async fn execute_with_search_url(
    client: &Client,
    search_url: &str,
    dsl: Value,
    use_scroll: bool,
    es_url: &str,
) -> Result<QueryResult, DaemonError> {
    let mut all_hits = Vec::new();

    let mut request = client
        .post(search_url)
        .header("Content-Type", "application/json")
        .json(&dsl);

    if use_scroll {
        let scroll_url = format!("{}?scroll=1m", search_url);
        request = client
            .post(&scroll_url)
            .header("Content-Type", "application/json")
            .json(&dsl);
    }

    let response = request
        .send()
        .await
        .map_err(|e| DaemonError::ElasticsearchError(format!("Search request failed: {}", e)))?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());

        if status.as_u16() == 404 && error_text.contains("index_not_found_exception") {
            return Err(DaemonError::ElasticsearchError(format!(
                "Index does not exist. No network data has been collected yet."
            )));
        } else if error_text.contains("Fielddata is disabled") && error_text.contains(".ip") {
            error!("Fielddata error detected. The query is probably missing .keyword suffix for text fields.");
            return Err(DaemonError::ElasticsearchError(
                format!("Error with text field aggregation. The query must use field.keyword for IP fields.")
            ));
        }

        return Err(DaemonError::ElasticsearchError(format!(
            "Elasticsearch returned error: {} - {}",
            status, error_text
        )));
    }

    let search_result: EsSearchResponse = response
        .json()
        .await
        .map_err(|e| DaemonError::ElasticsearchError(format!("Failed to parse response: {}", e)))?;

    let total_hits = search_result.hits.total.value;

    let has_hits = !search_result.hits.hits.is_empty();
    let first_hit_id = if has_hits {
        search_result.hits.hits[0].id.clone()
    } else {
        String::new()
    };

    all_hits.extend(search_result.hits.hits);

    if use_scroll && has_hits {
        let mut scroll_id = first_hit_id;
        let scroll_url = format!("{es_url}/_search/scroll");

        loop {
            let scroll_request = EsScrollRequest {
                scroll: "1m".to_string(),
                scroll_id: scroll_id.clone(),
            };

            let scroll_response = client
                .post(&scroll_url)
                .header("Content-Type", "application/json")
                .json(&scroll_request)
                .send()
                .await
                .map_err(|e| {
                    DaemonError::ElasticsearchError(format!("Scroll request failed: {}", e))
                })?;

            if !scroll_response.status().is_success() {
                break;
            }

            let scroll_result: EsSearchResponse = scroll_response.json().await.map_err(|e| {
                DaemonError::ElasticsearchError(format!("Failed to parse scroll response: {}", e))
            })?;

            if scroll_result.hits.hits.is_empty() {
                break;
            }

            let has_more_hits = !scroll_result.hits.hits.is_empty();

            let next_scroll_id = if has_more_hits {
                scroll_result.hits.hits[0].id.clone()
            } else {
                String::new()
            };

            all_hits.extend(scroll_result.hits.hits);

            if has_more_hits {
                scroll_id = next_scroll_id;
            }
        }
    }

    let mut flows: Vec<FlowData> = all_hits
        .iter()
        .map(|hit| convert_es_hit_to_flow(hit))
        .collect();

    let mut agg_total = 0;
    if let Some(ref aggregations) = search_result.aggregations {
        for (agg_name, agg_value) in aggregations {
            if let Some(ref buckets) = agg_value.buckets {
                if total_hits == 0 && !buckets.is_empty() {
                    agg_total += buckets.len();
                }

                for bucket in buckets {
                    let key = if agg_name.contains("src") || agg_name.contains("source") {
                        let ip = IpAddr::from_str(&bucket.key)
                            .unwrap_or_else(|_| IpAddr::from([0, 0, 0, 0]));
                        FlowKey::IpSrc(ip)
                    } else if agg_name.contains("dst") || agg_name.contains("dest") {
                        let ip = IpAddr::from_str(&bucket.key)
                            .unwrap_or_else(|_| IpAddr::from([0, 0, 0, 0]));
                        FlowKey::IpDst(ip)
                    } else if agg_name.contains("port") {
                        if let Ok(port) = bucket.key.parse::<u16>() {
                            FlowKey::Port(port)
                        } else {
                            let cleaned_key =
                                bucket.key.trim().trim_matches('"').trim_matches('\'');
                            if let Ok(port) = cleaned_key.parse::<u16>() {
                                FlowKey::Port(port)
                            } else {
                                info!("Failed to parse port from bucket key: {}", bucket.key);
                                continue;
                            }
                        }
                    } else {
                        if let Ok(ip) = IpAddr::from_str(&bucket.key) {
                            FlowKey::Ip(ip)
                        } else {
                            FlowKey::Generic(bucket.key.clone())
                        }
                    };

                    let stats = FlowStats {
                        bytes: bucket.doc_count as u64,
                        packets: bucket.doc_count as u64,
                        start_time: SystemTime::now(),
                        last_time: SystemTime::now(),
                    };

                    flows.push(FlowData { key, stats });
                }
            }
        }
    }

    let final_total = if total_hits == 0 && agg_total > 0 {
        agg_total
    } else {
        total_hits as usize
    };

    Ok(QueryResult {
        flows,
        total: final_total,
    })
}

/// Execute an Elasticsearch query, handling index wildcards and scroll API
pub async fn execute_elasticsearch_query(
    es_url: &str,
    query: &ElasticsearchQuery,
) -> Result<QueryResult, DaemonError> {
    let client = get_client();

    let index_name = if query.target_index.contains('*') {
        query.target_index.clone()
    } else if query.target_index.matches(|c| c == '.').count() >= 2
        && query.target_index.matches(|c| c == '-').count() >= 1
    {
        query.target_index.clone()
    } else {
        format!("{}-*", query.target_index)
    };

    if !index_name.contains('*') {
        let index_check_url = format!("{}/{}", es_url, index_name);
        let exists_response = client.head(&index_check_url).send().await;

        if let Ok(response) = exists_response {
            if !response.status().is_success() {
                info!(
                    "Specific index {} not found, falling back to wildcard",
                    index_name
                );

                let base_prefix = index_name.split('-').take(2).collect::<Vec<_>>().join("-");

                let index_wildcard = format!("{}-*", base_prefix);

                info!("Using wildcard index pattern: {}", index_wildcard);
                let search_url = format!("{}/{}/_search", es_url, index_wildcard);

                let (dsl, use_scroll) = {
                    let mut dsl = query.dsl.clone();
                    let size = dsl.get("size").and_then(|s| s.as_u64()).unwrap_or(100);

                    let use_scroll = size > 10000;

                    if use_scroll {
                        if let Some(obj) = dsl.as_object_mut() {
                            obj.insert("size".to_string(), Value::from(1000));
                        }
                    }

                    (dsl, use_scroll)
                };

                return execute_with_search_url(client, &search_url, dsl, use_scroll, es_url).await;
            }
        }
    };

    let search_url = format!("{}/{}/_search", es_url, index_name);

    let (dsl, use_scroll) = {
        let mut dsl = query.dsl.clone();
        let size = dsl.get("size").and_then(|s| s.as_u64()).unwrap_or(100);

        let use_scroll = size > 10000;

        if use_scroll {
            if let Some(obj) = dsl.as_object_mut() {
                obj.insert("size".to_string(), Value::from(1000));
            }
        }

        (dsl, use_scroll)
    };

    execute_with_search_url(client, &search_url, dsl, use_scroll, es_url).await
}

/// Convert ThinkingEvent to protobuf format
pub fn convert_thinking_event(
    event: &nl_gateway::multi_turn::ThinkingEvent,
) -> crate::pb::ThinkingEvent {
    crate::pb::ThinkingEvent {
        action: event.action.clone(),
        step_info: event.step_info.clone(),
        step_number: event.step_number,
        total_steps: event.total_steps,
    }
}
