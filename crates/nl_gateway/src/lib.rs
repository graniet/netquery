use anyhow::Result;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::OnceLock;
use thiserror::Error;
use tracing::error;

#[cfg(feature = "rag")]
use rag_engine::RagEngine;

pub mod multi_turn;

/// Errors for the NL Gateway.
#[derive(Debug, Error)]
pub enum NlGatewayError {
    #[error("Failed to parse intent: {0}")]
    IntentParseError(String),
    #[error("LLM service error: {0}")]
    LlmError(String),
    #[error("No data available")]
    NoData,
    #[error("Elasticsearch query error: {0}")]
    ElasticsearchError(String),
    #[error("OpenAI API error: {0}")]
    OpenAiError(String),
    #[error("API key not found")]
    ApiKeyNotFound,
}

/// Type of flow to query (IP, Port, or both).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowType {
    Ip,
    Port,
    IpPort,
}

impl ToString for FlowType {
    fn to_string(&self) -> String {
        match self {
            FlowType::Ip => "ip".to_string(),
            FlowType::Port => "port".to_string(),
            FlowType::IpPort => "ip_port".to_string(),
        }
    }
}

/// Sorting options for queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortBy {
    Bytes,
    Packets,
    StartTime,
    LastTime,
}

impl ToString for SortBy {
    fn to_string(&self) -> String {
        match self {
            SortBy::Bytes => "bytes".to_string(),
            SortBy::Packets => "packets".to_string(),
            SortBy::StartTime => "start_time".to_string(),
            SortBy::LastTime => "last_time".to_string(),
        }
    }
}

/// Structured intent parsed from natural language.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryIntent {
    pub flow_type: FlowType,
    pub limit: usize,
    pub sort_by: SortBy,
    pub filters: HashMap<String, String>,
}

impl Default for QueryIntent {
    fn default() -> Self {
        Self {
            flow_type: FlowType::Ip,
            limit: 10,
            sort_by: SortBy::Bytes,
            filters: HashMap::new(),
        }
    }
}

/// Query parameters for API requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryParams {
    pub flow_type: String,
    pub limit: usize,
    pub sort_by: String,
    pub filter: Option<HashMap<String, String>>,
}

impl QueryIntent {
    /// Convert QueryIntent to QueryParams for API usage.
    pub fn to_query_params(&self) -> QueryParams {
        QueryParams {
            flow_type: self.flow_type.to_string(),
            limit: self.limit,
            sort_by: self.sort_by.to_string(),
            filter: if self.filters.is_empty() {
                None
            } else {
                Some(self.filters.clone())
            },
        }
    }
}

/// Elasticsearch query and target index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElasticsearchQuery {
    pub dsl: Value,
    pub target_index: String,
}

fn get_openai_api_key() -> Result<String, NlGatewayError> {
    env::var("OPENAI_API_KEY").map_err(|_| NlGatewayError::ApiKeyNotFound)
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

/// Main struct for NL Gateway.
pub struct NlGateway {
    #[cfg(feature = "rag")]
    rag_engine: Option<RagEngine>,
}

impl NlGateway {
    /// Create a new NlGateway instance.
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "rag")]
            rag_engine: None,
        }
    }

    #[cfg(feature = "rag")]
    /// Attach a RAG engine to the gateway.
    pub fn with_rag_engine(mut self, rag_engine: RagEngine) -> Self {
        self.rag_engine = Some(rag_engine);
        self
    }

    /// Convert natural language to Elasticsearch query using OpenAI API.
    pub async fn nl_to_es(&self, question: &str) -> Result<ElasticsearchQuery, NlGatewayError> {
        let api_key = get_openai_api_key()?;
        let system_prompt = include_str!("prompts/es_system.txt");

        let examples = vec![
            (
                "Show me the top 10 source IPs",
                serde_json::json!({
                    "dsl": {
                        "size": 10,
                        "sort": [{"bytes": {"order": "desc"}}],
                        "query": {"match_all": {}}
                    },
                    "target_index": "netquery-flows-*"
                }),
            ),
            (
                "Affiche moi toutes les IP qui ont le port 80 ouvert",
                serde_json::json!({
                    "dsl": {
                        "size": 100,
                        "query": {
                            "bool": {
                                "should": [
                                    {"term": {"src.port": 80}},
                                    {"term": {"dst.port": 80}}
                                ]
                            }
                        },
                        "aggs": {
                            "ips": {
                                "terms": {"field": "src.ip.keyword", "size": 100}
                            }
                        }
                    },
                    "target_index": "netquery-flows-*"
                }),
            ),
            (
                "Show traffic from last night",
                serde_json::json!({
                    "dsl": {
                        "size": 100,
                        "query": {
                            "range": {
                                "@timestamp": {
                                    "gte": "now-1d/d",
                                    "lt": "now/d"
                                }
                            }
                        },
                        "sort": [{"bytes": {"order": "desc"}}]
                    },
                    "target_index": "netquery-flows-*"
                }),
            ),
            (
                "Montre moi tout le trafic UDP de la semaine",
                serde_json::json!({
                    "dsl": {
                        "size": 100,
                        "query": {
                            "bool": {
                                "must": [
                                    {"term": {"protocol": "udp"}},
                                    {"range": {"@timestamp": {"gte": "now-7d", "lt": "now"}}}
                                ]
                            }
                        },
                        "sort": [{"bytes": {"order": "desc"}}]
                    },
                    "target_index": "netquery-flows-*"
                }),
            ),
            (
                "Show me traffic from April 22, 2025",
                serde_json::json!({
                    "dsl": {
                        "size": 100,
                        "query": {
                            "range": {
                                "@timestamp": {
                                    "gte": "2025-04-22T00:00:00",
                                    "lt": "2025-04-23T00:00:00"
                                }
                            }
                        },
                        "sort": [{"bytes": {"order": "desc"}}]
                    },
                    "target_index": "netquery-flows-2025.04.22"
                }),
            ),
            (
                "Show me traffic between April 20 and April 22, 2025",
                serde_json::json!({
                    "dsl": {
                        "size": 100,
                        "query": {
                            "range": {
                                "@timestamp": {
                                    "gte": "2025-04-20T00:00:00",
                                    "lt": "2025-04-23T00:00:00"
                                }
                            }
                        },
                        "sort": [{"bytes": {"order": "desc"}}]
                    },
                    "target_index": "netquery-flows-*"
                }),
            ),
            (
                "What happened yesterday?",
                serde_json::json!({
                    "dsl": {
                        "size": 100,
                        "query": {
                            "range": {
                                "@timestamp": {
                                    "gte": "now-1d/d",
                                    "lt": "now/d"
                                }
                            }
                        },
                        "sort": [{"bytes": {"order": "desc"}}]
                    },
                    "target_index": "netquery-flows-*"
                }),
            ),
            (
                "Affiche toutes les IPs",
                serde_json::json!({
                    "dsl": {
                        "size": 0,
                        "query": {"match_all": {}},
                        "aggs": {
                            "source_ips": {
                                "terms": {
                                    "field": "src.ip.keyword",
                                    "size": 100
                                }
                            },
                            "dest_ips": {
                                "terms": {
                                    "field": "dst.ip.keyword",
                                    "size": 100
                                }
                            }
                        }
                    },
                    "target_index": "netquery-flows-*"
                }),
            ),
            (
                "Toutes les IP qui communiquent en DNS",
                serde_json::json!({
                    "dsl": {
                        "size": 0,
                        "query": {
                            "term": {"protocol": "dns"}
                        },
                        "aggs": {
                            "dns_clients": {
                                "terms": {
                                    "field": "src.ip.keyword",
                                    "size": 50
                                }
                            },
                            "dns_servers": {
                                "terms": {
                                    "field": "dst.ip.keyword",
                                    "size": 50
                                }
                            }
                        }
                    },
                    "target_index": "netquery-flows-*"
                }),
            ),
            (
                "Montre-moi tout le trafic HTTP",
                serde_json::json!({
                    "dsl": {
                        "size": 100,
                        "query": {
                            "term": {"protocol": "http"}
                        },
                        "sort": [{"bytes": {"order": "desc"}}]
                    },
                    "target_index": "netquery-flows-*"
                }),
            ),
            (
                "Montre-moi le trafic web",
                serde_json::json!({
                    "dsl": {
                        "size": 100,
                        "query": {
                            "bool": {
                                "should": [
                                    {"term": {"protocol": "http"}},
                                    {"term": {"protocol": "https"}}
                                ]
                            }
                        },
                        "sort": [{"bytes": {"order": "desc"}}]
                    },
                    "target_index": "netquery-flows-*"
                }),
            ),
        ];

        let mut messages = Vec::new();
        messages.push(serde_json::json!({
            "role": "system",
            "content": system_prompt
        }));

        for (user_msg, assistant_response) in examples {
            messages.push(serde_json::json!({
                "role": "user",
                "content": user_msg
            }));

            messages.push(serde_json::json!({
                "role": "assistant",
                "content": null,
                "function_call": {
                    "name": "create_elasticsearch_query",
                    "arguments": assistant_response.to_string()
                }
            }));
        }

        messages.push(serde_json::json!({
            "role": "user",
            "content": question
        }));

        let functions = serde_json::json!([{
            "name": "create_elasticsearch_query",
            "description": "Create an Elasticsearch query from natural language",
            "parameters": {
                "type": "object",
                "properties": {
                    "dsl": {
                        "type": "object",
                        "description": "Elasticsearch DSL query object"
                    },
                    "target_index": {
                        "type": "string",
                        "description": "Target Elasticsearch index",
                        "default": "netquery-flows-2025.04.22"
                    }
                },
                "required": ["dsl", "target_index"]
            }
        }]);

        let request_body = serde_json::json!({
            "model": "gpt-4o",
            "messages": messages,
            "functions": functions,
            "function_call": {"name": "create_elasticsearch_query"},
            "temperature": 0.1
        });

        let client = get_client();
        let response = client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| NlGatewayError::OpenAiError(format!("Request failed: {}", e)))?;

        let response_status = response.status();
        if !response_status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(NlGatewayError::OpenAiError(format!(
                "API error ({}): {}",
                response_status, error_text
            )));
        }

        let response_json: Value = response
            .json()
            .await
            .map_err(|e| NlGatewayError::OpenAiError(format!("Failed to parse response: {}", e)))?;

        let function_call = response_json["choices"][0]["message"]["function_call"].clone();
        if function_call.is_null() {
            return Err(NlGatewayError::OpenAiError(
                "No function call in response".to_string(),
            ));
        }

        let arguments = function_call["arguments"].as_str().ok_or_else(|| {
            NlGatewayError::OpenAiError("No arguments in function call".to_string())
        })?;

        let es_query: ElasticsearchQuery = serde_json::from_str(arguments).map_err(|e| {
            NlGatewayError::OpenAiError(format!("Failed to parse arguments: {}", e))
        })?;

        Ok(es_query)
    }

    /// Parse a natural language query into a QueryIntent.
    pub async fn parse_intent(&self, query: &str) -> Result<QueryIntent, NlGatewayError> {
        #[cfg(feature = "rag")]
        if let Some(_) = self.rag_engine {
            return self.rag_parse_intent(query).await;
        }

        self.rule_based_parse(query)
    }

    #[cfg(feature = "rag")]
    /// Parse intent using RAG engine.
    async fn rag_parse_intent(&self, query: &str) -> Result<QueryIntent, NlGatewayError> {
        if let Some(ref rag) = self.rag_engine {
            let prompt = format!(
                "Convert this network traffic query into a structured JSON object: '{}'\n\
                Return ONLY valid JSON with these fields:\n\
                - flow_type: one of ['ip', 'port', 'ip_port']\n\
                - limit: positive integer number of results to return\n\
                - sort_by: one of ['bytes', 'packets', 'start_time', 'last_time']\n\
                - filters: object with any of these optional keys: ['ip', 'port', 'src_ip', 'dst_ip', 'src_port', 'dst_port']",
                query
            );

            let response = rag
                .query(&prompt)
                .await
                .map_err(|e| NlGatewayError::LlmError(e.to_string()))?;

            let json_start = response.find('{').ok_or_else(|| {
                NlGatewayError::IntentParseError("No JSON found in response".into())
            })?;
            let json_end = response.rfind('}').ok_or_else(|| {
                NlGatewayError::IntentParseError("No JSON found in response".into())
            })?;

            let json_str = &response[json_start..=json_end];
            let intent: QueryIntent = serde_json::from_str(json_str)
                .map_err(|e| NlGatewayError::IntentParseError(format!("Invalid JSON: {}", e)))?;

            Ok(intent)
        } else {
            Err(NlGatewayError::LlmError(
                "RAG engine not initialized".into(),
            ))
        }
    }

    /// Parse intent using rule-based logic.
    fn rule_based_parse(&self, query: &str) -> Result<QueryIntent, NlGatewayError> {
        let mut intent = QueryIntent::default();
        let lower_query = query.to_lowercase();

        let is_french = lower_query.contains(" les ")
            || lower_query.contains("combien ")
            || lower_query.contains("montrer ")
            || lower_query.contains("affiche ");

        if lower_query.contains("ip port")
            || lower_query.contains("ip:port")
            || lower_query.contains("ip et port")
        {
            intent.flow_type = FlowType::IpPort;
        } else if lower_query.contains(" port") || lower_query.contains("ports") {
            intent.flow_type = FlowType::Port;
        } else {
            intent.flow_type = FlowType::Ip;
        }

        let limit_regex = if is_french {
            Regex::new(r"top\s+(\d+)").unwrap()
        } else {
            Regex::new(r"top\s+(\d+)").unwrap()
        };

        if let Some(cap) = limit_regex.captures(&lower_query) {
            if let Some(limit_str) = cap.get(1) {
                if let Ok(limit) = limit_str.as_str().parse::<usize>() {
                    intent.limit = limit;
                }
            }
        }

        if lower_query.contains("packets")
            || lower_query.contains("packet")
            || lower_query.contains("paquets")
            || lower_query.contains("paquet")
        {
            intent.sort_by = SortBy::Packets;
        } else if lower_query.contains("start time") || lower_query.contains("début") {
            intent.sort_by = SortBy::StartTime;
        } else if lower_query.contains("last time")
            || lower_query.contains("récent")
            || lower_query.contains("dernier")
        {
            intent.sort_by = SortBy::LastTime;
        } else {
            intent.sort_by = SortBy::Bytes;
        }

        let ip_regex = Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap();
        if let Some(cap) = ip_regex.captures(&lower_query) {
            if let Some(ip_str) = cap.get(1) {
                if let Ok(ip) = IpAddr::from_str(ip_str.as_str()) {
                    if lower_query.contains("source") || lower_query.contains("src") {
                        intent.filters.insert("src_ip".to_string(), ip.to_string());
                    } else if lower_query.contains("destination") || lower_query.contains("dst") {
                        intent.filters.insert("dst_ip".to_string(), ip.to_string());
                    } else {
                        intent.filters.insert("ip".to_string(), ip.to_string());
                    }
                }
            }
        }

        let port_regex = Regex::new(r"port\s+(\d+)").unwrap();
        if let Some(cap) = port_regex.captures(&lower_query) {
            if let Some(port_str) = cap.get(1) {
                if let Ok(port) = port_str.as_str().parse::<u16>() {
                    if lower_query.contains("source") || lower_query.contains("src") {
                        intent
                            .filters
                            .insert("src_port".to_string(), port.to_string());
                    } else if lower_query.contains("destination") || lower_query.contains("dst") {
                        intent
                            .filters
                            .insert("dst_port".to_string(), port.to_string());
                    } else {
                        intent.filters.insert("port".to_string(), port.to_string());
                    }
                }
            }
        }

        Ok(intent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_intent_english() {
        let gateway = NlGateway::new();

        let intent = gateway.parse_intent("Show top 5 IPs").unwrap();
        assert_eq!(intent.flow_type, FlowType::Ip);
        assert_eq!(intent.limit, 5);
        assert_eq!(intent.sort_by, SortBy::Bytes);
        assert!(intent.filters.is_empty());

        let intent = gateway.parse_intent("Top 10 ports by packets").unwrap();
        assert_eq!(intent.flow_type, FlowType::Port);
        assert_eq!(intent.limit, 10);
        assert_eq!(intent.sort_by, SortBy::Packets);
        assert!(intent.filters.is_empty());
    }

    #[test]
    fn test_simple_intent_french() {
        let gateway = NlGateway::new();

        let intent = gateway.parse_intent("Montrer les top 5 IPs").unwrap();
        assert_eq!(intent.flow_type, FlowType::Ip);
        assert_eq!(intent.limit, 5);
        assert_eq!(intent.sort_by, SortBy::Bytes);
        assert!(intent.filters.is_empty());

        let intent = gateway.parse_intent("Top 10 ports par paquets").unwrap();
        assert_eq!(intent.flow_type, FlowType::Port);
        assert_eq!(intent.limit, 10);
        assert_eq!(intent.sort_by, SortBy::Packets);
        assert!(intent.filters.is_empty());
    }

    #[test]
    fn test_filter_intent() {
        let gateway = NlGateway::new();

        let intent = gateway.parse_intent("Show IP 192.168.1.1").unwrap();
        assert_eq!(intent.flow_type, FlowType::Ip);
        assert_eq!(intent.filters.get("ip").unwrap(), "192.168.1.1");

        let intent = gateway
            .parse_intent("Top traffic from source 10.0.0.1")
            .unwrap();
        assert_eq!(intent.filters.get("src_ip").unwrap(), "10.0.0.1");

        let intent = gateway.parse_intent("Show port 80 traffic").unwrap();
        assert_eq!(intent.flow_type, FlowType::Port);
        assert_eq!(intent.filters.get("port").unwrap(), "80");
    }

    #[test]
    fn test_conversion_to_query_params() {
        let mut intent = QueryIntent::default();
        intent.flow_type = FlowType::Port;
        intent.limit = 5;
        intent.sort_by = SortBy::Packets;
        intent.filters.insert("port".to_string(), "443".to_string());

        let params = intent.to_query_params();

        assert_eq!(params.flow_type, "port");
        assert_eq!(params.limit, 5);
        assert_eq!(params.sort_by, "packets");
        assert!(params.filter.is_some());
        assert_eq!(params.filter.unwrap().get("port").unwrap(), "443");
    }

    #[tokio::test]
    #[ignore]
    async fn test_nl_port80_to_es() {
        let gateway = NlGateway::new();

        if let Ok(_) = std::env::var("OPENAI_API_KEY") {
            let result = gateway.nl_to_es("Show me all traffic on port 80").await;

            assert!(
                result.is_ok(),
                "Failed to convert NL to ES: {:?}",
                result.err()
            );
            let query = result.unwrap();

            assert_eq!(query.target_index, "netquery-flows");

            let dsl_str = serde_json::to_string_pretty(&query.dsl).unwrap();
            assert!(
                dsl_str.contains("80"),
                "Query doesn't contain port 80: {}",
                dsl_str
            );

            println!("Generated Elasticsearch query for port 80: {}", dsl_str);
        } else {
            println!("Skipping test_nl_port80_to_es as OPENAI_API_KEY is not set");
        }
    }
}
