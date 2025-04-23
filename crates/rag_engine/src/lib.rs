use anyhow::Result;
use once_cell::sync::OnceCell;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tracing::error;

/// Errors for the RAG engine
#[derive(Debug, Error)]
pub enum RagEngineError {
    /// Model loading error
    #[error("Model loading error: {0}")]
    ModelError(String),
    /// Qdrant client error
    #[error("Qdrant client error: {0}")]
    QdrantError(String),
    /// Inference error
    #[error("Inference error: {0}")]
    InferenceError(String),
    /// No knowledge base found
    #[error("No knowledge base found")]
    NoKnowledgeBase,
}

/// Dummy model structure (simulates a real LLM)
static MODEL: OnceCell<Arc<DummyModel>> = OnceCell::new();

struct DummyModel {}

impl DummyModel {
    fn new() -> Self {
        Self {}
    }

    fn generate(&self, prompt: &str) -> String {
        if prompt.contains("network traffic query") {
            r#"{
  "flow_type": "ip",
  "limit": 10,
  "sort_by": "bytes",
  "filters": {}
}"#
            .to_string()
        } else {
            format!("Generated response for: {}", prompt)
        }
    }
}

/// Qdrant configuration for the RAG engine
#[derive(Debug)]
pub struct QdrantConfig {
    pub url: String,
    pub port: u16,
    pub collection: String,
}

impl Default for QdrantConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost".to_string(),
            port: 6334,
            collection: "netquery_knowledge".to_string(),
        }
    }
}

/// Knowledge base entry
#[allow(dead_code)]
struct KnowledgeBase {
    id: u64,
    text: String,
    metadata: serde_json::Value,
}

/// RAG engine structure
#[allow(dead_code)]
pub struct RagEngine {
    config: QdrantConfig,
    model_path: Option<PathBuf>,
    knowledge_base: Vec<KnowledgeBase>,
}

impl RagEngine {
    /// Create a new RAG engine instance
    pub async fn new(
        config: QdrantConfig,
        model_path: Option<PathBuf>,
    ) -> Result<Self, RagEngineError> {
        if MODEL.get().is_none() {
            MODEL
                .set(Arc::new(DummyModel::new()))
                .map_err(|_| RagEngineError::ModelError("Failed to set global model".into()))?;
        }

        let knowledge_base = vec![
            KnowledgeBase {
                id: 1,
                text: "Network traffic analysis involves examining data packets to understand communication patterns.".to_string(),
                metadata: json!({"topic": "general", "category": "definition"}),
            },
            KnowledgeBase {
                id: 2,
                text: "IP addresses are unique identifiers assigned to devices on a network.".to_string(),
                metadata: json!({"topic": "ip", "category": "definition"}),
            },
            KnowledgeBase {
                id: 3,
                text: "Ports are endpoints for communication in an operating system, identified by numbers.".to_string(),
                metadata: json!({"topic": "port", "category": "definition"}),
            },
            KnowledgeBase {
                id: 4,
                text: "TCP (Transmission Control Protocol) provides reliable, ordered delivery of data packets.".to_string(),
                metadata: json!({"topic": "protocol", "category": "definition"}),
            },
            KnowledgeBase {
                id: 5,
                text: "UDP (User Datagram Protocol) offers fast but unreliable packet transmission.".to_string(),
                metadata: json!({"topic": "protocol", "category": "definition"}),
            },
            KnowledgeBase {
                id: 6,
                text: "Common ports include 80 (HTTP), 443 (HTTPS), 22 (SSH), and 53 (DNS).".to_string(),
                metadata: json!({"topic": "port", "category": "examples"}),
            },
            KnowledgeBase {
                id: 7,
                text: "A flow is a sequence of packets from a source to a destination.".to_string(),
                metadata: json!({"topic": "flow", "category": "definition"}),
            },
            KnowledgeBase {
                id: 8,
                text: "Bandwidth refers to the maximum rate of data transfer across a network.".to_string(),
                metadata: json!({"topic": "metrics", "category": "definition"}),
            },
            KnowledgeBase {
                id: 9,
                text: "Packet loss occurs when packets fail to reach their destination.".to_string(),
                metadata: json!({"topic": "metrics", "category": "definition"}),
            },
            KnowledgeBase {
                id: 10,
                text: "Latency is the delay before a transfer of data begins following an instruction.".to_string(),
                metadata: json!({"topic": "metrics", "category": "definition"}),
            },
        ];

        Ok(Self {
            config,
            model_path,
            knowledge_base,
        })
    }

    /// Query the RAG engine with a prompt and get a response
    pub async fn query(&self, prompt: &str) -> Result<String, RagEngineError> {
        let relevant_texts = self.search_knowledge(prompt).await?;

        let mut enhanced_prompt = String::new();
        if !relevant_texts.is_empty() {
            enhanced_prompt.push_str("Knowledge base:\n");
            for (i, text) in relevant_texts.iter().enumerate() {
                enhanced_prompt.push_str(&format!("{}. {}\n", i + 1, text));
            }
            enhanced_prompt.push_str("\n\n");
        }
        enhanced_prompt.push_str(&format!("Question: {}\n\nAnswer: ", prompt));

        let model = MODEL
            .get()
            .ok_or_else(|| RagEngineError::ModelError("Model not initialized".into()))?;

        let response = model.generate(&enhanced_prompt);

        Ok(response)
    }

    /// Search the knowledge base for relevant entries
    async fn search_knowledge(&self, query: &str) -> Result<Vec<String>, RagEngineError> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        for entry in &self.knowledge_base {
            if entry.text.to_lowercase().contains(&query_lower) {
                results.push(entry.text.clone());
            }
            if let Some(topic) = entry.metadata.get("topic") {
                if let Some(topic_str) = topic.as_str() {
                    if query_lower.contains(topic_str) {
                        results.push(entry.text.clone());
                    }
                }
            }
        }

        results.sort();
        results.dedup();
        results.truncate(3);

        if results.is_empty() {
            return Err(RagEngineError::NoKnowledgeBase);
        }

        Ok(results)
    }
}
