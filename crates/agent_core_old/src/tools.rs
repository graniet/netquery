use anyhow::{Result, anyhow, Context};
use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use std::time::Duration;
use thiserror::Error;
use tokio::time::timeout;
use tracing::{debug, error};

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("Tool execution timed out after {0:?}")]
    Timeout(Duration),
    #[error("Error executing tool: {0}")]
    Execution(String),
    #[error("Invalid arguments: {0}")]
    InvalidArguments(String),
    #[error("Elasticsearch error: {0}")]
    Elasticsearch(String),
}

/// Trait for agent tools that can be executed
#[async_trait]
pub trait Tool: Send + Sync {
    /// Returns the name of the tool
    async fn name(&self) -> &'static str;
    
    /// Executes the tool with given arguments and returns a result
    async fn run(&self, args: Value) -> Result<Value>;
}

/// Tool for ElasticSearch search operations
pub struct EsSearch {
    client: Client,
    es_url: String,
    auth: Option<(String, String)>,
    timeout_secs: u64,
    max_docs: usize,
}

impl EsSearch {
    /// Create a new EsSearch tool with custom settings
    pub fn new(
        es_url: String, 
        username: Option<String>, 
        password: Option<String>,
        timeout_secs: u64,
        max_docs: usize,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs + 5))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .context("Failed to build HTTP client")?;
            
        let auth = match (username, password) {
            (Some(u), Some(p)) => Some((u, p)),
            _ => None,
        };
        
        Ok(Self {
            client,
            es_url,
            auth,
            timeout_secs,
            max_docs,
        })
    }
    
    /// Create a default EsSearch instance
    pub fn default_instance() -> Result<Self> {
        Self::new(
            "http://localhost:9200".to_string(),
            None,
            None,
            3,
            200,
        )
    }
    
    /// Helper to build a basic search request
    fn build_search_query(&self, query_string: &str, size: usize) -> Value {
        json!({
            "size": size,
            "query": {
                "query_string": {
                    "query": query_string
                }
            },
            "_source": ["src.ip", "dst.ip", "dst.port", "bytes", "protocol", "timestamp"],
            "sort": [
                { "@timestamp": { "order": "desc" } }
            ]
        })
    }
}

#[async_trait]
impl Tool for EsSearch {
    async fn name(&self) -> &'static str {
        "es_search"
    }
    
    async fn run(&self, args: Value) -> Result<Value> {
        // Parse arguments
        let query = args.get("query")
            .and_then(|q| q.as_str())
            .ok_or_else(|| ToolError::InvalidArguments("Missing 'query' field".to_string()))?;
        
        let size = args.get("size")
            .and_then(|s| s.as_u64())
            .unwrap_or(self.max_docs as u64)
            .min(self.max_docs as u64) as usize;
            
        let index = args.get("index")
            .and_then(|i| i.as_str())
            .unwrap_or("netquery-flows-*");
            
        // Prepare request
        let search_url = format!("{}/{}/_search", self.es_url, index);
        let query_body = self.build_search_query(query, size);
        
        debug!("Elasticsearch search query: {}", query_body);
        
        // Execute search with timeout
        let search_client = self.client.clone();
        let auth_clone = self.auth.clone();
        
        let search_fut = async move {
            let mut request = search_client.post(&search_url)
                .json(&query_body)
                .header("Content-Type", "application/json");
                
            if let Some((username, password)) = auth_clone {
                request = request.basic_auth(username, Some(password));
            }
            
            let response = request.send().await?;
            let status = response.status();
            
            match status {
                StatusCode::OK => {
                    let response_body: Value = response.json().await?;
                    let hits = response_body
                        .get("hits")
                        .and_then(|h| h.get("hits"))
                        .and_then(|h| h.as_array())
                        .ok_or_else(|| anyhow!("No hits found in response"))?;
                        
                    let mut results = Vec::new();
                    for hit in hits {
                        if let Some(source) = hit.get("_source") {
                            results.push(source.clone());
                        }
                    }
                    
                    Ok(Value::Array(results))
                },
                _ => {
                    let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                    Err(ToolError::Elasticsearch(format!(
                        "Elasticsearch returned error {}: {}", 
                        status, 
                        error_text
                    )).into())
                }
            }
        };
        
        match timeout(Duration::from_secs(self.timeout_secs), search_fut).await {
            Ok(result) => result,
            Err(_) => Err(ToolError::Timeout(Duration::from_secs(self.timeout_secs)).into()),
        }
    }
}

/// Tool for ElasticSearch aggregation operations
pub struct EsAgg {
    client: Client,
    es_url: String,
    auth: Option<(String, String)>,
    timeout_secs: u64,
}

impl EsAgg {
    /// Create a new EsAgg tool with custom settings
    pub fn new(
        es_url: String, 
        username: Option<String>, 
        password: Option<String>,
        timeout_secs: u64,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs + 5))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .context("Failed to build HTTP client")?;
            
        let auth = match (username, password) {
            (Some(u), Some(p)) => Some((u, p)),
            _ => None,
        };
        
        Ok(Self {
            client,
            es_url,
            auth,
            timeout_secs,
        })
    }
    
    /// Create a default EsAgg instance
    pub fn default_instance() -> Result<Self> {
        Self::new(
            "http://localhost:9200".to_string(),
            None,
            None,
            3,
        )
    }
    
    /// Helper to build a terms aggregation
    fn build_terms_agg(&self, field: &str, size: usize) -> Value {
        json!({
            "size": 0,
            "aggs": {
                "top_values": {
                    "terms": {
                        "field": field,
                        "size": size
                    }
                }
            }
        })
    }
}

#[async_trait]
impl Tool for EsAgg {
    async fn name(&self) -> &'static str {
        "es_agg"
    }
    
    async fn run(&self, args: Value) -> Result<Value> {
        // Parse arguments
        let field = args.get("field")
            .and_then(|f| f.as_str())
            .ok_or_else(|| ToolError::InvalidArguments("Missing 'field' field".to_string()))?;
            
        let size = args.get("size")
            .and_then(|s| s.as_u64())
            .unwrap_or(10) as usize;
            
        let index = args.get("index")
            .and_then(|i| i.as_str())
            .unwrap_or("netquery-flows-*");
            
        let query = args.get("query")
            .and_then(|q| q.as_str());
            
        // Prepare aggregation request
        let agg_url = format!("{}/{}/_search", self.es_url, index);
        
        // Build aggregation body
        let mut agg_body = self.build_terms_agg(field, size);
        
        // Add query if provided
        if let Some(q) = query {
            agg_body["query"] = json!({
                "query_string": {
                    "query": q
                }
            });
        }
        
        debug!("Elasticsearch aggregation: {}", agg_body);
        
        // Execute aggregation with timeout
        let agg_client = self.client.clone();
        let auth_clone = self.auth.clone();
        
        let agg_fut = async move {
            let mut request = agg_client.post(&agg_url)
                .json(&agg_body)
                .header("Content-Type", "application/json");
                
            if let Some((username, password)) = auth_clone {
                request = request.basic_auth(username, Some(password));
            }
            
            let response = request.send().await?;
            let status = response.status();
            
            match status {
                StatusCode::OK => {
                    let response_body: Value = response.json().await?;
                    let buckets = response_body
                        .get("aggregations")
                        .and_then(|a| a.get("top_values"))
                        .and_then(|t| t.get("buckets"))
                        .and_then(|b| b.as_array())
                        .ok_or_else(|| anyhow!("No aggregation buckets found in response"))?;
                        
                    Ok(Value::Array(buckets.clone()))
                },
                _ => {
                    let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                    Err(ToolError::Elasticsearch(format!(
                        "Elasticsearch returned error {}: {}", 
                        status, 
                        error_text
                    )).into())
                }
            }
        };
        
        match timeout(Duration::from_secs(self.timeout_secs), agg_fut).await {
            Ok(result) => result,
            Err(_) => Err(ToolError::Timeout(Duration::from_secs(self.timeout_secs)).into()),
        }
    }
}

/// Tool to finalize the agent's answer
pub struct Finish {}

impl Finish {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Tool for Finish {
    async fn name(&self) -> &'static str {
        "finish"
    }
    
    async fn run(&self, args: Value) -> Result<Value> {
        // For Finish, we expect either a string or a JSON object with an "answer" field
        let answer = match args {
            Value::String(_) => args,
            Value::Object(_) => {
                if let Some(answer_text) = args.get("answer").and_then(|a| a.as_str()) {
                    Value::String(answer_text.to_string())
                } else {
                    args
                }
            },
            _ => args,
        };
        
        Ok(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio_test::block_on;

    #[test]
    fn es_tools_mock() {
        // Test EsSearch
        let es_search = EsSearch::default_instance().unwrap();
        let result = block_on(es_search.run(json!({"query": "ip:192.168.1.1"})));
        // The real implementation would fail without Elasticsearch, but we're just testing the interface
        assert!(result.is_err());
        
        // Test EsAgg
        let es_agg = EsAgg::default_instance().unwrap();
        let result = block_on(es_agg.run(json!({"field": "dst.port"})));
        // The real implementation would fail without Elasticsearch, but we're just testing the interface
        assert!(result.is_err());
        
        // Test Finish
        let finish = Finish::new();
        let answer = json!("Final answer text");
        let result = block_on(finish.run(answer.clone()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), answer);
    }
    
    #[tokio::test]
    async fn test_finish_with_object() {
        let finish = Finish::new();
        let answer_obj = json!({"answer": "This is the answer", "confidence": 0.9});
        let result = finish.run(answer_obj).await.unwrap();
        
        if let Value::String(answer_text) = result {
            assert_eq!(answer_text, "This is the answer");
        } else {
            // If not a string, it should return the original object
            assert_eq!(result, json!({"answer": "This is the answer", "confidence": 0.9}));
        }
    }
    
    // Mock tests would be added here if the mockito_tests feature is enabled
}