use anyhow::Result;
use chrono::Utc;
use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;
use tracing::{error, info, warn};

/// Structure responsible for Elasticsearch template and index setup
pub struct ElasticsearchBootstrap {
    client: Client,
    url: String,
    username: Option<String>,
    password: Option<String>,
    index_prefix: String,
}

impl ElasticsearchBootstrap {
    /// Create a new bootstrap instance
    pub fn new(
        url: String,
        username: Option<String>,
        password: Option<String>,
        index_prefix: String,
    ) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            url,
            username,
            password,
            index_prefix,
        }
    }

    /// Create the component template, ILM policy, and index template if they don't exist
    pub async fn bootstrap(&self) -> Result<()> {
        info!("Starting Elasticsearch bootstrap");

        self.ensure_template().await?;
        self.ensure_ilm_policy().await?;
        self.ensure_today_index().await?;

        info!("Elasticsearch bootstrap completed successfully");
        Ok(())
    }

    /// Ensure the index template exists
    async fn ensure_template(&self) -> Result<()> {
        let template_name = format!("{}-template", self.index_prefix);
        let template_url = format!("{}/_index_template/{}", self.url, template_name);
        let exists = self.check_exists(&template_url).await?;

        if !exists {
            info!("Creating index template: {}", template_name);
            let template = json!({
                "index_patterns": [format!("{}*", self.index_prefix)],
                "template": {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0,
                        "index.lifecycle.name": format!("{}-policy", self.index_prefix),
                        "index.lifecycle.rollover_alias": self.index_prefix
                    },
                    "mappings": {
                        "properties": {
                            "@timestamp": { "type": "date" },
                            "bucket_start": { "type": "date" },
                            "bucket_end": { "type": "date" },
                            "src": {
                                "properties": {
                                    "ip": { "type": "keyword" },
                                    "port": { "type": "integer" }
                                }
                            },
                            "dst": {
                                "properties": {
                                    "ip": { "type": "keyword" },
                                    "port": { "type": "integer" }
                                }
                            },
                            "protocol": { "type": "keyword" },
                            "bytes": { "type": "long" },
                            "packets": { "type": "long" },
                            "flags": { "type": "integer" },
                            "icmp_type": { "type": "integer" },
                            "icmp_code": { "type": "integer" }
                        }
                    }
                }
            });

            let put_response = self
                .send_request(reqwest::Method::PUT, &template_url, Some(template))
                .await?;

            if !put_response.status().is_success() {
                let error = put_response.text().await.unwrap_or_default();
                error!("Failed to create template: {}", error);
                return Err(anyhow::anyhow!("Failed to create template: {}", error));
            }

            info!("Index template created successfully");
        } else {
            info!("Index template already exists");
        }

        Ok(())
    }

    /// Ensure the ILM policy exists
    async fn ensure_ilm_policy(&self) -> Result<()> {
        let policy_name = format!("{}-policy", self.index_prefix);
        let policy_url = format!("{}/_ilm/policy/{}", self.url, policy_name);
        let exists = self.check_exists(&policy_url).await?;

        if !exists {
            info!("Creating ILM policy: {}", policy_name);
            let policy = json!({
                "policy": {
                    "phases": {
                        "hot": {
                            "min_age": "0ms",
                            "actions": {}
                        },
                        "delete": {
                            "min_age": "60d",
                            "actions": {
                                "delete": {}
                            }
                        }
                    }
                }
            });

            let put_response = self
                .send_request(reqwest::Method::PUT, &policy_url, Some(policy))
                .await?;

            if !put_response.status().is_success() {
                let error = put_response.text().await.unwrap_or_default();
                error!("Failed to create ILM policy: {}", error);
                return Err(anyhow::anyhow!("Failed to create ILM policy: {}", error));
            }

            info!("ILM policy created successfully");
        } else {
            info!("ILM policy already exists");
        }

        Ok(())
    }

    /// Ensure today's index exists and has the correct mapping
    async fn ensure_today_index(&self) -> Result<()> {
        let date = Utc::now().format("%Y.%m.%d").to_string();
        let index_name = format!("{}-{}", self.index_prefix, date);
        let index_url = format!("{}/{}", self.url, index_name);
        let exists = self.check_exists(&index_url).await?;

        if !exists {
            info!("Creating today's index: {}", index_name);
            let response = self
                .send_request(reqwest::Method::PUT, &index_url, None)
                .await?;

            if !response.status().is_success() {
                let error = response.text().await.unwrap_or_default();
                warn!(
                    "Failed to create index: {}. It will be created on first ingest.",
                    error
                );
            } else {
                info!("Today's index created successfully");
            }
        }

        self.ensure_protocol_field(&index_name).await?;

        Ok(())
    }

    /// Ensure the protocol field exists in the mapping
    async fn ensure_protocol_field(&self, index_name: &str) -> Result<()> {
        let mapping_url = format!("{}/_mapping", self.index_url(index_name));
        let response = self
            .send_request(reqwest::Method::GET, &mapping_url, None)
            .await?;

        let has_protocol_field = if response.status().is_success() {
            let mapping: Value = response.json().await?;
            mapping
                .get(index_name)
                .and_then(|idx| idx.get("mappings"))
                .and_then(|mappings| mappings.get("properties"))
                .and_then(|props| props.get("protocol"))
                .is_some()
        } else {
            false
        };

        if !has_protocol_field {
            info!("Adding protocol field to index mapping: {}", index_name);
            let protocol_mapping = json!({
                "properties": {
                    "protocol": { "type": "keyword" }
                }
            });

            let put_response = self
                .send_request(reqwest::Method::PUT, &mapping_url, Some(protocol_mapping))
                .await?;

            if !put_response.status().is_success() {
                let error = put_response.text().await.unwrap_or_default();
                error!("Failed to update mapping: {}", error);
                return Err(anyhow::anyhow!("Failed to update mapping: {}", error));
            }

            info!("Protocol field added to mapping successfully");
        } else {
            info!("Protocol field already exists in mapping");
        }

        Ok(())
    }

    /// Check if a resource exists
    async fn check_exists(&self, url: &str) -> Result<bool> {
        let response = self
            .client
            .head(url)
            .basic_auth_maybe(&self.username, &self.password)
            .send()
            .await?;

        Ok(response.status().is_success())
    }

    /// Build full index URL
    fn index_url(&self, index_name: &str) -> String {
        format!("{}/{}", self.url, index_name)
    }

    /// Send a request with optional JSON body
    async fn send_request(
        &self,
        method: reqwest::Method,
        url: &str,
        json_body: Option<Value>,
    ) -> Result<reqwest::Response> {
        let mut request = self.client.request(method, url);
        request = request.basic_auth_maybe(&self.username, &self.password);
        if let Some(body) = json_body {
            request = request
                .header("Content-Type", "application/json")
                .json(&body);
        }
        let response = request.send().await?;
        Ok(response)
    }
}

/// Extension trait for reqwest::RequestBuilder to add conditional basic auth
trait RequestBuilderExt {
    fn basic_auth_maybe(self, username: &Option<String>, password: &Option<String>) -> Self;
}

impl RequestBuilderExt for reqwest::RequestBuilder {
    fn basic_auth_maybe(self, username: &Option<String>, password: &Option<String>) -> Self {
        match (username, password) {
            (Some(u), Some(p)) => self.basic_auth(u, Some(p)),
            _ => self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    #[tokio::test]
    async fn test_bootstrap_with_existing_template() {
        let mut server = Server::new();
        let template_mock = server
            .mock("HEAD", "/_index_template/netquery-flows-template")
            .with_status(200)
            .create();
        let policy_mock = server
            .mock("HEAD", "/_ilm/policy/netquery-flows-policy")
            .with_status(200)
            .create();
        let today = Utc::now().format("%Y.%m.%d").to_string();
        let index_name = format!("netquery-flows-{}", today);
        let index_mock = server
            .mock("HEAD", &format!("/{}", index_name))
            .with_status(200)
            .create();
        let mapping_mock = server
            .mock("GET", &format!("/{}/_mapping", index_name))
            .with_status(200)
            .with_body(format!(
                r#"{{
                "{}": {{
                    "mappings": {{
                        "properties": {{
                            "protocol": {{ "type": "keyword" }}
                        }}
                    }}
                }}
            }}"#,
                index_name
            ))
            .create();
        let bootstrap =
            ElasticsearchBootstrap::new(server.url(), None, None, "netquery-flows".to_string());
        let result = bootstrap.bootstrap().await;
        assert!(result.is_ok());
        template_mock.assert();
        policy_mock.assert();
        index_mock.assert();
        mapping_mock.assert();
    }

    #[tokio::test]
    async fn test_bootstrap_with_missing_template() {
        let mut server = Server::new();
        let template_check_mock = server
            .mock("HEAD", "/_index_template/netquery-flows-template")
            .with_status(404)
            .create();
        let template_create_mock = server
            .mock("PUT", "/_index_template/netquery-flows-template")
            .with_status(200)
            .with_body(r#"{"acknowledged": true}"#)
            .create();
        let policy_mock = server
            .mock("HEAD", "/_ilm/policy/netquery-flows-policy")
            .with_status(200)
            .create();
        let today = Utc::now().format("%Y.%m.%d").to_string();
        let index_name = format!("netquery-flows-{}", today);
        let index_mock = server
            .mock("HEAD", &format!("/{}", index_name))
            .with_status(200)
            .create();
        let mapping_mock = server
            .mock("GET", &format!("/{}/_mapping", index_name))
            .with_status(200)
            .with_body(format!(
                r#"{{
                "{}": {{
                    "mappings": {{
                        "properties": {{
                            "protocol": {{ "type": "keyword" }}
                        }}
                    }}
                }}
            }}"#,
                index_name
            ))
            .create();
        let bootstrap =
            ElasticsearchBootstrap::new(server.url(), None, None, "netquery-flows".to_string());
        let result = bootstrap.bootstrap().await;
        assert!(result.is_ok());
        template_check_mock.assert();
        template_create_mock.assert();
        policy_mock.assert();
        index_mock.assert();
        mapping_mock.assert();
    }
}
