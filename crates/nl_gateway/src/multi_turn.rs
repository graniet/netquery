use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::sync::OnceLock;
use tokio::sync::mpsc as tokio_mpsc;
use tracing::{debug, error, info};

use crate::NlGatewayError;

/// Represents a single step in a multi-turn conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub action: String,
    pub args: Value,
    pub obs: String,
}

/// Represents a thinking event for streaming progress updates.
#[derive(Debug, Clone)]
pub struct ThinkingEvent {
    /// The action being performed.
    pub action: String,
    /// Description of the current step.
    pub step_info: String,
    /// Current step number.
    pub step_number: i32,
    /// Total number of steps taken so far.
    pub total_steps: i32,
}

/// Function call types for the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "name", content = "arguments")]
pub enum FunctionCall {
    #[serde(rename = "es_search")]
    EsSearch { query: Value, target_index: String },

    #[serde(rename = "es_agg")]
    EsAgg { query: Value, target_index: String },

    #[serde(rename = "finish")]
    Finish { answer: String },
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

/// Executes the Elasticsearch query and returns the results.
async fn execute_es_query(
    es_url: &str,
    query: &Value,
    target_index: &str,
) -> Result<String, NlGatewayError> {
    let client = get_client();

    let index_name = if target_index.contains('*') {
        target_index.to_string()
    } else if target_index.matches(|c| c == '.').count() >= 2
        && target_index.matches(|c| c == '-').count() >= 1
    {
        target_index.to_string()
    } else {
        format!("{}-*", target_index)
    };

    let search_url = format!("{}/{}/_search", es_url, index_name);

    let query_str = serde_json::to_string_pretty(query).unwrap_or_else(|_| query.to_string());
    debug!("Elasticsearch query: {}", query_str);

    let query_str = serde_json::to_string(query).unwrap_or_else(|_| "Invalid JSON".to_string());
    info!("Raw query JSON: {}", query_str);

    let wrapped_query = serde_json::json!({
        "query": { "match_all": {} },
        "size": 10
    });

    let response = client
        .post(&search_url)
        .header("Content-Type", "application/json")
        .json(&wrapped_query)
        .send()
        .await
        .map_err(|e| NlGatewayError::ElasticsearchError(format!("Search request failed: {}", e)))?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());

        return Err(NlGatewayError::ElasticsearchError(format!(
            "Elasticsearch returned error: {} - {}",
            status, error_text
        )));
    }

    let result = response.text().await.map_err(|e| {
        NlGatewayError::ElasticsearchError(format!("Failed to get response text: {}", e))
    })?;

    let response_json: Value = serde_json::from_str(&result).map_err(|e| {
        NlGatewayError::ElasticsearchError(format!("Failed to parse JSON: {}", e))
    })?;

    let pretty_json = serde_json::to_string_pretty(&response_json).map_err(|e| {
        NlGatewayError::ElasticsearchError(format!("Failed to prettify JSON: {}", e))
    })?;

    let max_length = 10000;
    if pretty_json.len() > max_length {
        Ok(format!(
            "{}\n... (truncated, total size: {})",
            &pretty_json[..max_length],
            pretty_json.len()
        ))
    } else {
        Ok(pretty_json)
    }
}

/// Stores the conversation history.
#[derive(Debug, Clone, Default)]
pub struct Conversation {
    pub steps: Vec<Step>,
    /// (User, Assistant) message pairs.
    pub messages: Vec<(String, String)>,
}

impl Conversation {
    pub fn new() -> Self {
        Self {
            steps: Vec::new(),
            messages: Vec::new(),
        }
    }

    pub fn add_message(&mut self, user: &str, assistant: &str) {
        self.messages.push((user.to_string(), assistant.to_string()));
    }
}

/// Thread-safe conversation storage with interior mutability.
pub type ConversationStore = std::sync::Arc<tokio::sync::Mutex<Conversation>>;

/// Creates a new conversation store.
pub fn new_conversation_store() -> ConversationStore {
    std::sync::Arc::new(tokio::sync::Mutex::new(Conversation::new()))
}

static CONVERSATION: OnceLock<ConversationStore> = OnceLock::new();

/// Gets or initializes the conversation history.
fn get_conversation() -> ConversationStore {
    CONVERSATION.get_or_init(|| new_conversation_store()).clone()
}

/// Executes a multi-turn conversation with the LLM (non-streaming version).
pub async fn run(question: &str) -> String {
    let (answer, _) = run_with_events(question, None).await;

    let conv = get_conversation();
    let mut conv_guard = conv.lock().await;
    conv_guard.add_message(question, &answer);
    drop(conv_guard);

    answer
}

/// Executes a multi-turn conversation with the LLM and emits events.
pub async fn run_with_events(
    question: &str,
    tx: Option<tokio_mpsc::Sender<ThinkingEvent>>,
) -> (String, Vec<Step>) {
    let api_key = match get_openai_api_key() {
        Ok(key) => key,
        Err(_) => {
            return (
                "Error: OpenAI API key not found. Please set the OPENAI_API_KEY environment variable."
                    .to_string(),
                Vec::new(),
            )
        }
    };

    let system_prompt = include_str!("../prompts/multi_turn.txt");
    let es_url = std::env::var("ELASTICSEARCH_URL").unwrap_or_else(|_| {
        info!("ELASTICSEARCH_URL not set, using default");
        "http://elasticsearch:9200".to_string()
    });
    info!("Using Elasticsearch URL: {}", es_url);

    let mut steps: Vec<Step> = Vec::new();

    for turn in 0..6 {
        debug!("Turn {}/6", turn + 1);

        if let Some(tx) = &tx {
            let step_info = if steps.is_empty() {
                "Analyzing question".to_string()
            } else {
                match steps.last() {
                    Some(step) => format!("Processing {} results", step.action),
                    None => "Processing results".to_string(),
                }
            };

            let thinking_event = ThinkingEvent {
                action: if steps.is_empty() {
                    "start".to_string()
                } else {
                    steps.last().unwrap().action.clone()
                },
                step_info,
                step_number: turn + 1,
                total_steps: steps.len() as i32,
            };

            let _ = tx.send(thinking_event).await;
        }

        let mut messages = Vec::new();
        messages.push(serde_json::json!({
            "role": "system",
            "content": system_prompt
        }));

        let recent_steps = if steps.len() > 20 {
            &steps[steps.len() - 20..]
        } else {
            &steps
        };

        for step in recent_steps {
            messages.push(serde_json::json!({
                "role": "assistant",
                "content": null,
                "function_call": {
                    "name": step.action,
                    "arguments": serde_json::to_string(&step.args).unwrap()
                }
            }));

            messages.push(serde_json::json!({
                "role": "user",
                "content": format!("Observation: {}", step.obs)
            }));
        }

        let conversation_history = if steps.is_empty() {
            let conv = get_conversation();
            let conv_guard = conv.lock().await;

            let mut history = Vec::new();
            if !conv_guard.messages.is_empty() {
                for (i, (user_msg, assistant_msg)) in conv_guard.messages.iter().enumerate() {
                    if i >= conv_guard.messages.len().saturating_sub(5) {
                        history.push((user_msg.clone(), assistant_msg.clone()));
                    }
                }
            }

            drop(conv_guard);
            history
        } else {
            Vec::new()
        };

        for (user_msg, assistant_msg) in conversation_history {
            messages.push(serde_json::json!({
                "role": "user",
                "content": user_msg
            }));

            messages.push(serde_json::json!({
                "role": "assistant",
                "content": assistant_msg
            }));
        }

        if steps.is_empty() {
            messages.push(serde_json::json!({
                "role": "user",
                "content": question
            }));
        }

        let functions = serde_json::json!([
            {
                "name": "es_search",
                "description": "Execute an Elasticsearch search query",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "object",
                            "description": "Elasticsearch DSL query object"
                        },
                        "target_index": {
                            "type": "string",
                            "description": "Target Elasticsearch index pattern",
                            "default": "netquery-flows-*"
                        }
                    },
                    "required": ["query", "target_index"]
                }
            },
            {
                "name": "es_agg",
                "description": "Execute an Elasticsearch aggregation query",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "object",
                            "description": "Elasticsearch DSL query with aggregations"
                        },
                        "target_index": {
                            "type": "string",
                            "description": "Target Elasticsearch index pattern",
                            "default": "netquery-flows-*"
                        }
                    },
                    "required": ["query", "target_index"]
                }
            },
            {
                "name": "finish",
                "description": "Provide a final answer to the user's question",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "answer": {
                            "type": "string",
                            "description": "The final answer to the user's question"
                        }
                    },
                    "required": ["answer"]
                }
            }
        ]);

        let request_body = serde_json::json!({
            "model": "gpt-4o",
            "messages": messages,
            "functions": functions,
            "temperature": 0.1
        });

        let client = get_client();
        let response = match client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                error!("OpenAI API request failed: {}", e);
                return (
                    format!("Error: Failed to communicate with OpenAI API: {}", e),
                    steps,
                );
            }
        };

        let response_status = response.status();
        if !response_status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            error!("OpenAI API error: {} - {}", response_status, error_text);
            return (format!("Error from OpenAI API: {}", error_text), steps);
        }

        let response_json: Value = match response.json().await {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to parse OpenAI response: {}", e);
                return (
                    "Error: Failed to parse response from OpenAI API".to_string(),
                    steps,
                );
            }
        };

        let function_call =
            match response_json["choices"][0]["message"]["function_call"].as_object() {
                Some(fc) => fc,
                None => {
                    if let Some(content) =
                        response_json["choices"][0]["message"]["content"].as_str()
                    {
                        info!("Model returned text response instead of function call");
                        return (content.to_string(), steps);
                    } else {
                        error!(
                            "No function call or content in response: {:?}",
                            response_json
                        );
                        return (
                            "Error: No function call or content in response from OpenAI API"
                                .to_string(),
                            steps,
                        );
                    }
                }
            };

        let function_name = match function_call.get("name").and_then(|n| n.as_str()) {
            Some(name) => name,
            None => {
                error!("No function name in function call");
                return ("Error: Invalid response from OpenAI API".to_string(), steps);
            }
        };

        let arguments = match function_call.get("arguments").and_then(|a| a.as_str()) {
            Some(args) => args,
            None => {
                error!("No arguments in function call");
                return ("Error: Invalid response from OpenAI API".to_string(), steps);
            }
        };

        let args_value: Value = match serde_json::from_str(arguments) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to parse function arguments: {}", e);
                return (
                    "Error: Invalid function arguments from OpenAI API".to_string(),
                    steps,
                );
            }
        };

        match function_name {
            "es_search" | "es_agg" => {
                let query = args_value.get("query").cloned().unwrap_or(Value::Null);
                let target_index = args_value
                    .get("target_index")
                    .and_then(|s| s.as_str())
                    .unwrap_or("netquery-flows-*");

                if let Some(tx) = &tx {
                    let step_info = format!("Executing {} on {}", function_name, target_index);
                    let thinking_event = ThinkingEvent {
                        action: function_name.to_string(),
                        step_info,
                        step_number: turn + 1,
                        total_steps: steps.len() as i32 + 1,
                    };
                    let _ = tx.send(thinking_event).await;
                }

                debug!("Executing ES query on index: {}", target_index);

                let result = match execute_es_query(&es_url, &query, target_index).await {
                    Ok(resp) => resp,
                    Err(e) => {
                        error!("Elasticsearch query failed: {}", e);
                        format!("Error executing Elasticsearch query: {}", e)
                    }
                };

                steps.push(Step {
                    action: function_name.to_string(),
                    args: args_value,
                    obs: result,
                });
            }
            "finish" => {
                let answer = args_value
                    .get("answer")
                    .and_then(|a| a.as_str())
                    .unwrap_or("I couldn't find a definitive answer.");

                if let Some(tx) = &tx {
                    let thinking_event = ThinkingEvent {
                        action: "finish".to_string(),
                        step_info: "Generating final answer".to_string(),
                        step_number: turn + 1,
                        total_steps: steps.len() as i32 + 1,
                    };
                    let _ = tx.send(thinking_event).await;
                }

                info!("Finishing with answer after {} turns", turn + 1);
                return (answer.to_string(), steps);
            }
            _ => {
                error!("Unknown function name: {}", function_name);
                return (
                    "Error: Unknown function called by OpenAI API".to_string(),
                    steps,
                );
            }
        }
    }

    (
        "I couldn't find a definitive answer after multiple queries. Please try rephrasing your question.".to_string(),
        steps,
    )
}