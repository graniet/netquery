use anyhow::{Result, anyhow};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{timeout, Duration};
use tracing::{debug, warn, info};
use uuid::Uuid;

use crate::tools::Tool;

/// A single step in the agent's execution
#[derive(Debug, Clone)]
pub struct Step {
    /// The name of the action/tool
    pub action: String,
    /// The arguments provided to the tool
    pub args: Value,
    /// The observation or response from the tool execution
    pub observation: Value,
}

/// Represents an LLM interface for agent tool use
#[async_trait]
pub trait Llm: Send + Sync {
    /// Call the LLM with a prompt and available tools
    async fn call_with_fn(&self, 
                         prompt: &str, 
                         tools: HashMap<String, Arc<dyn Tool + Send + Sync>>) 
                         -> Result<(String, Value)>;
}

/// Simple LLM implementation for testing
#[cfg(test)]
pub struct MockLlm {
    pub responses: Vec<(String, Value)>,
    pub current: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl MockLlm {
    pub fn new(responses: Vec<(String, Value)>) -> Self {
        Self {
            responses,
            current: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

#[cfg(test)]
#[async_trait]
impl Llm for MockLlm {
    async fn call_with_fn(&self, 
                         _prompt: &str, 
                         _tools: HashMap<String, Arc<dyn Tool + Send + Sync>>) 
                         -> Result<(String, Value)> {
        let current = self.current.load(std::sync::atomic::Ordering::SeqCst);
        if current >= self.responses.len() {
            return Err(anyhow!("No more mock responses"));
        }
        
        let response = self.responses[current].clone();
        self.current.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        
        Ok(response)
    }
}

/// The main Agent struct that handles the conversational flow
pub struct Agent {
    /// Agent identifier
    id: Uuid,
    /// LLM interface for generating responses
    llm: Box<dyn Llm>,
    /// Steps taken so far in the conversation
    steps: Vec<Step>,
    /// Maximum number of turns allowed in a conversation
    max_turns: u8,
    /// Available tools that the agent can use
    tools: HashMap<String, Arc<dyn Tool + Send + Sync>>,
    /// Timestamp when the agent was created
    created_at: chrono::DateTime<chrono::Utc>,
}

impl Agent {
    /// Create a new Agent with the given LLM and max turns
    pub fn new(llm: Box<dyn Llm>, max_turns: u8) -> Self {
        Self {
            id: Uuid::new_v4(),
            llm,
            steps: Vec::new(),
            max_turns,
            tools: HashMap::new(),
            created_at: chrono::Utc::now(),
        }
    }
    
    /// Get the agent's unique identifier
    pub fn id(&self) -> Uuid {
        self.id
    }
    
    /// Get the agent's creation timestamp
    pub fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.created_at
    }
    
    /// Get the number of steps taken
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }
    
    /// Get a reference to the steps taken
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }
    
    /// Register a tool with the agent
    pub async fn register_tool(&mut self, tool: Arc<dyn Tool + Send + Sync>) -> Result<()> {
        let name = tool.name().await.to_string();
        info!("Registering tool: {}", name);
        self.tools.insert(name, tool);
        Ok(())
    }
    
    /// Execute a single step based on user input
    /// Returns Some(answer) when a final answer is reached, None otherwise
    pub async fn step(&mut self, user: &str) -> Result<Option<String>> {
        // Check if maximum turns reached
        if self.steps.len() >= self.max_turns as usize {
            return Ok(Some("I apologize, but I've reached my maximum number of steps. Let me summarize what I know so far...".to_string()));
        }
        
        // Build the prompt with system instructions and conversation history
        let prompt = self.build_prompt(user);
        
        // Call the LLM to get the next action
        debug!("Calling LLM with prompt of length {}", prompt.len());
        let (tool_name, args) = self.llm.call_with_fn(&prompt, self.tools.clone()).await?;
        
        // Check if the tool exists
        if !self.tools.contains_key(&tool_name) {
            warn!("Tool '{}' not found", tool_name);
            return Err(anyhow!("Tool '{}' not found", tool_name));
        }
        
        // Execute the tool with timeout
        let tool = self.tools.get(&tool_name).unwrap().clone();
        let args_clone = args.clone();
        
        debug!("Executing tool: {} with args: {}", tool_name, args_clone);
        let observation = match timeout(Duration::from_secs(3), tool.run(args_clone)).await {
            Ok(result) => {
                match result {
                    Ok(value) => value,
                    Err(err) => Value::String(format!("Error: {}", err)),
                }
            },
            Err(_) => Value::String("Error: Tool execution timed out".to_string()),
        };
        
        // Record the step
        self.steps.push(Step {
            action: tool_name.clone(),
            args,
            observation: observation.clone(),
        });
        
        // Keep only the last 20 steps if we have more (as per guard-rails in the task)
        if self.steps.len() > 20 {
            self.steps = self.steps.drain(self.steps.len() - 20..).collect();
        }
        
        // If the tool was "finish", return the answer
        if tool_name == "finish" {
            if let Some(answer) = observation.as_str() {
                return Ok(Some(answer.to_string()));
            } else {
                return Ok(Some("I've completed my analysis.".to_string()));
            }
        }
        
        // Otherwise, continue the conversation
        Ok(None)
    }
    
    /// Build the prompt for the LLM
    fn build_prompt(&self, user_input: &str) -> String {
        let mut prompt = String::new();
        
        // Add system prompt from file
        prompt.push_str(&Self::load_system_prompt());
        prompt.push_str("\n\n");
        
        // Add conversation history
        for step in &self.steps {
            prompt.push_str(&format!("Tool: {}\nArguments: {}\nObservation: {}\n\n", 
                                    step.action, step.args, step.observation));
        }
        
        // Add user input
        prompt.push_str(&format!("User: {}\n\n", user_input));
        
        // Add instruction for tool use
        prompt.push_str("To answer the user's question, you should use the available tools.");
        
        debug!("Prompt size: {} bytes, with {} conversation steps", prompt.len(), self.steps.len());
        
        prompt
    }
    
    /// Load system prompt from file
    fn load_system_prompt() -> String {
        // In a production environment, we would handle errors better
        // and possibly cache the prompt after first load
        match std::fs::read_to_string("./crates/agent_core/prompts/agent_system.txt") {
            Ok(content) => content,
            Err(_) => {
                // Fallback to a basic prompt if file can't be read
                warn!("Could not load system prompt file, using fallback");
                "You are NetQuery Assistant, an AI agent specializing in network data analysis. Your role is to help users understand network traffic patterns, identify anomalies, and answer questions about network connections. You can use es_search, es_agg, and finish tools.".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use crate::tools::Finish;
    use std::sync::Arc;
    
    #[tokio::test]
    async fn finish_within_turns() {
        // Create a mock LLM that first uses a tool then finishes
        let mock_responses = vec![
            ("es_search".to_string(), json!({"query": "ip:192.168.1.1"})),
            ("finish".to_string(), json!("The IP 192.168.1.1 has been found in our data.")),
        ];
        
        let llm = MockLlm::new(mock_responses);
        let mut agent = Agent::new(Box::new(llm), 6);
        
        // Register a finish tool
        let finish_tool = Arc::new(Finish::new());
        agent.register_tool(finish_tool).await.unwrap();
        
        // Register a mock search tool
        let mock_search = Arc::new(EsSearch::default_instance().unwrap());
        agent.register_tool(mock_search).await.unwrap();
        
        // First step should return None (no final answer yet)
        let response = agent.step("Find information about 192.168.1.1").await.unwrap();
        assert!(response.is_none());
        
        // Second step should return the final answer
        let response = agent.step("What did you find?").await.unwrap();
        assert!(response.is_some());
        assert_eq!(response.unwrap(), "The IP 192.168.1.1 has been found in our data.");
        
        // Check steps
        assert_eq!(agent.steps.len(), 2);
        assert_eq!(agent.steps[0].action, "es_search");
        assert_eq!(agent.steps[1].action, "finish");
    }
    
    use crate::tools::EsSearch;
    
    #[tokio::test]
    async fn truncate_steps_after_limit() {
        // Create a tool that always returns the same response
        let mock_responses = vec![
            ("es_search".to_string(), json!({"query": "ip:192.168.1.1"})),
            ("es_search".to_string(), json!({"query": "ip:192.168.1.2"})),
            ("es_search".to_string(), json!({"query": "ip:192.168.1.3"})),
            // Add 20 more steps to exceed the limit
            ("es_search".to_string(), json!({"query": "step4"})),
            ("es_search".to_string(), json!({"query": "step5"})),
            ("es_search".to_string(), json!({"query": "step6"})),
            ("es_search".to_string(), json!({"query": "step7"})),
            ("es_search".to_string(), json!({"query": "step8"})),
            ("es_search".to_string(), json!({"query": "step9"})),
            ("es_search".to_string(), json!({"query": "step10"})),
            ("es_search".to_string(), json!({"query": "step11"})),
            ("es_search".to_string(), json!({"query": "step12"})),
            ("es_search".to_string(), json!({"query": "step13"})),
            ("es_search".to_string(), json!({"query": "step14"})),
            ("es_search".to_string(), json!({"query": "step15"})),
            ("es_search".to_string(), json!({"query": "step16"})),
            ("es_search".to_string(), json!({"query": "step17"})),
            ("es_search".to_string(), json!({"query": "step18"})),
            ("es_search".to_string(), json!({"query": "step19"})),
            ("es_search".to_string(), json!({"query": "step20"})),
            ("es_search".to_string(), json!({"query": "step21"})),
            ("es_search".to_string(), json!({"query": "step22"})),
            ("finish".to_string(), json!("Final answer after many steps")),
        ];
        
        let llm = MockLlm::new(mock_responses);
        let mut agent = Agent::new(Box::new(llm), 25); // Allow up to 25 turns
        
        // Register tools
        let finish_tool = Arc::new(Finish::new());
        agent.register_tool(finish_tool).await.unwrap();
        
        let mock_search = Arc::new(EsSearch::default_instance().unwrap());
        agent.register_tool(mock_search).await.unwrap();
        
        // Run steps until we get a final answer
        let mut final_answer = None;
        for i in 0..25 {
            let response = agent.step(&format!("Query {}", i)).await.unwrap();
            if response.is_some() {
                final_answer = response;
                break;
            }
        }
        
        // Verify final answer
        assert_eq!(final_answer, Some("Final answer after many steps".to_string()));
        
        // Verify that history was truncated to 20 steps
        assert_eq!(agent.steps().len(), 20);
        
        // The first few steps should have been truncated
        assert_eq!(agent.steps()[0].args, json!({"query": "step4"}));
        assert_eq!(agent.steps()[19].action, "finish");
    }
}