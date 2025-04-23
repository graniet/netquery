use clap::{Arg, ArgAction, Command};
use colored::*;
use daemon::pb::{net_query_client::NetQueryClient, AskRequest, MetricsRequest, StatusRequest};
use indicatif::{ProgressBar, ProgressStyle};
use std::error::Error;
use std::io::{self, Write};
use std::time::Duration;
use tonic::transport::Channel;
use tracing::{debug, Level};

/// Connect to the NetQuery server and return a gRPC client.
async fn connect_to_server(server_addr: &str) -> Result<NetQueryClient<Channel>, Box<dyn Error>> {
    let client = NetQueryClient::connect(format!("http://{}", server_addr)).await?;
    Ok(client)
}

/// Send a natural language query to the server and print the result.
/// If `json` is true, output is formatted as JSON.
async fn cmd_ask(
    client: &mut NetQueryClient<Channel>,
    query: &str,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let start = std::time::Instant::now();

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
            .template("{spinner} Thinking... (using ask.llm multi-turn mode)")
            .unwrap(),
    );
    spinner.enable_steady_tick(Duration::from_millis(120));

    let request = AskRequest {
        query: query.to_string(),
        language: "".to_string(),
    };

    let stream_request = request.clone();
    let stream_response = client.ask_stream(stream_request);
    let spinner_clone = spinner.clone();

    match stream_response.await {
        Ok(stream) => {
            let mut stream = stream.into_inner();
            tokio::spawn(async move {
                while let Some(event) = stream.message().await.unwrap_or(None) {
                    spinner_clone.set_message(format!("Thinking... {}", event.step_info));
                }
            });
        }
        Err(_) => {
            debug!("Streaming not supported, using basic spinner");
        }
    }

    let response = client.ask(request).await?;
    let response = response.into_inner();

    spinner.finish_and_clear();

    let elapsed = start.elapsed();
    debug!("Query took: {:?}", elapsed);

    if json {
        let mut json_output = String::new();
        json_output.push_str("{\n");
        json_output.push_str(&format!("  \"result\": \"{}\",\n", response.result));
        json_output.push_str(&format!(
            "  \"query_time_ms\": {},\n",
            response.query_time_ms
        ));
        json_output.push_str(&format!("  \"total_flows\": {},\n", response.total_flows));
        json_output.push_str("  \"flows\": []\n");
        json_output.push_str("}");
        println!("{}", json_output);
    } else {
        println!("{}", response.result);
        println!(
            "Query time: {}ms, Total flows: {}",
            response.query_time_ms, response.total_flows
        );
    }

    Ok(())
}

/// Request metrics from the server and print them.
/// If `json` is true, output is formatted as JSON.
async fn cmd_metrics(
    client: &mut NetQueryClient<Channel>,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let request = MetricsRequest {};
    let response = client.get_metrics(request).await?;
    let response = response.into_inner();

    if json {
        let json_output = format!(
            "{{
  \"packets_captured\": {},
  \"packets_dropped\": {},
  \"packets_processed\": {},
  \"current_window_count\": {},
  \"total_flows\": {},
  \"memory_usage_bytes\": {}
}}",
            response.packets_captured,
            response.packets_dropped,
            response.packets_processed,
            response.current_window_count,
            response.total_flows,
            response.memory_usage_bytes
        );
        println!("{}", json_output);
    } else {
        let drop_rate = if response.packets_captured + response.packets_dropped > 0 {
            (response.packets_dropped as f64
                / (response.packets_captured + response.packets_dropped) as f64)
                * 100.0
        } else {
            0.0
        };

        let mb = 1024 * 1024;
        let memory_mb = response.memory_usage_bytes as f64 / mb as f64;

        println!("{}", "NetQuery Metrics".green().bold());
        println!("Packets captured:  {}", response.packets_captured);
        println!(
            "Packets dropped:   {} ({:.2}%)",
            response.packets_dropped, drop_rate
        );
        println!("Packets processed: {}", response.packets_processed);
        println!("Current windows:   {}", response.current_window_count);
        println!("Total flows:       {}", response.total_flows);
        println!("Memory usage:      {:.2} MB", memory_mb);
    }

    Ok(())
}

/// Request the status of the daemon and print it.
/// If `json` is true, output is formatted as JSON.
async fn cmd_status(
    client: &mut NetQueryClient<Channel>,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let request = StatusRequest {};
    let response = client.get_status(request).await?;
    let response = response.into_inner();

    let status_str = match response.status {
        0 => "Unknown",
        1 => "Starting",
        2 => "Running",
        3 => "Degraded",
        4 => "Stopping",
        5 => "Stopped",
        _ => "Invalid",
    };

    if json {
        let json_output = format!(
            "{{
  \"status\": \"{}\",
  \"status_code\": {},
  \"version\": \"{}\",
  \"uptime_seconds\": {},
  \"interface\": \"{}\"
}}",
            status_str,
            response.status,
            response.version,
            response.uptime_seconds,
            response.interface
        );
        println!("{}", json_output);
    } else {
        let uptime_duration = Duration::from_secs(response.uptime_seconds as u64);
        let days = uptime_duration.as_secs() / 86400;
        let hours = (uptime_duration.as_secs() % 86400) / 3600;
        let minutes = (uptime_duration.as_secs() % 3600) / 60;
        let seconds = uptime_duration.as_secs() % 60;

        let uptime_str = if days > 0 {
            format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
        } else if hours > 0 {
            format!("{}h {}m {}s", hours, minutes, seconds)
        } else if minutes > 0 {
            format!("{}m {}s", minutes, seconds)
        } else {
            format!("{}s", seconds)
        };

        println!("{}", "NetQuery Status".green().bold());

        let status_colored = match response.status {
            2 => status_str.green().bold(),
            3 => status_str.yellow().bold(),
            5 => status_str.red().bold(),
            _ => status_str.normal(),
        };

        println!("Status:    {}", status_colored);
        println!("Version:   {}", response.version);
        println!("Uptime:    {}", uptime_str);
        println!("Interface: {}", response.interface);
    }

    Ok(())
}

/// Start the interactive CLI mode for NetQuery.
async fn interactive_mode(server_addr: &str) -> Result<(), Box<dyn Error>> {
    println!("{}", "NetQuery Interactive Mode".green().bold());
    println!("Connected to {}", server_addr);
    println!("Type a natural language query or 'exit' to quit.");
    println!();

    let mut client = connect_to_server(server_addr).await?;

    loop {
        print!("netquery> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        if input == "exit" || input == "quit" {
            break;
        }

        if input == "status" {
            cmd_status(&mut client, false).await?;
        } else if input == "metrics" {
            cmd_metrics(&mut client, false).await?;
        } else {
            let _ = cmd_ask(&mut client, input, false).await;
        }

        println!();
    }

    println!("Goodbye!");
    Ok(())
}

/// Start an interactive chat session with conversation history.
async fn cmd_chat_interactive(client: &mut NetQueryClient<Channel>, initial_query: &str) -> Result<(), Box<dyn Error>> {
    println!("{}", "NetQuery Chat Mode".green().bold());
    println!("Start a conversation with follow-up questions.");
    println!("Type 'exit' or 'quit' to end the session.");
    println!();
    
    println!("You: {}", initial_query.blue());
    
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
            .template("{spinner} Thinking... (using chat mode)")
            .unwrap(),
    );
    spinner.enable_steady_tick(Duration::from_millis(120));
    
    let request = AskRequest {
        query: initial_query.to_string(),
        language: "".to_string(),
    };
    
    let spinner_clone = spinner.clone();
    let stream_request = request.clone();
    match client.ask_stream(stream_request).await {
        Ok(stream) => {
            let mut stream = stream.into_inner();
            tokio::spawn(async move {
                while let Some(event) = stream.message().await.unwrap_or(None) {
                    spinner_clone.set_message(format!("Thinking... {}", event.step_info));
                }
            });
        }
        Err(_) => {
            debug!("Streaming not supported, using basic spinner");
        }
    }
    
    let response = client.ask(request).await?;
    let response = response.into_inner();
    
    spinner.finish_and_clear();
    
    println!("NetQuery: {}", response.result.trim().green());
    println!();
    
    loop {
        print!("You: ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        let input = input.trim();
        
        if input.is_empty() {
            continue;
        }
        
        if input == "exit" || input == "quit" {
            break;
        }
        
        println!("{}", input.blue());
        
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                .template("{spinner} Thinking... (with conversation history)")
                .unwrap(),
        );
        spinner.enable_steady_tick(Duration::from_millis(120));
        
        let request = AskRequest {
            query: input.to_string(),
            language: "".to_string(),
        };
        
        let spinner_clone = spinner.clone();
        let stream_request = request.clone();
        match client.ask_stream(stream_request).await {
            Ok(stream) => {
                let mut stream = stream.into_inner();
                tokio::spawn(async move {
                    while let Some(event) = stream.message().await.unwrap_or(None) {
                        spinner_clone.set_message(format!("Thinking... {}", event.step_info));
                    }
                });
            }
            Err(_) => {
                debug!("Streaming not supported, using basic spinner");
            }
        }
        
        let response = client.ask(request).await?;
        let response = response.into_inner();
        
        spinner.finish_and_clear();
        
        println!("NetQuery: {}", response.result.trim().green());
        println!();
    }
    
    println!("Chat session ended.");
    Ok(())
}

/// Entry point for the NetQuery CLI application.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if std::env::var("RUST_LOG").is_ok() {
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .init();
    }

    let matches = Command::new("netquery")
        .about("NetQuery CLI for network traffic analysis")
        .version("0.1.0")
        .subcommand_required(true)
        .arg(
            Arg::new("server")
                .short('s')
                .long("server")
                .help("Server address in host:port format")
                .default_value("[::1]:50051"),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .help("Output in JSON format")
                .action(ArgAction::SetTrue),
        )
        .subcommand(
            Command::new("ask")
                .about("Ask a natural language question about network traffic")
                .arg(
                    Arg::new("query")
                        .help("The query in natural language")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("chat")
                .about("Start a conversational session with history")
                .arg(
                    Arg::new("query")
                        .help("The initial question in natural language")
                        .required(true),
                ),
        )
        .subcommand(Command::new("status").about("Get the status of the daemon"))
        .subcommand(Command::new("metrics").about("Get performance metrics"))
        .subcommand(
            Command::new("interactive")
                .about("Start interactive mode")
                .alias("i"),
        )
        .get_matches();

    let server_addr = matches.get_one::<String>("server").unwrap();
    let json_output = matches.get_flag("json");

    let mut client = connect_to_server(server_addr).await?;

    match matches.subcommand() {
        Some(("ask", ask_matches)) => {
            let query = ask_matches.get_one::<String>("query").unwrap();
            cmd_ask(&mut client, query, json_output).await?;
        }
        Some(("chat", chat_matches)) => {
            let initial_query = chat_matches.get_one::<String>("query").unwrap();
            cmd_chat_interactive(&mut client, initial_query).await?;
        }
        Some(("status", _)) => {
            cmd_status(&mut client, json_output).await?;
        }
        Some(("metrics", _)) => {
            cmd_metrics(&mut client, json_output).await?;
        }
        Some(("interactive", _)) => {
            interactive_mode(server_addr).await?;
        }
        _ => unreachable!(),
    }

    Ok(())
}
