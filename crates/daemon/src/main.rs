use clap::{ArgAction, Parser};
use daemon::{DaemonConfig, NetQueryDaemon};
use pb::{
    net_query_server::{NetQuery, NetQueryServer},
    AskRequest, AskResponse, MetricsRequest, MetricsResponse, StatusRequest, StatusResponse,
    ThinkingEvent,
};
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use daemon::pb;

/// Command-line arguments for the NetQuery daemon.
#[derive(Parser)]
#[command(name = "netqueryd")]
#[command(about = "NetQuery daemon for network traffic analysis")]
struct Cli {
    /// Network interface to capture traffic from
    #[arg(short, long)]
    interface: Option<String>,

    /// Maximum capture size for packets
    #[arg(long, default_value = "65535")]
    snaplen: i32,

    /// Enable promiscuous mode
    #[arg(long, action = ArgAction::SetTrue)]
    promiscuous: bool,

    /// Buffer size for packet processing
    #[arg(long, default_value = "100000")]
    buffer_size: usize,

    /// Time window duration in seconds
    #[arg(long, default_value = "60")]
    window_duration: u64,

    /// Time window overlap in seconds
    #[arg(long, default_value = "10")]
    window_overlap: u64,

    /// Maximum entries per window
    #[arg(long, default_value = "1000000")]
    max_entries: usize,

    /// URL for Qdrant vector database
    #[arg(long, default_value = "http://localhost")]
    qdrant_url: String,

    /// Port for Qdrant vector database
    #[arg(long, default_value = "6334")]
    qdrant_port: u16,

    /// Path to local LLM model file (optional)
    #[arg(long)]
    model_path: Option<String>,

    /// gRPC listen address
    #[arg(long, default_value = "[::1]:50051")]
    grpc_addr: String,

    /// Elasticsearch URL
    #[arg(long, default_value = "http://elasticsearch:9200")]
    elasticsearch_url: String,

    /// Elasticsearch username (optional)
    #[arg(long)]
    elasticsearch_username: Option<String>,

    /// Elasticsearch password (optional)
    #[arg(long)]
    elasticsearch_password: Option<String>,

    /// Elasticsearch index prefix
    #[arg(long, default_value = "netquery-flows")]
    elasticsearch_index_prefix: String,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

/// gRPC service implementation for NetQuery.
struct NetQueryService {
    daemon: std::sync::Arc<tokio::sync::Mutex<NetQueryDaemon>>,
}

#[tonic::async_trait]
impl NetQuery for NetQueryService {
    /// Handle natural language query requests.
    async fn ask(&self, request: Request<AskRequest>) -> Result<Response<AskResponse>, Status> {
        let query = request.into_inner().query;

        let daemon = self.daemon.lock().await;
        let response = daemon
            .process_query(&query)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(response))
    }
    
    /// Handle streaming query requests with thinking steps.
    type AskStreamStream = ReceiverStream<Result<ThinkingEvent, Status>>;
    
    async fn ask_stream(
        &self,
        request: Request<AskRequest>,
    ) -> Result<Response<Self::AskStreamStream>, Status> {
        let query = request.into_inner().query;
        
        let (tx, rx) = mpsc::channel::<Result<ThinkingEvent, Status>>(32);
        
        let daemon = self.daemon.clone();
        
        tokio::spawn(async move {
            let es_url;
            {
                let daemon_guard = daemon.lock().await;
                es_url = daemon_guard.config.elasticsearch_url.clone();
            }
            
            let (thinking_tx, mut thinking_rx) = mpsc::channel(32);
            
            tokio::spawn(async move {
                if std::env::var("ELASTICSEARCH_URL").is_err() {
                    info!("Setting ELASTICSEARCH_URL from daemon config: {}", &es_url);
                    std::env::set_var("ELASTICSEARCH_URL", &es_url);
                }
                
                let _ = nl_gateway::multi_turn::run_with_events(&query, Some(thinking_tx)).await;
            });
            
            while let Some(event) = thinking_rx.recv().await {
                let pb_event = daemon::router::convert_thinking_event(&event);
                
                if tx.send(Ok(pb_event)).await.is_err() {
                    break;
                }
            }
        });
        
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    /// Handle metrics requests.
    async fn get_metrics(
        &self,
        _request: Request<MetricsRequest>,
    ) -> Result<Response<MetricsResponse>, Status> {
        let daemon = self.daemon.lock().await;
        let metrics = daemon
            .get_metrics()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(metrics))
    }

    /// Handle status requests.
    async fn get_status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let daemon = self.daemon.lock().await;
        let status = daemon.get_status();

        Ok(Response::new(status))
    }
}

/// Main entry point for the NetQuery daemon.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let log_level = match cli.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting NetQuery daemon");

    let config = DaemonConfig {
        interface: cli.interface,
        snaplen: cli.snaplen,
        promiscuous: cli.promiscuous,
        buffer_size: cli.buffer_size,
        window_duration_secs: cli.window_duration,
        window_overlap_secs: cli.window_overlap,
        max_entries_per_window: cli.max_entries,
        metrics_interval_secs: 10,
        qdrant_url: cli.qdrant_url,
        qdrant_port: cli.qdrant_port,
        model_path: cli.model_path,
        grpc_addr: cli.grpc_addr.clone(),
        elasticsearch_url: cli.elasticsearch_url,
        elasticsearch_username: cli.elasticsearch_username,
        elasticsearch_password: cli.elasticsearch_password,
        elasticsearch_index_prefix: cli.elasticsearch_index_prefix,
    };

    let mut daemon = NetQueryDaemon::new(config);

    if let Err(e) = daemon.init().await {
        error!("Failed to initialize daemon: {}", e);
        return Err(e.into());
    }

    if let Err(e) = daemon.start().await {
        error!("Failed to start daemon: {}", e);
        return Err(e.into());
    }

    let daemon = std::sync::Arc::new(tokio::sync::Mutex::new(daemon));

    let grpc_addr: SocketAddr = cli.grpc_addr.parse()?;
    let service = NetQueryService {
        daemon: daemon.clone(),
    };

    info!("Starting gRPC server on {}", grpc_addr);

    Server::builder()
        .add_service(NetQueryServer::new(service))
        .serve(grpc_addr)
        .await?;

    let mut daemon_guard = daemon.lock().await;
    if let Err(e) = daemon_guard.stop().await {
        error!("Error shutting down daemon: {}", e);
    }

    info!("NetQuery daemon terminated");
    Ok(())
}
