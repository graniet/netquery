pub mod pb {
    tonic::include_proto!("netquery");
}

use crate::pb::flow_key::KeyType;
use crate::pb::ip_addr::IpType;
use anyhow::Result;
use flume;
use futures::stream::StreamExt;
use ingest_es::{ElasticsearchIngestor, IngestConfig};
use nl_gateway::NlGateway;
use parser::Parser;
use pb::{
    AskResponse, FlowData as PbFlowData, FlowKey as PbFlowKey, FlowStats as PbFlowStats,
    IpAddr as PbIpAddr, MetricsResponse, StatusResponse,
};
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use rag_engine::{QdrantConfig, RagEngine};
use signal_hook::consts::TERM_SIGNALS;
use signal_hook_tokio::Signals;
use sniffer::{Sniffer, SnifferConfig};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{error, info, warn};

mod bootstrap;
pub mod router;

/// Error type for daemon operations
#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("Failed to initialize component: {0}")]
    InitError(String),
    #[error("Failed to start component: {0}")]
    StartError(String),
    #[error("Failed to process query: {0}")]
    QueryError(String),
    #[error("Failed to get metrics: {0}")]
    MetricsError(String),
    #[error("Component is not running")]
    NotRunning,
    #[error("Elasticsearch error: {0}")]
    ElasticsearchError(String),
}

/// Key for flow aggregation
#[derive(Debug, Clone)]
pub enum FlowKey {
    /// Pair of source and destination IP addresses
    IpPair(IpAddr, IpAddr),
    /// Pair of source and destination IP endpoints (address and port)
    IpPortPair(IpEndpoint, IpEndpoint),
    /// Single IP address
    Ip(IpAddr),
    /// Source IP address
    IpSrc(IpAddr),
    /// Destination IP address
    IpDst(IpAddr),
    /// Port number
    Port(u16),
    /// Generic string key
    Generic(String),
}

/// IP endpoint (address and port)
#[derive(Debug, Clone)]
pub struct IpEndpoint {
    pub addr: IpAddr,
    pub port: u16,
}

/// Statistics for a flow
#[derive(Debug, Clone)]
pub struct FlowStats {
    pub bytes: u64,
    pub packets: u64,
    pub start_time: SystemTime,
    pub last_time: SystemTime,
}

/// Data for a flow
#[derive(Debug, Clone)]
pub struct FlowData {
    pub key: FlowKey,
    pub stats: FlowStats,
}

/// Result of a query
#[derive(Debug, Clone)]
pub struct QueryResult {
    pub flows: Vec<FlowData>,
    pub total: usize,
}

/// Status of the daemon
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonStatus {
    /// Status unknown
    Unknown,
    /// Daemon is starting
    Starting,
    /// Daemon is running
    Running,
    /// Daemon is running in degraded mode
    Degraded,
    /// Daemon is stopping
    Stopping,
    /// Daemon is stopped
    Stopped,
}

impl From<DaemonStatus> for i32 {
    fn from(status: DaemonStatus) -> Self {
        match status {
            DaemonStatus::Unknown => 0,
            DaemonStatus::Starting => 1,
            DaemonStatus::Running => 2,
            DaemonStatus::Degraded => 3,
            DaemonStatus::Stopping => 4,
            DaemonStatus::Stopped => 5,
        }
    }
}

/// Main daemon structure
#[allow(dead_code)]
pub struct NetQueryDaemon {
    sniffer: Option<Arc<tokio::sync::Mutex<Sniffer>>>,
    parser: Option<Arc<tokio::sync::Mutex<Parser>>>,
    es_ingestor: Option<Arc<tokio::sync::Mutex<ElasticsearchIngestor>>>,
    nl_gateway: Arc<NlGateway>,
    rag_engine: Option<Arc<RagEngine>>,
    pub config: DaemonConfig,
    metrics_registry: Registry,
    status: Arc<std::sync::Mutex<DaemonStatus>>,
    start_time: Instant,
    packet_process_handle: Option<JoinHandle<()>>,
    shutdown_signal: Arc<AtomicBool>,
    processed_count: Arc<AtomicU64>,
    dropped_count: Arc<AtomicU64>,
}

/// Configuration for the daemon
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub interface: Option<String>,
    pub snaplen: i32,
    pub promiscuous: bool,
    pub buffer_size: usize,
    pub window_duration_secs: u64,
    pub window_overlap_secs: u64,
    pub max_entries_per_window: usize,
    pub metrics_interval_secs: u64,
    pub qdrant_url: String,
    pub qdrant_port: u16,
    pub model_path: Option<String>,
    pub grpc_addr: String,
    pub elasticsearch_url: String,
    pub elasticsearch_username: Option<String>,
    pub elasticsearch_password: Option<String>,
    pub elasticsearch_index_prefix: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            interface: None,
            snaplen: 65535,
            promiscuous: true,
            buffer_size: 100000,
            window_duration_secs: 60,
            window_overlap_secs: 10,
            max_entries_per_window: 1_000_000,
            metrics_interval_secs: 10,
            qdrant_url: "http://localhost".to_string(),
            qdrant_port: 6334,
            model_path: None,
            grpc_addr: "[::1]:50051".to_string(),
            elasticsearch_url: "http://elasticsearch:9200".to_string(),
            elasticsearch_username: None,
            elasticsearch_password: None,
            elasticsearch_index_prefix: "netquery-flows".to_string(),
        }
    }
}

impl NetQueryDaemon {
    /// Create a new daemon instance
    pub fn new(config: DaemonConfig) -> Self {
        let metrics_registry = Registry::default();
        Self {
            sniffer: None,
            parser: None,
            es_ingestor: None,
            nl_gateway: Arc::new(NlGateway::new()),
            rag_engine: None,
            config,
            metrics_registry,
            status: Arc::new(std::sync::Mutex::new(DaemonStatus::Unknown)),
            start_time: Instant::now(),
            packet_process_handle: None,
            shutdown_signal: Arc::new(AtomicBool::new(false)),
            processed_count: Arc::new(AtomicU64::new(0)),
            dropped_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Initialize all components of the daemon
    pub async fn init(&mut self) -> Result<(), DaemonError> {
        *self.status.lock().unwrap() = DaemonStatus::Starting;

        info!("Bootstrapping Elasticsearch...");
        let es_bootstrap = bootstrap::ElasticsearchBootstrap::new(
            self.config.elasticsearch_url.clone(),
            self.config.elasticsearch_username.clone(),
            self.config.elasticsearch_password.clone(),
            self.config.elasticsearch_index_prefix.clone(),
        );

        if let Err(e) = es_bootstrap.bootstrap().await {
            warn!("Elasticsearch bootstrap failed: {}", e);
            warn!("Will continue, but some features may not work correctly");
            *self.status.lock().unwrap() = DaemonStatus::Degraded;
        } else {
            info!("Elasticsearch bootstrap completed successfully");
        }

        let qdrant_config = QdrantConfig {
            url: self.config.qdrant_url.clone(),
            port: self.config.qdrant_port,
            collection: "netquery_knowledge".to_string(),
        };

        let model_path = self.config.model_path.as_ref().map(|p| p.into());

        match RagEngine::new(qdrant_config, model_path).await {
            Ok(engine) => {
                self.rag_engine = Some(Arc::new(engine));
                let nl_gateway = NlGateway::new();
                #[cfg(feature = "rag")]
                let nl_gateway =
                    nl_gateway.with_rag_engine(self.rag_engine.as_ref().unwrap().clone());
                self.nl_gateway = Arc::new(nl_gateway);
            }
            Err(e) => {
                warn!("Failed to initialize RAG engine: {}", e);
            }
        }

        let sniffer_config = SnifferConfig {
            interface: self.config.interface.clone(),
            snaplen: self.config.snaplen,
            promiscuous: self.config.promiscuous,
            timeout_ms: 1000,
            buffer_size: self.config.buffer_size,
            bpf_filter: Some("ip or ip6".to_string()),
            immediate_mode: true,
        };

        let sniffer = Sniffer::new(sniffer_config);
        self.sniffer = Some(Arc::new(tokio::sync::Mutex::new(sniffer)));

        let parser = Parser::new();
        self.parser = Some(Arc::new(tokio::sync::Mutex::new(parser)));

        let es_config = IngestConfig {
            url: self.config.elasticsearch_url.clone(),
            username: self.config.elasticsearch_username.clone(),
            password: self.config.elasticsearch_password.clone(),
            index_prefix: self.config.elasticsearch_index_prefix.clone(),
            max_bulk_size: 1000,
            max_flush_interval_secs: 1,
            channel_buffer_size: self.config.buffer_size,
            bucket_interval_mins: 1,
            verbose_logging: false,
        };

        match ElasticsearchIngestor::new(es_config).await {
            Ok(ingestor) => {
                self.es_ingestor = Some(Arc::new(tokio::sync::Mutex::new(ingestor)));
                info!("Elasticsearch ingestor initialized successfully");
            }
            Err(e) => {
                warn!("Failed to initialize Elasticsearch ingestor: {}", e);
                *self.status.lock().unwrap() = DaemonStatus::Degraded;
            }
        }

        Ok(())
    }

    /// Start all components and begin processing
    pub async fn start(&mut self) -> Result<(), DaemonError> {
        if *self.status.lock().unwrap() != DaemonStatus::Starting {
            return Err(DaemonError::StartError(
                "Daemon not in starting state".into(),
            ));
        }

        let sniffer = self
            .sniffer
            .as_ref()
            .ok_or_else(|| DaemonError::StartError("Sniffer not initialized".into()))?;

        let packet_rx = {
            let mut sniffer_guard = sniffer.lock().await;
            sniffer_guard
                .start()
                .map_err(|e| DaemonError::StartError(format!("Failed to start sniffer: {}", e)))?
        };

        let parser = self
            .parser
            .as_ref()
            .ok_or_else(|| DaemonError::StartError("Parser not initialized".into()))?;

        let meta_rx = {
            let mut parser_guard = parser.lock().await;
            parser_guard
                .start(packet_rx, self.config.buffer_size)
                .map_err(|e| DaemonError::StartError(format!("Failed to start parser: {}", e)))?
        };

        if let Some(es_ingestor) = &self.es_ingestor {
            let mut es_guard = es_ingestor.lock().await;
            let es_rx = meta_rx.clone();

            match es_guard.start(es_rx).await {
                Ok(_) => {
                    info!("Elasticsearch ingestor started successfully");
                }
                Err(e) => {
                    warn!("Failed to start Elasticsearch ingestor: {}", e);
                    *self.status.lock().unwrap() = DaemonStatus::Degraded;
                }
            }
        } else {
            warn!("Elasticsearch ingestor not initialized, running in degraded mode");
            *self.status.lock().unwrap() = DaemonStatus::Degraded;
        }

        let shutdown_signal = self.shutdown_signal.clone();
        let processed_count = self.processed_count.clone();
        let meta_rx_clone = meta_rx.clone();

        let handle = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_millis(1000));
            let mut local_count: u64 = 0;

            while !shutdown_signal.load(Ordering::SeqCst) {
                for _ in 0..100 {
                    match meta_rx_clone.try_recv() {
                        Ok(_) => {
                            local_count += 1;
                        }
                        Err(flume::TryRecvError::Empty) => {
                            break;
                        }
                        Err(flume::TryRecvError::Disconnected) => {
                            warn!("Metadata channel disconnected");
                            break;
                        }
                    }
                }

                if local_count > 0 {
                    processed_count.fetch_add(local_count, Ordering::SeqCst);
                    local_count = 0;
                }

                interval.tick().await;
            }

            info!("Packet processing loop terminated");
        });

        self.packet_process_handle = Some(handle);

        if *self.status.lock().unwrap() != DaemonStatus::Degraded {
            *self.status.lock().unwrap() = DaemonStatus::Running;
        }

        self.handle_shutdown_signals();

        Ok(())
    }

    /// Handle shutdown signals for graceful termination
    fn handle_shutdown_signals(&self) {
        let signals = Signals::new(TERM_SIGNALS).unwrap();
        let shutdown_signal = self.shutdown_signal.clone();
        let status = self.status.clone();

        tokio::spawn(async move {
            let mut signals = signals.fuse();
            if let Some(signal) = signals.next().await {
                info!("Received signal {:?}", signal);
                *status.lock().unwrap() = DaemonStatus::Stopping;
                shutdown_signal.store(true, Ordering::SeqCst);
            }
        });
    }

    /// Stop all components and clean up
    pub async fn stop(&mut self) -> Result<(), DaemonError> {
        info!("Stopping NetQuery daemon");
        self.shutdown_signal.store(true, Ordering::SeqCst);
        *self.status.lock().unwrap() = DaemonStatus::Stopping;

        if let Some(handle) = self.packet_process_handle.take() {
            if let Err(e) = handle.await {
                warn!("Error waiting for packet processing to stop: {:?}", e);
            }
        }

        if let Some(ref es_ingestor) = self.es_ingestor {
            let mut es_guard = es_ingestor.lock().await;
            es_guard.stop();
            info!("Elasticsearch ingestor stopped");
        }

        if let Some(ref parser) = self.parser {
            let mut parser_guard = parser.lock().await;
            parser_guard.stop();
        }

        if let Some(ref sniffer) = self.sniffer {
            let mut sniffer_guard = sniffer.lock().await;
            sniffer_guard.stop();
        }

        *self.status.lock().unwrap() = DaemonStatus::Stopped;
        Ok(())
    }

    /// Process a natural language query and return the result
    pub async fn process_query(&self, query: &str) -> Result<AskResponse, DaemonError> {
        let current_status = *self.status.lock().unwrap();
        if current_status != DaemonStatus::Running && current_status != DaemonStatus::Degraded {
            return Err(DaemonError::NotRunning);
        }

        let start_time = Instant::now();

        let has_api_key = std::env::var("OPENAI_API_KEY").is_ok();
        if !has_api_key {
            return Err(DaemonError::QueryError(
                "OpenAI API key not found. Please set the OPENAI_API_KEY environment variable."
                    .to_string(),
            ));
        }

        let es_url = &self.config.elasticsearch_url;
        if std::env::var("ELASTICSEARCH_URL").is_err() {
            info!("Setting ELASTICSEARCH_URL from daemon config: {}", es_url);
            std::env::set_var("ELASTICSEARCH_URL", es_url);
        }
        
        let answer = nl_gateway::multi_turn::run(query).await;
        
        if answer.starts_with("Error:") {
            return Err(DaemonError::QueryError(answer));
        }
        
        let result = QueryResult {
            flows: Vec::new(),
            total: 0,
        };

        let mut pb_flows = Vec::new();

        for flow in &result.flows {
            let pb_flow = Self::convert_to_pb_flow(flow);
            pb_flows.push(pb_flow);
        }

        let query_time = start_time.elapsed().as_millis() as i64;

        let summary = format!("Query: \"{}\"\n\n{}", query, answer);

        Ok(AskResponse {
            result: summary,
            flows: pb_flows,
            query_time_ms: query_time,
            total_flows: result.total as i32,
        })
    }

    /// Convert a FlowData to protobuf format
    fn convert_to_pb_flow(flow: &FlowData) -> pb::FlowData {
        let key_type = match &flow.key {
            FlowKey::IpPair(src, dst) => {
                let src_pb = Self::ip_to_pb_ip(src);
                let dst_pb = Self::ip_to_pb_ip(dst);

                Some(KeyType::IpPair(pb::IpPair {
                    src: Some(src_pb),
                    dst: Some(dst_pb),
                }))
            }
            FlowKey::IpPortPair(src, dst) => {
                let src_pb = pb::IpEndpoint {
                    addr: Some(Self::ip_to_pb_ip(&src.addr)),
                    port: src.port as u32,
                };

                let dst_pb = pb::IpEndpoint {
                    addr: Some(Self::ip_to_pb_ip(&dst.addr)),
                    port: dst.port as u32,
                };

                Some(KeyType::IpPortPair(pb::IpPortPair {
                    src: Some(src_pb),
                    dst: Some(dst_pb),
                }))
            }
            FlowKey::Ip(ip) => Some(KeyType::Ip(Self::ip_to_pb_ip(ip))),
            FlowKey::IpSrc(ip) => {
                let src_pb = Self::ip_to_pb_ip(ip);
                let null_ip = Self::ip_to_pb_ip(&IpAddr::from([0, 0, 0, 0]));

                Some(KeyType::IpPair(pb::IpPair {
                    src: Some(src_pb),
                    dst: Some(null_ip),
                }))
            }
            FlowKey::IpDst(ip) => {
                let dst_pb = Self::ip_to_pb_ip(ip);
                let null_ip = Self::ip_to_pb_ip(&IpAddr::from([0, 0, 0, 0]));

                Some(KeyType::IpPair(pb::IpPair {
                    src: Some(null_ip),
                    dst: Some(dst_pb),
                }))
            }
            FlowKey::Port(port) => Some(KeyType::Port(*port as u32)),
            FlowKey::Generic(name) => {
                let bytes = format!("generic:{}", name).into_bytes();
                Some(KeyType::Ip(PbIpAddr {
                    ip_type: Some(IpType::Ipv4(bytes)),
                }))
            }
        };

        let stats = PbFlowStats {
            bytes: flow.stats.bytes,
            packets: flow.stats.packets,
            start_time: flow
                .stats
                .start_time
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            last_time: flow
                .stats
                .last_time
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        };

        PbFlowData {
            key: Some(PbFlowKey { key_type }),
            stats: Some(stats),
        }
    }

    /// Convert an IpAddr to protobuf format
    fn ip_to_pb_ip(ip: &IpAddr) -> PbIpAddr {
        match ip {
            IpAddr::V4(ipv4) => PbIpAddr {
                ip_type: Some(IpType::Ipv4(ipv4.octets().to_vec())),
            },
            IpAddr::V6(ipv6) => PbIpAddr {
                ip_type: Some(IpType::Ipv6(ipv6.octets().to_vec())),
            },
        }
    }

    /// Get metrics for Prometheus and gRPC
    pub async fn get_metrics(&self) -> Result<MetricsResponse, DaemonError> {
        let current_status = *self.status.lock().unwrap();
        if current_status != DaemonStatus::Running && current_status != DaemonStatus::Degraded {
            return Err(DaemonError::NotRunning);
        }

        let sniffer = self.sniffer.as_ref().ok_or(DaemonError::NotRunning)?;
        let sniffer_guard = sniffer.lock().await;
        let (packets_captured, packets_dropped) = sniffer_guard.get_stats();

        let parser = self.parser.as_ref().ok_or(DaemonError::NotRunning)?;
        let parser_guard = parser.lock().await;
        let (packets_processed, _, _) = parser_guard.get_stats();

        let (window_count, total_flows) = if let Some(es_ingestor) = &self.es_ingestor {
            let es_guard = es_ingestor.lock().await;
            let (docs_processed, docs_sent, _docs_failed) = es_guard.get_metrics();
            (docs_processed, docs_sent)
        } else {
            (0, 0)
        };

        let memory_usage = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .map(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .parse::<u64>()
                    .unwrap_or(0)
                    * 1024
            })
            .unwrap_or(0);

        Ok(MetricsResponse {
            packets_captured,
            packets_dropped,
            packets_processed,
            current_window_count: window_count as u64,
            total_flows,
            memory_usage_bytes: memory_usage,
        })
    }

    /// Get Prometheus metrics as a string
    pub fn get_prometheus_metrics(&self) -> Result<String, DaemonError> {
        let mut buffer = String::new();
        encode(&mut buffer, &self.metrics_registry)
            .map_err(|e| DaemonError::MetricsError(format!("Failed to encode metrics: {}", e)))?;

        Ok(buffer)
    }

    /// Get the current status of the daemon
    pub fn get_status(&self) -> StatusResponse {
        let status = *self.status.lock().unwrap();
        let interface = self
            .config
            .interface
            .clone()
            .unwrap_or_else(|| "default".to_string());

        let es_url = &self.config.elasticsearch_url;
        let es_health_url = format!("{}/_cat/indices/{}*?format=json", es_url, self.config.elasticsearch_index_prefix);
        
        let client = reqwest::Client::new();
        let _ = client.get(&es_health_url).send();
        
        info!("Elasticsearch URL: {}", es_url);
        info!("Elasticsearch indices URL: {}", es_health_url);

        StatusResponse {
            status: status.into(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: self.start_time.elapsed().as_secs() as i64,
            interface,
        }
    }
}
