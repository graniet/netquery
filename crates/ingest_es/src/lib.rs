use anyhow::Result;
use async_trait::async_trait;
use backoff::{backoff::Backoff, ExponentialBackoff};
use chrono::{DateTime, Utc};
use flume::{Receiver, Sender};
use parser::{PacketMeta, Transport};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use thiserror::Error;
use tracing::{error, info, warn};

pub mod flow_builder;
pub mod protocol;

#[derive(Debug, Error)]
pub enum IngestError {
    #[error("Failed to connect to Elasticsearch: {0}")]
    ConnectionError(String),
    #[error("Failed to create index: {0}")]
    IndexError(String),
    #[error("Failed to index document: {0}")]
    IndexingError(String),
    #[error("Failed to flush documents: {0}")]
    FlushError(String),
    #[error("Channel error: {0}")]
    ChannelError(String),
    #[error("Operation was interrupted")]
    Interrupted,
}

/// Configuration for the Elasticsearch ingestor
#[derive(Debug, Clone)]
pub struct IngestConfig {
    /// Elasticsearch URL
    pub url: String,
    /// Optional username for authentication
    pub username: Option<String>,
    /// Optional password for authentication
    pub password: Option<String>,
    /// Index name prefix (will be appended with date for time-based indices)
    pub index_prefix: String,
    /// Maximum number of documents to buffer before flushing
    pub max_bulk_size: usize,
    /// Maximum time between flushes (in seconds)
    pub max_flush_interval_secs: u64,
    /// Size of the internal channel buffer
    pub channel_buffer_size: usize,
    /// Number of minutes in each flow document bucket (1-minute buckets by default)
    pub bucket_interval_mins: u32,
    /// Whether to enable verbose logging
    pub verbose_logging: bool,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:9200".to_string(),
            username: None,
            password: None,
            index_prefix: "netquery-flows".to_string(),
            max_bulk_size: 1000,
            max_flush_interval_secs: 1,
            channel_buffer_size: 10000,
            bucket_interval_mins: 1,
            verbose_logging: false,
        }
    }
}

/// Flow document structure for Elasticsearch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowDoc {
    #[serde(rename = "@timestamp")]
    pub timestamp: DateTime<Utc>,
    pub bucket_start: DateTime<Utc>,
    pub bucket_end: DateTime<Utc>,
    pub src: IpField,
    pub dst: IpField,
    pub protocol: String,
    pub bytes: u64,
    pub packets: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_code: Option<u8>,
}

/// IP address field for Elasticsearch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpField {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct FlowKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: String,
    bucket_time: u64,
}

#[derive(Debug, Clone)]
struct FlowBucket {
    bytes: u64,
    packets: u64,
    first_seen: SystemTime,
    last_seen: SystemTime,
    flags: u8,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
}

impl Default for FlowBucket {
    fn default() -> Self {
        Self {
            bytes: 0,
            packets: 0,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            flags: 0,
            icmp_type: None,
            icmp_code: None,
        }
    }
}

/// The ingestor service that processes packets and sends them to Elasticsearch
pub struct ElasticsearchIngestor {
    client: Client,
    config: IngestConfig,
    packet_rx: Option<Receiver<PacketMeta>>,
    running: Arc<AtomicBool>,
    docs_processed: Arc<AtomicU64>,
    docs_sent: Arc<AtomicU64>,
    docs_failed: Arc<AtomicU64>,
    bulk_size_sum: Arc<AtomicU64>,
    bulk_count: Arc<AtomicU64>,
}

impl ElasticsearchIngestor {
    /// Creates a new Elasticsearch ingestor with the given configuration
    pub async fn new(config: IngestConfig) -> Result<Self, IngestError> {
        let mut client_builder = Client::builder();
        client_builder = client_builder
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10));
        let client = client_builder.build().map_err(|e| {
            IngestError::ConnectionError(format!("Failed to build HTTP client: {}", e))
        })?;
        let es_url = format!("{}", config.url);
        let mut request = client.get(&es_url);
        if let (Some(username), Some(password)) = (&config.username, &config.password) {
            request = request.basic_auth(username, Some(password));
        }
        let response = request.send().await.map_err(|e| {
            IngestError::ConnectionError(format!("Failed to connect to Elasticsearch: {}", e))
        })?;
        if !response.status().is_success() {
            return Err(IngestError::ConnectionError(format!(
                "Elasticsearch returned an error: {}",
                response.status()
            )));
        }
        info!("Connected to Elasticsearch at {}", config.url);
        Ok(Self {
            client,
            config,
            packet_rx: None,
            running: Arc::new(AtomicBool::new(false)),
            docs_processed: Arc::new(AtomicU64::new(0)),
            docs_sent: Arc::new(AtomicU64::new(0)),
            docs_failed: Arc::new(AtomicU64::new(0)),
            bulk_size_sum: Arc::new(AtomicU64::new(0)),
            bulk_count: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Starts the ingestor, taking packets from the provided receiver
    pub async fn start(&mut self, packet_rx: Receiver<PacketMeta>) -> Result<(), IngestError> {
        if self.running.load(Ordering::SeqCst) {
            warn!("Ingestor already running");
            return Ok(());
        }
        self.packet_rx = Some(packet_rx);
        self.running.store(true, Ordering::SeqCst);
        let (doc_tx, doc_rx) = flume::bounded(self.config.channel_buffer_size);
        let processor_handle = self.start_packet_processor(doc_tx).await?;
        let indexer_handle = self.start_document_indexer(doc_rx).await?;
        info!("Elasticsearch ingestor started");
        tokio::spawn(async move {
            let _ = tokio::try_join!(processor_handle, indexer_handle);
            info!("Elasticsearch ingestor tasks completed");
        });
        Ok(())
    }

    /// Starts the packet processor that aggregates packets into flows
    async fn start_packet_processor(
        &self,
        doc_tx: Sender<FlowDoc>,
    ) -> Result<tokio::task::JoinHandle<()>, IngestError> {
        let packet_rx = self.packet_rx.as_ref().ok_or_else(|| {
            IngestError::ChannelError("Packet receiver not initialized".to_string())
        })?;
        let packet_rx = packet_rx.clone();
        let running = self.running.clone();
        let docs_processed = self.docs_processed.clone();
        let config = self.config.clone();
        let handle = tokio::spawn(async move {
            info!("Starting packet processor task");
            let mut flow_buckets: HashMap<FlowKey, FlowBucket> = HashMap::new();
            let mut last_rotation = Instant::now();
            let rotation_interval = Duration::from_secs(config.bucket_interval_mins as u64 * 60);
            let mut local_processed = 0;
            while running.load(Ordering::SeqCst) {
                if last_rotation.elapsed() >= rotation_interval {
                    Self::rotate_buckets(
                        &flow_buckets,
                        &doc_tx,
                        &docs_processed,
                        &config,
                        local_processed,
                    );
                    flow_buckets.clear();
                    local_processed = 0;
                    last_rotation = Instant::now();
                }
                let mut batch_size = 0;
                for _ in 0..100 {
                    match packet_rx.try_recv() {
                        Ok(packet) => {
                            batch_size += 1;
                            local_processed += 1;
                            Self::process_packet(packet, &mut flow_buckets, &config);
                        }
                        Err(flume::TryRecvError::Empty) => {
                            break;
                        }
                        Err(flume::TryRecvError::Disconnected) => {
                            error!("Packet channel disconnected");
                            running.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
                if batch_size == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            Self::rotate_buckets(
                &flow_buckets,
                &doc_tx,
                &docs_processed,
                &config,
                local_processed,
            );
            info!("Packet processor task ended");
        });
        Ok(handle)
    }

    /// Process a packet by aggregating it into flow buckets
    fn process_packet(
        packet: PacketMeta,
        flow_buckets: &mut HashMap<FlowKey, FlowBucket>,
        config: &IngestConfig,
    ) {
        let (protocol, flags, icmp_type, icmp_code) = match &packet.transport {
            Transport::Tcp { flags, .. } => ("tcp".to_string(), Some(*flags), None, None),
            Transport::Udp { .. } => ("udp".to_string(), None, None, None),
            Transport::Icmp {
                type_value,
                code_value,
                ..
            } => (
                "icmp".to_string(),
                None,
                Some(*type_value),
                Some(*code_value),
            ),
            Transport::Other { protocol } => (format!("proto-{}", protocol), None, None, None),
        };
        let timestamp_secs = packet
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let bucket_interval_secs = (config.bucket_interval_mins as u64) * 60;
        let bucket_time = (timestamp_secs / bucket_interval_secs) * bucket_interval_secs;
        let key = FlowKey {
            src_ip: packet.src.addr,
            dst_ip: packet.dst.addr,
            src_port: packet.src.port,
            dst_port: packet.dst.port,
            protocol: protocol.clone(),
            bucket_time,
        };
        let bucket = flow_buckets.entry(key).or_insert_with(|| {
            let mut new_bucket = FlowBucket::default();
            new_bucket.first_seen = packet.timestamp;
            new_bucket.last_seen = packet.timestamp;
            if let Some(f) = flags {
                new_bucket.flags = f;
            }
            if let Some(t) = icmp_type {
                new_bucket.icmp_type = Some(t);
            }
            if let Some(c) = icmp_code {
                new_bucket.icmp_code = Some(c);
            }
            new_bucket
        });
        bucket.packets += 1;
        bucket.bytes += packet.size as u64;
        if packet.timestamp < bucket.first_seen {
            bucket.first_seen = packet.timestamp;
        }
        if packet.timestamp > bucket.last_seen {
            bucket.last_seen = packet.timestamp;
        }
        if let Some(f) = flags {
            bucket.flags |= f;
        }
    }

    /// Rotate flow buckets, sending the aggregated data to Elasticsearch
    fn rotate_buckets(
        flow_buckets: &HashMap<FlowKey, FlowBucket>,
        doc_tx: &Sender<FlowDoc>,
        docs_processed: &Arc<AtomicU64>,
        config: &IngestConfig,
        local_processed: u64,
    ) {
        if flow_buckets.is_empty() {
            return;
        }
        let mut docs_count = 0;
        for (key, bucket) in flow_buckets {
            let bucket_start_secs = key.bucket_time;
            let bucket_end_secs = bucket_start_secs + (config.bucket_interval_mins as u64 * 60);
            let bucket_start = DateTime::<Utc>::from_timestamp(bucket_start_secs as i64, 0)
                .unwrap_or_else(|| Utc::now());
            let bucket_end = DateTime::<Utc>::from_timestamp(bucket_end_secs as i64, 0)
                .unwrap_or_else(|| Utc::now());
            let timestamp = bucket_start
                + chrono::Duration::seconds(((bucket_end_secs - bucket_start_secs) / 2) as i64);
            let doc = FlowDoc {
                timestamp,
                bucket_start,
                bucket_end,
                src: IpField {
                    ip: key.src_ip.to_string(),
                    port: if key.src_port > 0 {
                        Some(key.src_port)
                    } else {
                        None
                    },
                },
                dst: IpField {
                    ip: key.dst_ip.to_string(),
                    port: if key.dst_port > 0 {
                        Some(key.dst_port)
                    } else {
                        None
                    },
                },
                protocol: key.protocol.clone(),
                bytes: bucket.bytes,
                packets: bucket.packets,
                flags: if bucket.flags > 0 {
                    Some(bucket.flags)
                } else {
                    None
                },
                icmp_type: bucket.icmp_type,
                icmp_code: bucket.icmp_code,
            };
            if let Err(e) = doc_tx.try_send(doc) {
                error!("Failed to send document to indexer: {}", e);
            } else {
                docs_count += 1;
            }
        }
        docs_processed.fetch_add(docs_count, Ordering::Relaxed);
        info!(
            "Rotated flow buckets: {} flows from {} packets",
            docs_count, local_processed
        );
    }

    /// Starts the document indexer that sends documents to Elasticsearch
    async fn start_document_indexer(
        &self,
        doc_rx: Receiver<FlowDoc>,
    ) -> Result<tokio::task::JoinHandle<()>, IngestError> {
        let client = self.client.clone();
        let running = self.running.clone();
        let docs_sent = self.docs_sent.clone();
        let docs_failed = self.docs_failed.clone();
        let bulk_size_sum = self.bulk_size_sum.clone();
        let bulk_count = self.bulk_count.clone();
        let config = self.config.clone();
        let handle = tokio::spawn(async move {
            info!("Starting document indexer task");
            let mut doc_buffer: Vec<FlowDoc> = Vec::with_capacity(config.max_bulk_size);
            let mut next_flush =
                Instant::now() + Duration::from_secs(config.max_flush_interval_secs);
            let mut last_stats_time = Instant::now();
            while running.load(Ordering::SeqCst) {
                let now = Instant::now();
                let time_to_flush = now >= next_flush;
                let size_to_flush = doc_buffer.len() >= config.max_bulk_size;
                if time_to_flush || size_to_flush {
                    if !doc_buffer.is_empty() {
                        match Self::flush_documents(&client, &doc_buffer, &config).await {
                            Ok(count) => {
                                docs_sent.fetch_add(count as u64, Ordering::Relaxed);
                                bulk_size_sum.fetch_add(doc_buffer.len() as u64, Ordering::Relaxed);
                                bulk_count.fetch_add(1, Ordering::Relaxed);
                                if config.verbose_logging {
                                    info!("Flushed {} documents to Elasticsearch", count);
                                }
                            }
                            Err(e) => {
                                error!("Failed to flush documents: {}", e);
                                docs_failed.fetch_add(doc_buffer.len() as u64, Ordering::Relaxed);
                            }
                        }
                        doc_buffer.clear();
                    }
                    if time_to_flush {
                        next_flush =
                            Instant::now() + Duration::from_secs(config.max_flush_interval_secs);
                    }
                }
                match doc_rx.try_recv() {
                    Ok(doc) => {
                        doc_buffer.push(doc);
                    }
                    Err(flume::TryRecvError::Empty) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(flume::TryRecvError::Disconnected) => {
                        error!("Document channel disconnected");
                        running.store(false, Ordering::SeqCst);
                    }
                }
                if last_stats_time.elapsed() >= Duration::from_secs(10) {
                    let sent = docs_sent.load(Ordering::Relaxed);
                    let failed = docs_failed.load(Ordering::Relaxed);
                    let bulk_count_val = bulk_count.load(Ordering::Relaxed);
                    let avg_bulk_size = if bulk_count_val > 0 {
                        bulk_size_sum.load(Ordering::Relaxed) / bulk_count_val
                    } else {
                        0
                    };
                    info!(
                        "Indexer stats: sent={}, failed={}, avg_bulk_size={}",
                        sent, failed, avg_bulk_size
                    );
                    last_stats_time = Instant::now();
                }
            }
            if !doc_buffer.is_empty() {
                if let Err(e) = Self::flush_documents(&client, &doc_buffer, &config).await {
                    error!("Failed to flush final documents: {}", e);
                }
            }
            info!("Document indexer task ended");
        });
        Ok(handle)
    }

    /// Flushes documents to Elasticsearch using the Bulk API
    async fn flush_documents(
        client: &Client,
        docs: &[FlowDoc],
        config: &IngestConfig,
    ) -> Result<usize, IngestError> {
        if docs.is_empty() {
            return Ok(0);
        }
        let now = chrono::Utc::now();
        let index_name = format!("{}-{}", config.index_prefix, now.format("%Y.%m.%d"));
        let mut body = String::with_capacity(docs.len() * 200);
        for doc in docs {
            body.push_str(&format!(
                "{{\"create\":{{\"_index\":\"{}\"}}}}\n",
                index_name
            ));
            let doc_json = serde_json::to_string(doc).map_err(|e| {
                IngestError::IndexingError(format!("Failed to serialize document: {}", e))
            })?;
            body.push_str(&doc_json);
            body.push('\n');
        }
        let es_url = config.url.clone();
        let bulk_url = format!("{es_url}/_bulk");
        let mut backoff = ExponentialBackoff {
            max_elapsed_time: Some(Duration::from_secs(30)),
            ..Default::default()
        };
        let mut retry_count = 0;
        let max_retries = 5;
        loop {
            let request_builder = client
                .post(&bulk_url)
                .header("Content-Type", "application/x-ndjson");
            let request_builder =
                if let (Some(username), Some(password)) = (&config.username, &config.password) {
                    request_builder.basic_auth(username, Some(password))
                } else {
                    request_builder
                };
            let response = request_builder.body(body.clone()).send().await;
            match response {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        let response_body = response.json::<Value>().await.map_err(|e| {
                            IngestError::IndexingError(format!(
                                "Failed to parse bulk response: {}",
                                e
                            ))
                        })?;
                        let has_errors = response_body
                            .get("errors")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if has_errors {
                            if let Some(items) =
                                response_body.get("items").and_then(|i| i.as_array())
                            {
                                for item in items {
                                    if let Some(err) = item.get("error") {
                                        error!("Bulk indexing error: {:?}", err);
                                    }
                                }
                            }
                            return Err(IngestError::IndexingError(
                                "Bulk request contained errors".to_string(),
                            ));
                        }
                        let indexed = response_body
                            .get("items")
                            .and_then(|items| items.as_array())
                            .map(|arr| arr.len())
                            .unwrap_or(docs.len());
                        info!(
                            "Successfully indexed {} documents to {}",
                            indexed, index_name
                        );
                        return Ok(indexed);
                    } else {
                        let error_text = response
                            .text()
                            .await
                            .unwrap_or_else(|_| "Unknown error".to_string());
                        match status.as_u16() {
                            429 => {
                                warn!(
                                    "Elasticsearch is overloaded (429). Retrying with backoff..."
                                );
                            }
                            408 | 500 | 502 | 503 | 504 => {
                                warn!("Elasticsearch error ({}). Retrying with backoff...", status);
                            }
                            _ => {
                                return Err(IngestError::IndexingError(format!(
                                    "Elasticsearch returned error {}: {}",
                                    status, error_text
                                )));
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Elasticsearch request failed: {}. Retrying...", e);
                }
            }
            retry_count += 1;
            if retry_count >= max_retries {
                return Err(IngestError::IndexingError(format!(
                    "Failed to index documents after {} retries",
                    max_retries
                )));
            }
            if let Some(duration) = backoff.next_backoff() {
                warn!("Retrying Elasticsearch request in {:?}", duration);
                tokio::time::sleep(duration).await;
            } else {
                return Err(IngestError::IndexingError(
                    "Retry timeout exceeded".to_string(),
                ));
            }
        }
    }

    /// Stops the ingestor
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Elasticsearch ingestor stopping");
    }

    /// Returns ingestor metrics
    pub fn get_metrics(&self) -> (u64, u64, u64) {
        (
            self.docs_processed.load(Ordering::Relaxed),
            self.docs_sent.load(Ordering::Relaxed),
            self.docs_failed.load(Ordering::Relaxed),
        )
    }

    /// Check if the ingestor is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Helper to create a flow document from a packet
    pub fn create_doc_from_packet(packet: &PacketMeta, bucket_mins: u32) -> FlowDoc {
        let (protocol, flags, icmp_type, icmp_code) = match &packet.transport {
            Transport::Tcp { flags, .. } => ("tcp".to_string(), Some(*flags), None, None),
            Transport::Udp { .. } => ("udp".to_string(), None, None, None),
            Transport::Icmp {
                type_value,
                code_value,
                ..
            } => (
                "icmp".to_string(),
                None,
                Some(*type_value),
                Some(*code_value),
            ),
            Transport::Other { protocol } => (format!("proto-{}", protocol), None, None, None),
        };
        let bucket_interval_secs = (bucket_mins as u64) * 60;
        let timestamp_secs = packet
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let bucket_start_secs = (timestamp_secs / bucket_interval_secs) * bucket_interval_secs;
        let bucket_end_secs = bucket_start_secs + bucket_interval_secs;
        let bucket_start = DateTime::<Utc>::from_timestamp(bucket_start_secs as i64, 0)
            .unwrap_or_else(|| Utc::now());
        let bucket_end = DateTime::<Utc>::from_timestamp(bucket_end_secs as i64, 0)
            .unwrap_or_else(|| Utc::now());
        let timestamp =
            DateTime::<Utc>::from_timestamp(timestamp_secs as i64, 0).unwrap_or_else(|| Utc::now());
        FlowDoc {
            timestamp,
            bucket_start,
            bucket_end,
            src: IpField {
                ip: packet.src.addr.to_string(),
                port: if packet.src.port > 0 {
                    Some(packet.src.port)
                } else {
                    None
                },
            },
            dst: IpField {
                ip: packet.dst.addr.to_string(),
                port: if packet.dst.port > 0 {
                    Some(packet.dst.port)
                } else {
                    None
                },
            },
            protocol,
            bytes: packet.size as u64,
            packets: 1,
            flags,
            icmp_type,
            icmp_code,
        }
    }
}

#[async_trait]
pub trait DocumentProvider: Send + Sync {
    async fn index_document(&self, doc: FlowDoc) -> Result<(), IngestError>;
    async fn bulk_index(&self, docs: Vec<FlowDoc>) -> Result<usize, IngestError>;
}

#[cfg(test)]
pub struct MockProvider {
    pub indexed_docs: std::sync::Mutex<Vec<FlowDoc>>,
}

#[cfg(test)]
impl MockProvider {
    pub fn new() -> Self {
        Self {
            indexed_docs: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn get_indexed_docs(&self) -> Vec<FlowDoc> {
        self.indexed_docs.lock().unwrap().clone()
    }
}

#[cfg(test)]
#[async_trait]
impl DocumentProvider for MockProvider {
    async fn index_document(&self, doc: FlowDoc) -> Result<(), IngestError> {
        self.indexed_docs.lock().unwrap().push(doc);
        Ok(())
    }

    async fn bulk_index(&self, docs: Vec<FlowDoc>) -> Result<usize, IngestError> {
        let count = docs.len();
        self.indexed_docs.lock().unwrap().extend(docs);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    #[test]
    fn test_config_default() {
        let config = IngestConfig::default();
        assert_eq!(config.url, "http://localhost:9200");
        assert_eq!(config.max_bulk_size, 1000);
        assert_eq!(config.bucket_interval_mins, 1);
    }

    #[test]
    fn test_flow_doc_serialization() {
        let doc = FlowDoc {
            timestamp: Utc::now(),
            bucket_start: Utc::now(),
            bucket_end: Utc::now(),
            src: IpField {
                ip: "192.168.1.1".to_string(),
                port: Some(12345),
            },
            dst: IpField {
                ip: "192.168.1.2".to_string(),
                port: Some(80),
            },
            protocol: "tcp".to_string(),
            bytes: 1500,
            packets: 1,
            flags: Some(0x02),
            icmp_type: None,
            icmp_code: None,
        };
        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("192.168.1.1"));
        assert!(json.contains("12345"));
        assert!(json.contains("tcp"));
    }

    #[tokio::test]
    async fn test_create_doc_from_packet() {
        let packet = PacketMeta {
            timestamp: SystemTime::now(),
            size: 1500,
            src: IpEndpoint {
                addr: IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap()),
                port: 12345,
            },
            dst: IpEndpoint {
                addr: IpAddr::V4(Ipv4Addr::from_str("192.168.1.2").unwrap()),
                port: 80,
            },
            transport: Transport::Tcp {
                src_port: 12345,
                dst_port: 80,
                flags: 0x02,
                seq: 123456,
                ack: 0,
                window: 65535,
            },
            ttl: 64,
        };
        let doc = ElasticsearchIngestor::create_doc_from_packet(&packet, 1);
        assert_eq!(doc.src.ip, "192.168.1.1");
        assert_eq!(doc.src.port, Some(12345));
        assert_eq!(doc.dst.ip, "192.168.1.2");
        assert_eq!(doc.dst.port, Some(80));
        assert_eq!(doc.protocol, "tcp");
        assert_eq!(doc.bytes, 1500);
        assert_eq!(doc.packets, 1);
        assert_eq!(doc.flags, Some(0x02));
    }

    #[test]
    fn test_ip_field_serialization() {
        let field_with_port = IpField {
            ip: "192.168.1.1".to_string(),
            port: Some(80),
        };
        let json = serde_json::to_string(&field_with_port).unwrap();
        assert!(json.contains("80"));
        let field_without_port = IpField {
            ip: "192.168.1.1".to_string(),
            port: None,
        };
        let json = serde_json::to_string(&field_without_port).unwrap();
        assert!(!json.contains("port"));
    }
}
