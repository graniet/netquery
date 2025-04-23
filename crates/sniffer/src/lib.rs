use anyhow::Result;
use flume::{Receiver, Sender};
use pcap::{Active, Capture, Device};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// Error type for sniffer operations.
#[derive(Debug, Error)]
pub enum SnifferError {
    #[error("Failed to find network device: {0}")]
    DeviceNotFound(String),
    #[error("Failed to open capture device: {0}")]
    CaptureError(#[from] pcap::Error),
    #[error("Channel send error")]
    ChannelError,
}

/// Structure representing a captured packet and its timestamp.
pub struct PacketData {
    pub data: Vec<u8>,
    pub timestamp: SystemTime,
}

/// Configuration for the sniffer.
pub struct SnifferConfig {
    pub interface: Option<String>,
    pub snaplen: i32,
    pub promiscuous: bool,
    pub timeout_ms: i32,
    pub buffer_size: usize,
    pub bpf_filter: Option<String>,
    pub immediate_mode: bool,
}

impl Default for SnifferConfig {
    fn default() -> Self {
        Self {
            interface: None,
            snaplen: 65535,
            promiscuous: true,
            timeout_ms: 1000,
            buffer_size: 10000,
            bpf_filter: None,
            immediate_mode: true,
        }
    }
}

/// Main sniffer structure for packet capture.
pub struct Sniffer {
    config: SnifferConfig,
    running: Arc<AtomicBool>,
    packets_captured: Arc<AtomicU64>,
    packets_dropped: Arc<AtomicU64>,
}

impl Sniffer {
    /// Create a new sniffer with the given configuration.
    pub fn new(config: SnifferConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            packets_captured: Arc::new(AtomicU64::new(0)),
            packets_dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Start the sniffer and return a receiver for captured packets.
    pub fn start(&mut self) -> Result<Receiver<PacketData>> {
        if self.running.load(Ordering::SeqCst) {
            warn!("Sniffer already running");
            return Err(anyhow::anyhow!("Sniffer already running"));
        }

        let (tx, rx) = flume::bounded(self.config.buffer_size);
        self.running.store(true, Ordering::SeqCst);

        let device = match &self.config.interface {
            Some(interface) => {
                let devices = Device::list()?;
                info!(
                    "Available devices: {}",
                    devices
                        .iter()
                        .map(|d| d.name.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                );

                devices
                    .into_iter()
                    .find(|d| d.name == *interface)
                    .ok_or_else(|| SnifferError::DeviceNotFound(interface.clone()))?
            }
            None => {
                let default_device = Device::lookup()?
                    .ok_or_else(|| SnifferError::DeviceNotFound("default".into()))?;
                info!("Using default device: {}", default_device.name);
                default_device
            }
        };

        info!("Starting capture on device: {}", device.name);

        let mut cap_builder = Capture::from_device(device)?
            .snaplen(self.config.snaplen)
            .promisc(self.config.promiscuous)
            .timeout(self.config.timeout_ms);

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if self.config.immediate_mode {
            cap_builder = cap_builder.immediate_mode(true);
            info!("Enabled immediate mode for faster packet processing");
        }

        let mut cap = cap_builder.open()?;

        if let Some(filter) = &self.config.bpf_filter {
            info!("Applying BPF filter: {}", filter);
            match cap.filter(filter, true) {
                Ok(_) => info!("BPF filter applied successfully"),
                Err(e) => warn!("Failed to apply BPF filter: {}", e),
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Err(e) = cap.setnonblock() {
                warn!("Failed to set nonblocking mode: {}", e);
            }
        }

        let running = self.running.clone();
        let packets_captured = self.packets_captured.clone();
        let packets_dropped = self.packets_dropped.clone();

        std::thread::spawn(move || {
            Self::capture_loop(cap, tx, running, packets_captured, packets_dropped);
        });

        Ok(rx)
    }

    /// Main capture loop for processing packets.
    fn capture_loop(
        mut cap: Capture<Active>,
        tx: Sender<PacketData>,
        running: Arc<AtomicBool>,
        packets_captured: Arc<AtomicU64>,
        packets_dropped: Arc<AtomicU64>,
    ) {
        let mut local_captured = 0;
        let mut local_dropped = 0;
        let packet_batch_size = 100;

        let mut last_stats_time = SystemTime::now();
        let stats_interval = Duration::from_secs(5);

        while running.load(Ordering::SeqCst) {
            let mut packet_batch = Vec::with_capacity(packet_batch_size);

            for _ in 0..packet_batch_size {
                match cap.next_packet() {
                    Ok(packet) => {
                        local_captured += 1;
                        let timestamp = SystemTime::UNIX_EPOCH
                            + Duration::new(
                                packet.header.ts.tv_sec as u64,
                                packet.header.ts.tv_usec as u32 * 1000,
                            );
                        packet_batch.push(PacketData {
                            data: packet.data.to_vec(),
                            timestamp,
                        });
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        break;
                    }
                    Err(e) => {
                        error!("Error capturing packet: {}", e);
                        if !running.load(Ordering::SeqCst) {
                            break;
                        }
                        continue;
                    }
                }
            }

            if !packet_batch.is_empty() {
                for packet in packet_batch {
                    if tx.send(packet).is_err() {
                        local_dropped += 1;
                        if local_dropped % 1000 == 0 {
                            warn!("Channel full, dropped {} packets", local_dropped);
                        }
                    }
                }
            } else {
                std::thread::sleep(Duration::from_millis(1));
            }

            if let Ok(elapsed) = SystemTime::now().duration_since(last_stats_time) {
                if elapsed >= stats_interval {
                    packets_captured.fetch_add(local_captured, Ordering::SeqCst);
                    packets_dropped.fetch_add(local_dropped, Ordering::SeqCst);

                    debug!(
                        "Capture stats: captured={}, dropped={}, drop_rate={:.2}%",
                        local_captured,
                        local_dropped,
                        if local_captured + local_dropped > 0 {
                            (local_dropped as f64 / (local_captured + local_dropped) as f64) * 100.0
                        } else {
                            0.0
                        }
                    );

                    if let Ok(stats) = cap.stats() {
                        debug!(
                            "Libpcap stats: received={}, dropped={}",
                            stats.received, stats.dropped
                        );
                    }

                    local_captured = 0;
                    local_dropped = 0;
                    last_stats_time = SystemTime::now();
                }
            }
        }

        packets_captured.fetch_add(local_captured, Ordering::SeqCst);
        packets_dropped.fetch_add(local_dropped, Ordering::SeqCst);

        info!(
            "Capture loop ended. Local: captured={}, dropped={}",
            local_captured, local_dropped
        );
    }

    /// Stop the sniffer.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Sniffer stopped");
    }

    /// Check if the sniffer is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get statistics: (captured, dropped).
    pub fn get_stats(&self) -> (u64, u64) {
        (
            self.packets_captured.load(Ordering::SeqCst),
            self.packets_dropped.load(Ordering::SeqCst),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_sniffer_config_default() {
        let config = SnifferConfig::default();
        assert_eq!(config.snaplen, 65535);
        assert_eq!(config.promiscuous, true);
        assert_eq!(config.timeout_ms, 1000);
        assert_eq!(config.buffer_size, 10000);
        assert_eq!(config.bpf_filter, None);
        assert_eq!(config.immediate_mode, true);
    }

    #[test]
    fn test_sniffer_new() {
        let config = SnifferConfig::default();
        let sniffer = Sniffer::new(config);
        assert_eq!(sniffer.is_running(), false);
    }

    /// This test requires network access and may need sudo privileges.
    #[test]
    #[ignore]
    fn test_sniffer_start_stop() {
        let config = SnifferConfig {
            interface: None,
            snaplen: 65535,
            promiscuous: true,
            timeout_ms: 100,
            buffer_size: 1000,
            bpf_filter: Some("tcp or udp".to_string()),
            immediate_mode: true,
        };

        let mut sniffer = Sniffer::new(config);
        let rx = sniffer.start().expect("Failed to start sniffer");

        assert_eq!(sniffer.is_running(), true);

        std::thread::sleep(Duration::from_secs(3));

        let (captured, dropped) = sniffer.get_stats();
        println!(
            "Stats from counter: captured={}, dropped={}",
            captured, dropped
        );

        sniffer.stop();
        assert_eq!(sniffer.is_running(), false);

        let count = rx.try_iter().count();
        println!("Received {} packets in channel", count);
    }
}
