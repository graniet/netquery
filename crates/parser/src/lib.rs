use etherparse::{NetHeaders, PacketHeaders};
use flume::{Receiver, Sender};
use sniffer::PacketData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, info, warn};

/// Error type for the parser.
#[derive(Debug, Error)]
pub enum ParserError {
    #[error("Failed to parse packet: {0}")]
    ParseError(String),
    #[error("Channel error")]
    ChannelError,
}

/// Represents an IP endpoint (address and port).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpEndpoint {
    pub addr: IpAddr,
    pub port: u16,
}

/// Transport layer protocol information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Transport {
    /// TCP transport.
    Tcp {
        src_port: u16,
        dst_port: u16,
        flags: u8,
        seq: u32,
        ack: u32,
        window: u16,
    },
    /// UDP transport.
    Udp {
        src_port: u16,
        dst_port: u16,
        length: u16,
    },
    /// ICMP transport.
    Icmp {
        /// Combined type and code for filtering.
        type_code: u16,
        /// ICMP type value.
        type_value: u8,
        /// ICMP code value.
        code_value: u8,
    },
    /// Other protocol.
    Other { protocol: u8 },
}

/// Metadata for a parsed packet.
#[derive(Debug, Clone)]
pub struct PacketMeta {
    pub timestamp: std::time::SystemTime,
    pub size: usize,
    pub src: IpEndpoint,
    pub dst: IpEndpoint,
    pub transport: Transport,
    pub ttl: u8,
}

/// Packet parser.
pub struct Parser {
    running: Arc<AtomicBool>,
    packets_processed: Arc<AtomicU64>,
    packets_dropped: Arc<AtomicU64>,
    parse_errors: Arc<AtomicU64>,
}

impl Parser {
    /// Create a new parser.
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            packets_processed: Arc::new(AtomicU64::new(0)),
            packets_dropped: Arc::new(AtomicU64::new(0)),
            parse_errors: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Start the parser thread.
    pub fn start(
        &mut self,
        input_rx: Receiver<PacketData>,
        buffer_size: usize,
    ) -> Result<Receiver<PacketMeta>, ParserError> {
        if self.running.load(Ordering::SeqCst) {
            warn!("Parser already running");
            return Err(ParserError::ParseError("Parser already running".into()));
        }

        let (tx, rx) = flume::bounded(buffer_size);
        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        let packets_processed_counter = self.packets_processed.clone();
        let packets_dropped_counter = self.packets_dropped.clone();
        let parse_errors_counter = self.parse_errors.clone();

        std::thread::spawn(move || {
            Self::parse_loop(
                input_rx,
                tx,
                running,
                packets_processed_counter,
                packets_dropped_counter,
                parse_errors_counter,
            );
        });

        Ok(rx)
    }

    /// Main parsing loop.
    fn parse_loop(
        input_rx: Receiver<PacketData>,
        tx: Sender<PacketMeta>,
        running: Arc<AtomicBool>,
        packets_processed_counter: Arc<AtomicU64>,
        packets_dropped_counter: Arc<AtomicU64>,
        parse_errors_counter: Arc<AtomicU64>,
    ) {
        let mut local_processed = 0;
        let mut local_dropped = 0;
        let mut local_errors = 0;

        let mut last_stats_time = std::time::SystemTime::now();
        let stats_interval = std::time::Duration::from_secs(5);

        let batch_size = 100;

        while running.load(Ordering::SeqCst) {
            let mut meta_batch = Vec::with_capacity(batch_size);
            let mut batch_count = 0;

            for _ in 0..batch_size {
                match input_rx.try_recv() {
                    Ok(packet) => {
                        local_processed += 1;
                        batch_count += 1;

                        packets_processed_counter.fetch_add(1, Ordering::Relaxed);

                        match Self::parse_packet(&packet) {
                            Ok(meta) => {
                                meta_batch.push(meta);
                            }
                            Err(e) => {
                                local_errors += 1;
                                parse_errors_counter.fetch_add(1, Ordering::Relaxed);

                                if local_errors % 1000 == 0 {
                                    warn!("Parse errors: {} - Last error: {:?}", local_errors, e);
                                }
                            }
                        }
                    }
                    Err(flume::TryRecvError::Empty) => {
                        break;
                    }
                    Err(flume::TryRecvError::Disconnected) => {
                        info!("Input channel disconnected, stopping parser");
                        running.store(false, Ordering::SeqCst);
                        break;
                    }
                }
            }

            if !meta_batch.is_empty() {
                for meta in meta_batch {
                    if tx.try_send(meta).is_err() {
                        local_dropped += 1;
                        packets_dropped_counter.fetch_add(1, Ordering::Relaxed);

                        if local_dropped % 1000 == 0 {
                            warn!("Channel full, dropped {} packets", local_dropped);
                        }
                    }
                }
            } else if batch_count == 0 {
                std::thread::sleep(std::time::Duration::from_micros(100));
            }

            if let Ok(elapsed) = std::time::SystemTime::now().duration_since(last_stats_time) {
                if elapsed >= stats_interval {
                    let packets_per_sec = if elapsed.as_secs_f64() > 0.0 {
                        (local_processed as f64) / elapsed.as_secs_f64()
                    } else {
                        0.0
                    };

                    let total_processed = packets_processed_counter.load(Ordering::Relaxed);
                    let total_dropped = packets_dropped_counter.load(Ordering::Relaxed);
                    let total_errors = parse_errors_counter.load(Ordering::Relaxed);

                    info!(
                        "Parser stats: processed_batch={}, total_processed={}, dropped={}, errors={}, rate={:.2} pkt/s",
                        local_processed, total_processed, total_dropped, total_errors, packets_per_sec
                    );

                    local_processed = 0;
                    local_dropped = 0;
                    local_errors = 0;
                    last_stats_time = std::time::SystemTime::now();
                }
            }
        }

        let total_processed = packets_processed_counter.load(Ordering::Relaxed);
        let total_dropped = packets_dropped_counter.load(Ordering::Relaxed);
        let total_errors = parse_errors_counter.load(Ordering::Relaxed);

        info!(
            "Parser loop ended. Total: processed={}, dropped={}, errors={}",
            total_processed, total_dropped, total_errors
        );
    }

    /// Parse a single packet and extract metadata.
    #[inline]
    fn parse_packet(packet: &PacketData) -> Result<PacketMeta, ParserError> {
        let size = packet.data.len();
        let timestamp = packet.timestamp;

        let packet_headers = PacketHeaders::from_ethernet_slice(&packet.data)
            .map_err(|e| ParserError::ParseError(format!("Failed to parse packet: {}", e)))?;

        let (src_ip, dst_ip, ttl, protocol) = match &packet_headers.net {
            Some(NetHeaders::Ipv4(ipv4, _)) => (
                IpAddr::V4(Ipv4Addr::from(ipv4.source)),
                IpAddr::V4(Ipv4Addr::from(ipv4.destination)),
                ipv4.time_to_live,
                ipv4.protocol.0,
            ),
            Some(NetHeaders::Ipv6(ipv6, _)) => (
                IpAddr::V6(Ipv6Addr::from(ipv6.source)),
                IpAddr::V6(Ipv6Addr::from(ipv6.destination)),
                ipv6.hop_limit,
                ipv6.next_header.0,
            ),
            None => {
                return Err(ParserError::ParseError("No IP header".into()));
            }
        };

        let transport = match &packet_headers.transport {
            Some(etherparse::TransportHeader::Tcp(tcp)) => {
                let flags = (if tcp.fin { 1 } else { 0 })
                    | (if tcp.syn { 2 } else { 0 })
                    | (if tcp.rst { 4 } else { 0 })
                    | (if tcp.psh { 8 } else { 0 })
                    | (if tcp.ack { 16 } else { 0 })
                    | (if tcp.urg { 32 } else { 0 });

                Transport::Tcp {
                    src_port: tcp.source_port,
                    dst_port: tcp.destination_port,
                    flags,
                    seq: tcp.sequence_number,
                    ack: tcp.acknowledgment_number,
                    window: tcp.window_size,
                }
            }
            Some(etherparse::TransportHeader::Udp(udp)) => Transport::Udp {
                src_port: udp.source_port,
                dst_port: udp.destination_port,
                length: udp.length,
            },
            _ => match protocol {
                1 => {
                    let ip_header_len = match &packet_headers.net {
                        Some(NetHeaders::Ipv4(ipv4, _)) => (ipv4.ihl() * 4) as usize,
                        _ => 20,
                    };
                    let icmp_offset = 14 + ip_header_len;
                    if packet.data.len() >= icmp_offset + 2 {
                        let icmp_type = packet.data[icmp_offset];
                        let icmp_code = packet.data[icmp_offset + 1];
                        let type_code = ((icmp_type as u16) << 8) | (icmp_code as u16);
                        Transport::Icmp {
                            type_code,
                            type_value: icmp_type,
                            code_value: icmp_code,
                        }
                    } else {
                        Transport::Icmp {
                            type_code: 0,
                            type_value: 0,
                            code_value: 0,
                        }
                    }
                }
                58 => {
                    let ip_header_len = 40;
                    let icmp_offset = 14 + ip_header_len;
                    if packet.data.len() >= icmp_offset + 2 {
                        let icmp_type = packet.data[icmp_offset];
                        let icmp_code = packet.data[icmp_offset + 1];
                        let type_code = ((icmp_type as u16) << 8) | (icmp_code as u16);
                        Transport::Icmp {
                            type_code,
                            type_value: icmp_type,
                            code_value: icmp_code,
                        }
                    } else {
                        Transport::Icmp {
                            type_code: 0,
                            type_value: 0,
                            code_value: 0,
                        }
                    }
                }
                p => Transport::Other { protocol: p },
            },
        };

        let (src_port, dst_port) = match &transport {
            Transport::Tcp {
                src_port, dst_port, ..
            } => (*src_port, *dst_port),
            Transport::Udp {
                src_port, dst_port, ..
            } => (*src_port, *dst_port),
            _ => (0, 0),
        };

        let src = IpEndpoint {
            addr: src_ip,
            port: src_port,
        };

        let dst = IpEndpoint {
            addr: dst_ip,
            port: dst_port,
        };

        Ok(PacketMeta {
            timestamp,
            size,
            src,
            dst,
            transport,
            ttl,
        })
    }

    /// Stop the parser.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Parser stopped");
    }

    /// Check if the parser is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get parser statistics: (processed, dropped, errors).
    pub fn get_stats(&self) -> (u64, u64, u64) {
        (
            self.packets_processed.load(Ordering::Relaxed),
            self.packets_dropped.load(Ordering::Relaxed),
            self.parse_errors.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::time::SystemTime;

    #[test]
    fn test_parser_new() {
        let parser = Parser::new();
        assert_eq!(parser.is_running(), false);
    }

    #[test]
    fn test_parse_tcp_packet() {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 64)
            .tcp(12345, 80, 123456, 64000);

        let payload = b"HTTP GET /index.html";
        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet, payload).unwrap();

        let packet_data = PacketData {
            data: packet,
            timestamp: SystemTime::now(),
        };

        let meta = Parser::parse_packet(&packet_data).unwrap();

        assert_eq!(meta.src.addr, IpAddr::V4("192.168.1.1".parse().unwrap()));
        assert_eq!(meta.src.port, 12345);
        assert_eq!(meta.dst.addr, IpAddr::V4("192.168.1.2".parse().unwrap()));
        assert_eq!(meta.dst.port, 80);
        assert_eq!(meta.ttl, 64);

        match meta.transport {
            Transport::Tcp {
                src_port, dst_port, ..
            } => {
                assert_eq!(src_port, 12345);
                assert_eq!(dst_port, 80);
            }
            _ => panic!("Expected TCP transport"),
        }
    }

    #[test]
    fn test_parse_udp_packet() {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 64)
            .udp(12345, 53);

        let payload = b"DNS request";
        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet, payload).unwrap();

        let packet_data = PacketData {
            data: packet,
            timestamp: SystemTime::now(),
        };

        let meta = Parser::parse_packet(&packet_data).unwrap();

        assert_eq!(meta.src.addr, IpAddr::V4("192.168.1.1".parse().unwrap()));
        assert_eq!(meta.src.port, 12345);
        assert_eq!(meta.dst.addr, IpAddr::V4("192.168.1.2".parse().unwrap()));
        assert_eq!(meta.dst.port, 53);

        match meta.transport {
            Transport::Udp {
                src_port,
                dst_port,
                length,
            } => {
                assert_eq!(src_port, 12345);
                assert_eq!(dst_port, 53);
                assert!(length > 0);
            }
            _ => panic!("Expected UDP transport"),
        }
    }
}
