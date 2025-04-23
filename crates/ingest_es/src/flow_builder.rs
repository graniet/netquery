use crate::{FlowDoc, IpField};
use chrono::{DateTime, Utc};
use parser::{PacketMeta, Transport};
use std::time::SystemTime;

use crate::protocol::infer as infer_protocol;

/// FlowBuilder enrichi qui ajoute des informations de protocole en utilisant le classificateur de protocole
pub struct FlowBuilder {
    bucket_interval_mins: u32,
}

impl FlowBuilder {
    /// Crée un nouveau FlowBuilder avec l'intervalle de bucket spécifié
    pub fn new(bucket_interval_mins: u32) -> Self {
        Self {
            bucket_interval_mins,
        }
    }

    /// Crée un document de flux à partir d'un paquet avec une inférence de protocole améliorée
    pub async fn create_doc_from_packet(&self, packet: &PacketMeta) -> FlowDoc {
        let (base_protocol, flags, icmp_type, icmp_code) = match &packet.transport {
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

        let protocol = match &packet.transport {
            Transport::Tcp {
                src_port, dst_port, ..
            } => {
                let server_port = if Self::is_likely_server_port(*dst_port) {
                    *dst_port
                } else if Self::is_likely_server_port(*src_port) {
                    *src_port
                } else {
                    std::cmp::min(*src_port, *dst_port)
                };
                infer_protocol(server_port, "tcp").await
            }
            Transport::Udp {
                src_port, dst_port, ..
            } => {
                let server_port = if Self::is_likely_server_port(*dst_port) {
                    *dst_port
                } else if Self::is_likely_server_port(*src_port) {
                    *src_port
                } else {
                    std::cmp::min(*src_port, *dst_port)
                };
                infer_protocol(server_port, "udp").await
            }
            _ => base_protocol.to_string(),
        };

        let bucket_interval_secs = (self.bucket_interval_mins as u64) * 60;

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

    /// Méthode utilitaire pour deviner si un port est probablement un port serveur
    fn is_likely_server_port(port: u16) -> bool {
        port < 1024 || port == 8080 || port == 8443 || port == 3306 || port == 5432
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parser::IpEndpoint;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_create_doc_from_packet_http() {
        let packet = PacketMeta {
            timestamp: SystemTime::now(),
            size: 1500,
            src: IpEndpoint {
                addr: IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap()),
                port: 54321,
            },
            dst: IpEndpoint {
                addr: IpAddr::V4(Ipv4Addr::from_str("192.168.1.2").unwrap()),
                port: 80,
            },
            transport: Transport::Tcp {
                src_port: 54321,
                dst_port: 80,
                flags: 0x02,
                seq: 123456,
                ack: 0,
                window: 65535,
            },
            ttl: 64,
        };

        let builder = FlowBuilder::new(1);
        let doc = builder.create_doc_from_packet(&packet).await;

        assert_eq!(doc.src.ip, "192.168.1.1");
        assert_eq!(doc.src.port, Some(54321));
        assert_eq!(doc.dst.ip, "192.168.1.2");
        assert_eq!(doc.dst.port, Some(80));
        assert_eq!(doc.protocol, "http");
        assert_eq!(doc.bytes, 1500);
        assert_eq!(doc.packets, 1);
        assert_eq!(doc.flags, Some(0x02));
    }

    #[tokio::test]
    async fn test_create_doc_from_packet_dns() {
        let packet = PacketMeta {
            timestamp: SystemTime::now(),
            size: 60,
            src: IpEndpoint {
                addr: IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap()),
                port: 33333,
            },
            dst: IpEndpoint {
                addr: IpAddr::V4(Ipv4Addr::from_str("8.8.8.8").unwrap()),
                port: 53,
            },
            transport: Transport::Udp {
                src_port: 33333,
                dst_port: 53,
            },
            ttl: 64,
        };

        let builder = FlowBuilder::new(1);
        let doc = builder.create_doc_from_packet(&packet).await;

        assert_eq!(doc.src.ip, "192.168.1.1");
        assert_eq!(doc.src.port, Some(33333));
        assert_eq!(doc.dst.ip, "8.8.8.8");
        assert_eq!(doc.dst.port, Some(53));
        assert_eq!(doc.protocol, "dns");
        assert_eq!(doc.bytes, 60);
        assert_eq!(doc.packets, 1);
    }

    #[tokio::test]
    async fn test_create_doc_from_packet_unknown() {
        let packet = PacketMeta {
            timestamp: SystemTime::now(),
            size: 100,
            src: IpEndpoint {
                addr: IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap()),
                port: 12345,
            },
            dst: IpEndpoint {
                addr: IpAddr::V4(Ipv4Addr::from_str("192.168.1.2").unwrap()),
                port: 54321,
            },
            transport: Transport::Tcp {
                src_port: 12345,
                dst_port: 54321,
                flags: 0x02,
                seq: 123456,
                ack: 0,
                window: 65535,
            },
            ttl: 64,
        };

        let builder = FlowBuilder::new(1);
        let doc = builder.create_doc_from_packet(&packet).await;

        assert!(doc.protocol == "tcp" || doc.protocol.len() > 2);
        assert_eq!(doc.bytes, 100);
        assert_eq!(doc.packets, 1);
    }
}
