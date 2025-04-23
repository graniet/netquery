use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fake::{Fake, Faker};
use ingest_es::{ElasticsearchIngestor, FlowDoc, IpField};
use parser::{IpEndpoint, PacketMeta, Transport};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::runtime::Runtime;

fn generate_random_packet() -> PacketMeta {
    // Generate random IPs
    let src_ip_bytes: [u8; 4] = Faker.fake();
    let dst_ip_bytes: [u8; 4] = Faker.fake();

    // Avoid private IPs for more realistic data
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        (src_ip_bytes[0] % 223) + 1, // Avoid 0 and 224+
        src_ip_bytes[1],
        src_ip_bytes[2],
        src_ip_bytes[3],
    ));

    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        (dst_ip_bytes[0] % 223) + 1, // Avoid 0 and 224+
        dst_ip_bytes[1],
        dst_ip_bytes[2],
        dst_ip_bytes[3],
    ));

    // Random ports but avoid 0
    let src_port = (1..65535).fake::<u16>();
    let dst_port = (1..65535).fake::<u16>();

    // Transport protocol (mostly TCP and UDP)
    let transport = match (0..10).fake::<u8>() {
        0..=7 => Transport::Tcp {
            src_port,
            dst_port,
            flags: (0..=31).fake::<u8>(), // Random TCP flags
            seq: Faker.fake(),
            ack: Faker.fake(),
            window: Faker.fake(),
        },
        8..=9 => Transport::Udp {
            src_port,
            dst_port,
            length: (40..1500).fake(),
        },
        _ => unreachable!(),
    };

    PacketMeta {
        timestamp: SystemTime::now(),
        size: (40..1500).fake(),
        src: IpEndpoint {
            addr: src_ip,
            port: src_port,
        },
        dst: IpEndpoint {
            addr: dst_ip,
            port: dst_port,
        },
        transport,
        ttl: (32..128).fake(),
    }
}

fn generate_random_flow_docs(count: usize) -> Vec<FlowDoc> {
    let now = chrono::Utc::now();
    let bucket_start = now - chrono::Duration::minutes(1);
    let bucket_end = now;

    (0..count)
        .map(|_| {
            let src_port: Option<u16> = if (0..10).fake::<u8>() < 9 {
                Some((1..65535).fake::<u16>())
            } else {
                None
            };

            let dst_port: Option<u16> = if (0..10).fake::<u8>() < 9 {
                Some((1..65535).fake::<u16>())
            } else {
                None
            };

            let protocol = match (0..10).fake::<u8>() {
                0..=7 => "tcp".to_string(),
                8..=9 => "udp".to_string(),
                _ => "icmp".to_string(),
            };

            let flags = if protocol == "tcp" {
                Some((0..=31).fake::<u8>())
            } else {
                None
            };

            let (icmp_type, icmp_code) = if protocol == "icmp" {
                (Some((0..=15).fake::<u8>()), Some((0..=15).fake::<u8>()))
            } else {
                (None, None)
            };

            FlowDoc {
                timestamp: now,
                bucket_start,
                bucket_end,
                src: IpField {
                    ip: format!(
                        "{}.{}.{}.{}",
                        (1..=254).fake::<u8>(),
                        (1..=254).fake::<u8>(),
                        (1..=254).fake::<u8>(),
                        (1..=254).fake::<u8>()
                    ),
                    port: src_port,
                },
                dst: IpField {
                    ip: format!(
                        "{}.{}.{}.{}",
                        (1..=254).fake::<u8>(),
                        (1..=254).fake::<u8>(),
                        (1..=254).fake::<u8>(),
                        (1..=254).fake::<u8>()
                    ),
                    port: dst_port,
                },
                protocol,
                bytes: (40..100000).fake::<u64>(),
                packets: (1..1000).fake::<u64>(),
                flags,
                icmp_type,
                icmp_code,
            }
        })
        .collect()
}

fn bench_packet_to_doc_conversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_to_doc");

    // Create 1000 sample packets
    let packets: Vec<_> = (0..1000).map(|_| generate_random_packet()).collect();
    let packets_arc = Arc::new(packets);

    group.bench_function("convert_1000_packets", |b| {
        let packets = packets_arc.clone();
        b.iter(|| {
            for packet in packets.iter() {
                let _ = ElasticsearchIngestor::create_doc_from_packet(packet, 1);
            }
        });
    });

    group.finish();
}

fn bench_bulk_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("bulk_serialization");

    for size in [100, 1000, 5000].iter() {
        let docs = generate_random_flow_docs(*size);

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &docs, |b, docs| {
            b.iter(|| {
                for doc in docs.iter() {
                    let _ = serde_json::to_string(doc).unwrap();
                }
            });
        });
    }

    group.finish();
}

fn bench_full_bulk_pipeline(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("bulk_pipeline");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10);

    for size in [100, 1000, 5000].iter() {
        let docs = generate_random_flow_docs(*size);

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &docs, |b, docs| {
            let docs = docs.clone();
            b.to_async(&rt).iter(|| async {
                // This is a mock implementation as we don't want to connect to a real ES server during benchmarks
                // In a real scenario, this would use the ElasticsearchIngestor::flush_documents method

                // Convert all docs to JSON - create an NDJSON bulk body
                let mut bulk_body = String::with_capacity(docs.len() * 200);

                for doc in &docs {
                    // Action line
                    bulk_body.push_str("{\"create\":{\"_index\":\"netquery-flows-test\"}}\n");

                    // Document line
                    bulk_body.push_str(&serde_json::to_string(&doc).unwrap());
                    bulk_body.push('\n');
                }

                // In a real scenario, this would be sent to ES
                let _bulk_request_body = bulk_body;

                // Simulate some network latency
                tokio::time::sleep(Duration::from_millis(5)).await;
            });
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(20))
        .sample_size(50);
    targets = bench_packet_to_doc_conversion, bench_bulk_serialization, bench_full_bulk_pipeline
);
criterion_main!(benches);
