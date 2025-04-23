use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use etherparse::PacketBuilder;
use parser::{PacketMeta, Parser};
use sniffer::PacketData;
use std::time::{Duration, SystemTime};

fn create_sample_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, 123456, 64000);

    let payload = b"HTTP GET /index.html";
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, payload).unwrap();
    packet
}

fn parse_time_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser");
    group.throughput(Throughput::Elements(1));
    group.measurement_time(Duration::from_secs(10));

    // Generate a range of different packets to avoid caching effects
    let mut packets = Vec::with_capacity(1000);
    for i in 0..250 {
        for j in 0..4 {
            let src_ip = [192, 168, (i % 256) as u8, ((i / 256) % 256) as u8];
            let dst_ip = [10, 0, (j % 256) as u8, ((j / 256) % 256) as u8];
            let src_port = 1024 + (i % 60000) as u16;
            let dst_port = 1024 + (j % 60000) as u16;

            let packet = create_sample_packet(src_ip, dst_ip, src_port, dst_port);
            packets.push(PacketData {
                data: packet,
                timestamp: SystemTime::now(),
            });
        }
    }

    group.bench_function("parse_time_per_pkt", |b| {
        b.iter_batched(
            || packets.clone(),
            |packets| {
                for packet in packets {
                    let _meta = Parser::parse_packet(&packet).unwrap();
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, parse_time_benchmark);
criterion_main!(benches);
