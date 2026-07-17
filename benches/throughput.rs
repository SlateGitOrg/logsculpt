//! Throughput benchmark: synthesizes a mixed-format log stream (JSON /
//! syslog / plaintext, matching the mix a real multi-service incident would
//! produce) and measures parse throughput, comparing sequential vs. rayon
//! parallel parsing to demonstrate the scaling story for multi-GB logs.
//!
//! Run with: `cargo bench`
//! (Criterion's HTML report lands in target/criterion/report/index.html.)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use logsculpt::parsers::{parse_line, parse_lines_parallel};

fn synth_line(i: usize) -> String {
    match i % 3 {
        0 => format!(
            r#"{{"ts":{},"level":"info","service":"orders-api","host":"host-{}","message":"processed order {} in {}ms"}}"#,
            1_700_000_000_000i64 + i as i64,
            i % 12,
            i,
            i % 500
        ),
        1 => format!(
            "<13>Jan  2 15:04:{:02} host-{} orders-worker[{}]: picked up job {}",
            i % 60,
            i % 12,
            1000 + i % 500,
            i
        ),
        _ => format!(
            "2024-01-15 10:23:{:02} INFO orders-worker: retrying job {} (attempt {})",
            i % 60,
            i,
            i % 5
        ),
    }
}

fn generate_corpus(n: usize) -> Vec<String> {
    (0..n).map(synth_line).collect()
}

fn bench_sequential_vs_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_throughput");

    for &n in &[10_000usize, 100_000, 500_000] {
        let corpus = generate_corpus(n);
        let total_bytes: u64 = corpus.iter().map(|l| l.len() as u64 + 1).sum();
        group.throughput(Throughput::Bytes(total_bytes));

        group.bench_with_input(BenchmarkId::new("sequential", n), &corpus, |b, corpus| {
            b.iter(|| {
                let out: Vec<_> = corpus
                    .iter()
                    .map(|line| parse_line(black_box(line), "bench.log", 0))
                    .collect();
                black_box(out);
            });
        });

        group.bench_with_input(
            BenchmarkId::new("rayon_parallel", n),
            &corpus,
            |b, corpus| {
                b.iter(|| {
                    let out = parse_lines_parallel(black_box(corpus), "bench.log");
                    black_box(out);
                });
            },
        );
    }

    group.finish();
}

fn bench_anomaly_detection(c: &mut Criterion) {
    use logsculpt::anomaly::{
        detect_rare_error_clusters, detect_rate_spikes, ErrorClusterConfig, RateSpikeConfig,
    };

    let mut group = c.benchmark_group("anomaly_detection");
    for &n in &[50_000usize, 200_000] {
        let corpus = generate_corpus(n);
        let entries = parse_lines_parallel(&corpus, "bench.log");
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(
            BenchmarkId::new("rate_spikes", n),
            &entries,
            |b, entries| {
                b.iter(|| {
                    black_box(detect_rate_spikes(
                        black_box(entries),
                        &RateSpikeConfig::default(),
                    ))
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("error_clusters", n),
            &entries,
            |b, entries| {
                b.iter(|| {
                    black_box(detect_rare_error_clusters(
                        black_box(entries),
                        &ErrorClusterConfig::default(),
                    ))
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_sequential_vs_parallel,
    bench_anomaly_detection
);
criterion_main!(benches);
