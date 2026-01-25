//! Benchmarks for response body scanning in icebreaker-proxy.

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use futures::StreamExt;
use http_body_util::BodyExt;

use icebreaker_bench::{generate_random_bytes, CHUNK_SIZES, PATTERN_SIZES};
use icebreaker_proxy::{OverlapBuffer, ScanningBody, SecretScannerConfig, StreamScanner};

/// Benchmarks overlap buffer processing with various chunk sizes.
fn bench_overlap_buffer_process(c: &mut Criterion) {
    let mut group = c.benchmark_group("overlap_buffer_process");

    for chunk_size in CHUNK_SIZES {
        let chunk = Bytes::from(generate_random_bytes(*chunk_size));

        group.throughput(Throughput::Bytes(*chunk_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(chunk_size),
            &chunk,
            |b, chunk| {
                b.iter(|| {
                    let mut buffer = OverlapBuffer::default();
                    black_box(buffer.process(black_box(chunk), false))
                })
            },
        );
    }
    group.finish();
}

/// Benchmarks overlap buffer with multiple chunks.
fn bench_overlap_buffer_streaming(c: &mut Criterion) {
    let mut group = c.benchmark_group("overlap_buffer_streaming");

    let chunk_counts = [4, 16, 64];
    let chunk_size = 4096;

    for count in chunk_counts {
        let chunks: Vec<Bytes> = (0..count)
            .map(|_| Bytes::from(generate_random_bytes(chunk_size)))
            .collect();

        let total_bytes = count * chunk_size;
        group.throughput(Throughput::Bytes(total_bytes as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &chunks, |b, chunks| {
            b.iter(|| {
                let mut buffer = OverlapBuffer::default();
                for (i, chunk) in chunks.iter().enumerate() {
                    let is_last = i == chunks.len() - 1;
                    black_box(buffer.process(black_box(chunk), is_last));
                }
            })
        });
    }
    group.finish();
}

/// Benchmarks stream scanner with varying pattern lengths.
fn bench_stream_scanner_pattern_length(c: &mut Criterion) {
    let chunk_size = 16 * 1024;
    let chunk = Bytes::from(generate_random_bytes(chunk_size));

    let mut group = c.benchmark_group("stream_scanner_pattern_length");
    group.throughput(Throughput::Bytes(chunk_size as u64));

    for pattern_size in PATTERN_SIZES {
        let pattern: Vec<u8> = (0..*pattern_size).map(|i| (i % 256) as u8).collect();
        let patterns = vec![pattern];

        group.bench_with_input(
            BenchmarkId::from_parameter(pattern_size),
            &patterns,
            |b, patterns| {
                b.iter(|| {
                    let mut scanner = StreamScanner::new(patterns.clone());
                    black_box(scanner.scan_chunk(black_box(&chunk), false))
                })
            },
        );
    }
    group.finish();
}

/// Benchmarks stream scanner with varying number of patterns.
fn bench_stream_scanner_pattern_count(c: &mut Criterion) {
    let chunk_size = 16 * 1024;
    let chunk = Bytes::from(generate_random_bytes(chunk_size));

    let pattern_counts = [1, 5, 10, 20];

    let mut group = c.benchmark_group("stream_scanner_pattern_count");
    group.throughput(Throughput::Bytes(chunk_size as u64));

    for count in pattern_counts {
        let patterns: Vec<Vec<u8>> = (0..count)
            .map(|i| {
                let base = i * 32;
                (base..base + 32).map(|j| (j % 256) as u8).collect()
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &patterns,
            |b, patterns| {
                b.iter(|| {
                    let mut scanner = StreamScanner::new(patterns.clone());
                    black_box(scanner.scan_chunk(black_box(&chunk), false))
                })
            },
        );
    }
    group.finish();
}

/// Benchmarks stream scanner when secret is found.
fn bench_stream_scanner_detection(c: &mut Criterion) {
    let secret = b"super_secret_api_key_12345";
    let chunk_size = 16 * 1024;

    // Create chunk with secret at various positions
    let mut chunk_start = generate_random_bytes(chunk_size);
    chunk_start[..secret.len()].copy_from_slice(secret);

    let mut chunk_middle = generate_random_bytes(chunk_size);
    let mid = chunk_size / 2;
    chunk_middle[mid..mid + secret.len()].copy_from_slice(secret);

    let mut chunk_end = generate_random_bytes(chunk_size);
    let end_pos = chunk_size - secret.len();
    chunk_end[end_pos..].copy_from_slice(secret);

    let patterns = vec![secret.to_vec()];

    let mut group = c.benchmark_group("stream_scanner_detection");
    group.throughput(Throughput::Bytes(chunk_size as u64));

    group.bench_function("secret_at_start", |b| {
        let chunk = Bytes::from(chunk_start.clone());
        b.iter(|| {
            let mut scanner = StreamScanner::new(patterns.clone());
            black_box(scanner.scan_chunk(black_box(&chunk), false))
        })
    });

    group.bench_function("secret_at_middle", |b| {
        let chunk = Bytes::from(chunk_middle.clone());
        b.iter(|| {
            let mut scanner = StreamScanner::new(patterns.clone());
            black_box(scanner.scan_chunk(black_box(&chunk), false))
        })
    });

    group.bench_function("secret_at_end", |b| {
        let chunk = Bytes::from(chunk_end.clone());
        b.iter(|| {
            let mut scanner = StreamScanner::new(patterns.clone());
            black_box(scanner.scan_chunk(black_box(&chunk), false))
        })
    });

    // No secret (worst case - must scan entire chunk)
    group.bench_function("no_secret", |b| {
        let chunk = Bytes::from(generate_random_bytes(chunk_size));
        b.iter(|| {
            let mut scanner = StreamScanner::new(patterns.clone());
            black_box(scanner.scan_chunk(black_box(&chunk), false))
        })
    });

    group.finish();
}

/// Benchmarks stream scanner with boundary-spanning patterns.
fn bench_stream_scanner_boundary(c: &mut Criterion) {
    let secret = b"boundary_spanning_secret";
    let chunk_size = 4096;

    // Create two chunks where the secret spans the boundary
    let mut chunk1 = generate_random_bytes(chunk_size);
    let split_point = secret.len() / 2;
    let insert_pos = chunk_size - split_point;
    chunk1[insert_pos..].copy_from_slice(&secret[..split_point]);

    let mut chunk2 = generate_random_bytes(chunk_size);
    chunk2[..secret.len() - split_point].copy_from_slice(&secret[split_point..]);

    let patterns = vec![secret.to_vec()];

    c.bench_function("stream_scanner_boundary_detection", |b| {
        let c1 = Bytes::from(chunk1.clone());
        let c2 = Bytes::from(chunk2.clone());
        b.iter(|| {
            let mut scanner = StreamScanner::new(patterns.clone());
            scanner.scan_chunk(black_box(&c1), false);
            black_box(scanner.scan_chunk(black_box(&c2), false))
        })
    });
}

/// Benchmarks SecretScannerConfig creation and wrapping.
fn bench_secret_scanner_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("secret_scanner_config");

    group.bench_function("create_scanner", |b| {
        let config = SecretScannerConfig::new()
            .with_pattern(b"secret1")
            .with_pattern(b"secret2")
            .with_pattern(b"secret3");
        b.iter(|| black_box(config.create_scanner()))
    });

    group.finish();
}

/// Benchmarks ScanningBody with streaming data.
fn bench_scanning_body(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let patterns = vec![
        b"secret_api_key".to_vec(),
        b"password123".to_vec(),
        b"auth_token".to_vec(),
    ];

    let body_sizes = [1024, 8 * 1024, 64 * 1024];

    let mut group = c.benchmark_group("scanning_body");

    for size in body_sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &patterns,
            |b, patterns| {
                b.iter(|| {
                    rt.block_on(async {
                        let data = generate_random_bytes(size);
                        let body = http_body_util::Full::new(Bytes::from(data));
                        let scanning = ScanningBody::new(body, patterns.clone());
                        black_box(scanning.collect().await)
                    })
                })
            },
        );
    }

    group.finish();
}

/// Benchmarks chunked body scanning.
fn bench_scanning_body_chunked(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let patterns = vec![b"secret_value".to_vec()];
    let chunk_count = 16;
    let chunk_size = 4096;

    c.bench_function("scanning_body_chunked_16x4kb", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Create a stream of chunks
                let chunks: Vec<Result<Bytes, std::convert::Infallible>> = (0..chunk_count)
                    .map(|_| Ok(Bytes::from(generate_random_bytes(chunk_size))))
                    .collect();

                let stream = futures::stream::iter(chunks);
                let body =
                    http_body_util::StreamBody::new(stream.map(|r| r.map(http_body::Frame::data)));
                let scanning = ScanningBody::new(body, patterns.clone());
                black_box(scanning.collect().await)
            })
        })
    });
}

/// Benchmarks varying chunk sizes for scanning.
fn bench_scan_chunk_sizes(c: &mut Criterion) {
    let patterns = vec![b"secret_pattern_to_find".to_vec()];

    let mut group = c.benchmark_group("scan_chunk_sizes");

    for chunk_size in CHUNK_SIZES {
        let chunk = Bytes::from(generate_random_bytes(*chunk_size));

        group.throughput(Throughput::Bytes(*chunk_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(chunk_size),
            &chunk,
            |b, chunk| {
                b.iter(|| {
                    let mut scanner = StreamScanner::new(patterns.clone());
                    black_box(scanner.scan_chunk(black_box(chunk), false))
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    scanning_benches,
    bench_overlap_buffer_process,
    bench_overlap_buffer_streaming,
    bench_stream_scanner_pattern_length,
    bench_stream_scanner_pattern_count,
    bench_stream_scanner_detection,
    bench_stream_scanner_boundary,
    bench_secret_scanner_config,
    bench_scanning_body,
    bench_scanning_body_chunked,
    bench_scan_chunk_sizes,
);

criterion_main!(scanning_benches);
