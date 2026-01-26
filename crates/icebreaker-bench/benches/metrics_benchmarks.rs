//! Benchmarks for metrics recording overhead in icebreaker-proxy.
//!
//! These benchmarks measure the performance overhead of recording metrics
//! to ensure that instrumentation doesn't significantly impact request latency.

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use icebreaker_proxy::metrics::{
    record_blocked_address, record_connect_tunnel, record_host_rejection, record_processor_used,
    record_request, record_request_bytes, record_request_duration, record_response_bytes,
    record_secret_leak_detected, record_token_validation, set_active_connections, BlockReason,
    TokenValidationResult,
};

// ============================================================================
// Request Metrics
// ============================================================================

/// Benchmarks recording a completed HTTP request.
fn bench_record_request(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics_record_request");

    // 2xx success with processor
    group.bench_function("2xx_with_processor", |b| {
        b.iter(|| {
            record_request(black_box("POST"), black_box(200), black_box(Some("inject")));
        })
    });

    // 4xx error without processor
    group.bench_function("4xx_no_processor", |b| {
        b.iter(|| {
            record_request(black_box("GET"), black_box(404), black_box(None));
        })
    });

    // 5xx error
    group.bench_function("5xx", |b| {
        b.iter(|| {
            record_request(black_box("POST"), black_box(500), black_box(Some("sigv4")));
        })
    });

    group.finish();
}

/// Benchmarks recording request duration.
fn bench_record_request_duration(c: &mut Criterion) {
    let durations = [
        Duration::from_micros(100),
        Duration::from_millis(1),
        Duration::from_millis(10),
        Duration::from_millis(100),
        Duration::from_secs(1),
    ];

    let mut group = c.benchmark_group("metrics_record_duration");

    for duration in durations {
        group.bench_function(format!("{:?}", duration), |b| {
            b.iter(|| {
                record_request_duration(black_box(duration));
            })
        });
    }

    group.finish();
}

/// Benchmarks recording request/response bytes.
fn bench_record_bytes(c: &mut Criterion) {
    let byte_counts = [0u64, 1024, 65536, 1024 * 1024];

    let mut group = c.benchmark_group("metrics_record_bytes");

    for bytes in byte_counts {
        group.bench_function(format!("request_{}", bytes), |b| {
            b.iter(|| {
                record_request_bytes(black_box(bytes));
            })
        });

        group.bench_function(format!("response_{}", bytes), |b| {
            b.iter(|| {
                record_response_bytes(black_box(bytes));
            })
        });
    }

    group.finish();
}

// ============================================================================
// Token Metrics
// ============================================================================

/// Benchmarks recording token validation results.
fn bench_record_token_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics_record_token_validation");

    group.bench_function("success", |b| {
        b.iter(|| {
            record_token_validation(black_box(TokenValidationResult::Success));
        })
    });

    group.bench_function("expired", |b| {
        b.iter(|| {
            record_token_validation(black_box(TokenValidationResult::Expired));
        })
    });

    group.bench_function("invalid", |b| {
        b.iter(|| {
            record_token_validation(black_box(TokenValidationResult::Invalid));
        })
    });

    group.bench_function("decryption_failed", |b| {
        b.iter(|| {
            record_token_validation(black_box(TokenValidationResult::DecryptionFailed));
        })
    });

    group.bench_function("missing", |b| {
        b.iter(|| {
            record_token_validation(black_box(TokenValidationResult::Missing));
        })
    });

    group.finish();
}

/// Benchmarks recording host rejection.
fn bench_record_host_rejection(c: &mut Criterion) {
    let hosts = [
        "evil.com",
        "internal.corp.example.com",
        "very-long-subdomain.another-subdomain.example.org",
    ];

    let mut group = c.benchmark_group("metrics_record_host_rejection");

    for host in hosts {
        group.bench_function(format!("host_len_{}", host.len()), |b| {
            b.iter(|| {
                record_host_rejection(black_box(host));
            })
        });
    }

    group.finish();
}

// ============================================================================
// Security Metrics
// ============================================================================

/// Benchmarks recording secret leak detection.
fn bench_record_secret_leak(c: &mut Criterion) {
    c.bench_function("metrics_record_secret_leak", |b| {
        b.iter(|| {
            record_secret_leak_detected();
        })
    });
}

/// Benchmarks recording blocked addresses.
fn bench_record_blocked_address(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics_record_blocked_address");

    group.bench_function("private_network", |b| {
        b.iter(|| {
            record_blocked_address(black_box(BlockReason::PrivateNetwork));
        })
    });

    group.bench_function("loopback", |b| {
        b.iter(|| {
            record_blocked_address(black_box(BlockReason::Loopback));
        })
    });

    group.bench_function("link_local", |b| {
        b.iter(|| {
            record_blocked_address(black_box(BlockReason::LinkLocal));
        })
    });

    group.bench_function("blocked_cidr", |b| {
        b.iter(|| {
            record_blocked_address(black_box(BlockReason::BlockedCidr));
        })
    });

    group.bench_function("blocked_hostname", |b| {
        b.iter(|| {
            record_blocked_address(black_box(BlockReason::BlockedHostname));
        })
    });

    group.finish();
}

// ============================================================================
// Connection Metrics
// ============================================================================

/// Benchmarks setting active connections gauge.
fn bench_set_active_connections(c: &mut Criterion) {
    let counts = [0u64, 1, 10, 100, 1000, 10000];

    let mut group = c.benchmark_group("metrics_set_active_connections");

    for count in counts {
        group.bench_function(format!("count_{}", count), |b| {
            b.iter(|| {
                set_active_connections(black_box(count));
            })
        });
    }

    group.finish();
}

/// Benchmarks recording CONNECT tunnel.
fn bench_record_connect_tunnel(c: &mut Criterion) {
    c.bench_function("metrics_record_connect_tunnel", |b| {
        b.iter(|| {
            record_connect_tunnel();
        })
    });
}

// ============================================================================
// Processor Metrics
// ============================================================================

/// Benchmarks recording processor usage.
fn bench_record_processor_used(c: &mut Criterion) {
    let processor_types = ["inject", "inject_hmac", "oauth", "inject_body", "sigv4"];

    let mut group = c.benchmark_group("metrics_record_processor_used");

    for processor_type in processor_types {
        group.bench_function(processor_type, |b| {
            b.iter(|| {
                record_processor_used(black_box(processor_type));
            })
        });
    }

    group.finish();
}

// ============================================================================
// Combined Metrics (Realistic Scenarios)
// ============================================================================

/// Benchmarks a typical successful request metrics recording pattern.
fn bench_metrics_success_request_pattern(c: &mut Criterion) {
    let duration = Duration::from_millis(5);

    c.bench_function("metrics_success_request_pattern", |b| {
        b.iter(|| {
            record_token_validation(TokenValidationResult::Success);
            record_processor_used("inject");
            record_request_bytes(1024);
            record_response_bytes(4096);
            record_request_duration(duration);
            record_request("POST", 200, Some("inject"));
        })
    });
}

/// Benchmarks a typical failed request metrics recording pattern.
fn bench_metrics_failed_request_pattern(c: &mut Criterion) {
    c.bench_function("metrics_failed_request_pattern", |b| {
        b.iter(|| {
            record_token_validation(TokenValidationResult::Invalid);
            record_host_rejection("blocked.example.com");
            record_request("GET", 403, None);
        })
    });
}

/// Benchmarks a blocked address metrics recording pattern.
fn bench_metrics_blocked_pattern(c: &mut Criterion) {
    c.bench_function("metrics_blocked_pattern", |b| {
        b.iter(|| {
            record_token_validation(TokenValidationResult::Success);
            record_blocked_address(BlockReason::PrivateNetwork);
            record_request("GET", 403, None);
        })
    });
}

/// Benchmarks a secret leak detection metrics recording pattern.
fn bench_metrics_leak_detection_pattern(c: &mut Criterion) {
    let duration = Duration::from_millis(10);

    c.bench_function("metrics_leak_detection_pattern", |b| {
        b.iter(|| {
            record_token_validation(TokenValidationResult::Success);
            record_processor_used("inject");
            record_request_bytes(256);
            record_secret_leak_detected();
            record_request_duration(duration);
            record_request("POST", 500, Some("inject"));
        })
    });
}

criterion_group!(
    metrics_benches,
    bench_record_request,
    bench_record_request_duration,
    bench_record_bytes,
    bench_record_token_validation,
    bench_record_host_rejection,
    bench_record_secret_leak,
    bench_record_blocked_address,
    bench_set_active_connections,
    bench_record_connect_tunnel,
    bench_record_processor_used,
    bench_metrics_success_request_pattern,
    bench_metrics_failed_request_pattern,
    bench_metrics_blocked_pattern,
    bench_metrics_leak_detection_pattern,
);

criterion_main!(metrics_benches);
