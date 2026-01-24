//! Benchmarks for middleware components in icebreaker-proxy.

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use icebreaker_bench::{create_test_crypto, create_test_payload};
use icebreaker_common::RateLimitConfig;
use icebreaker_proxy::{HostValidationConfig, RateLimiter};

/// Benchmarks host validation with exact match.
fn bench_host_validation_exact(c: &mut Criterion) {
    let config = HostValidationConfig::new()
        .allow_host("api.example.com")
        .allow_host("api.test.com")
        .allow_host("api.staging.com")
        .allow_host("api.production.com")
        .allow_host("api.dev.com");

    let mut group = c.benchmark_group("host_validation_exact");

    // Benchmark matching the first host
    group.bench_function("first_match", |b| {
        b.iter(|| black_box(config.validate(black_box("api.example.com"))))
    });

    // Benchmark matching the last host
    group.bench_function("last_match", |b| {
        b.iter(|| black_box(config.validate(black_box("api.dev.com"))))
    });

    // Benchmark non-matching host (should fail)
    group.bench_function("no_match", |b| {
        b.iter(|| black_box(config.validate(black_box("evil.com"))))
    });

    group.finish();
}

/// Benchmarks host validation with regex patterns.
fn bench_host_validation_regex(c: &mut Criterion) {
    let config = HostValidationConfig::new()
        .allow_pattern(r"^api\.[a-z]+\.example\.com$")
        .allow_pattern(r".*\.internal\.company\.com$");

    let mut group = c.benchmark_group("host_validation_regex");

    // Benchmark matching pattern
    group.bench_function("pattern_match", |b| {
        b.iter(|| black_box(config.validate(black_box("api.test.example.com"))))
    });

    // Benchmark non-matching
    group.bench_function("pattern_no_match", |b| {
        b.iter(|| black_box(config.validate(black_box("evil.example.org"))))
    });

    group.finish();
}

/// Benchmarks host validation with blocklist.
fn bench_host_validation_blocklist(c: &mut Criterion) {
    let config = HostValidationConfig::new()
        .allow_pattern(".*")
        .block_host("blocked.example.com")
        .block_pattern(r".*\.internal\..*");

    let mut group = c.benchmark_group("host_validation_blocklist");

    // Allowed host
    group.bench_function("allowed", |b| {
        b.iter(|| black_box(config.validate(black_box("api.example.com"))))
    });

    // Exact block match
    group.bench_function("blocked_exact", |b| {
        b.iter(|| black_box(config.validate(black_box("blocked.example.com"))))
    });

    // Pattern block match
    group.bench_function("blocked_pattern", |b| {
        b.iter(|| black_box(config.validate(black_box("api.internal.company.com"))))
    });

    group.finish();
}

/// Benchmarks host validation with varying allowlist sizes.
fn bench_host_validation_scale(c: &mut Criterion) {
    let sizes = [1, 10, 50, 100];

    let mut group = c.benchmark_group("host_validation_scale");
    for size in sizes {
        let mut config = HostValidationConfig::new();
        for i in 0..size {
            config = config.allow_host(format!("api{}.example.com", i));
        }
        // Add the test host at the end
        config = config.allow_host("target.example.com");

        group.bench_with_input(BenchmarkId::from_parameter(size), &config, |b, cfg| {
            b.iter(|| black_box(cfg.validate(black_box("target.example.com"))))
        });
    }
    group.finish();
}

/// Benchmarks rate limiter check operation.
fn bench_rate_limiter_check(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let config = RateLimitConfig {
        max_requests: 1000,
        period: Duration::from_secs(60),
        burst: 100,
    };
    let limiter = RateLimiter::new(config);

    let mut group = c.benchmark_group("rate_limiter");

    // Benchmark cold check (new key)
    group.bench_function("cold_check", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let key = format!("key-{}", counter);
            rt.block_on(async { black_box(limiter.check(black_box(&key)).await) })
        })
    });

    // Benchmark hot check (same key, within limit)
    group.bench_function("hot_check", |b| {
        b.iter(|| rt.block_on(async { black_box(limiter.check(black_box("hot-key")).await) }))
    });

    // Benchmark check with many keys
    for i in 0..100 {
        let key = format!("preload-key-{}", i);
        rt.block_on(async { limiter.check(&key).await });
    }

    group.bench_function("check_with_contention", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let key = format!("preload-key-{}", counter % 100);
            rt.block_on(async { black_box(limiter.check(black_box(&key)).await) })
        })
    });

    group.finish();
}

/// Benchmarks rate limiter clear operation.
fn bench_rate_limiter_clear(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let config = RateLimitConfig {
        max_requests: 1000,
        period: Duration::from_secs(60),
        burst: 100,
    };
    let limiter = RateLimiter::new(config);

    // Preload some keys
    for i in 0..50 {
        let key = format!("key-{}", i);
        rt.block_on(async { limiter.check(&key).await });
    }

    let mut group = c.benchmark_group("rate_limiter_clear");

    group.bench_function("clear_single", |b| {
        b.iter(|| rt.block_on(async { limiter.clear(black_box("key-0")).await }))
    });

    group.bench_function("clear_all", |b| {
        b.iter(|| rt.block_on(async { limiter.clear_all().await }))
    });

    group.finish();
}

/// Benchmarks token crypto seal/unseal as part of the injection pipeline.
fn bench_token_crypto_pipeline(c: &mut Criterion) {
    let crypto = create_test_crypto();
    let payload = create_test_payload(64);
    let sealed = crypto.seal(&payload).unwrap();

    let mut group = c.benchmark_group("token_crypto_pipeline");

    // Seal + unseal roundtrip
    group.bench_function("seal_unseal_roundtrip", |b| {
        b.iter(|| {
            let sealed = crypto.seal(black_box(&payload)).unwrap();
            black_box(crypto.unseal(black_box(&sealed)).unwrap())
        })
    });

    // Just unseal (the hot path in the proxy)
    group.bench_function("unseal_only", |b| {
        b.iter(|| black_box(crypto.unseal(black_box(&sealed)).unwrap()))
    });

    group.finish();
}

/// Benchmarks TokenPayload host validation.
fn bench_token_payload_host_validation(c: &mut Criterion) {
    let payload_single = icebreaker_common::TokenPayload::builder(
        secrecy::SecretString::from("secret"),
        icebreaker_common::ProcessorConfig::Inject(icebreaker_common::InjectConfig::bearer(
            "Authorization",
        )),
    )
    .allowed_host("api.example.com")
    .build();

    let payload_multiple = icebreaker_common::TokenPayload::builder(
        secrecy::SecretString::from("secret"),
        icebreaker_common::ProcessorConfig::Inject(icebreaker_common::InjectConfig::bearer(
            "Authorization",
        )),
    )
    .allowed_host("api.example.com")
    .allowed_host("api.test.com")
    .allowed_host("api.staging.com")
    .allowed_host("api.production.com")
    .build();

    let payload_pattern = icebreaker_common::TokenPayload::builder(
        secrecy::SecretString::from("secret"),
        icebreaker_common::ProcessorConfig::Inject(icebreaker_common::InjectConfig::bearer(
            "Authorization",
        )),
    )
    .allowed_host_pattern(r".*\.example\.com$")
    .build();

    let mut group = c.benchmark_group("token_payload_host_validation");

    group.bench_function("single_host_match", |b| {
        b.iter(|| black_box(payload_single.validate_host(black_box("api.example.com"))))
    });

    group.bench_function("multiple_hosts_match", |b| {
        b.iter(|| black_box(payload_multiple.validate_host(black_box("api.production.com"))))
    });

    group.bench_function("pattern_match", |b| {
        b.iter(|| black_box(payload_pattern.validate_host(black_box("api.example.com"))))
    });

    group.bench_function("pattern_no_match", |b| {
        b.iter(|| black_box(payload_pattern.validate_host(black_box("evil.com"))))
    });

    group.finish();
}

criterion_group!(
    middleware_benches,
    bench_host_validation_exact,
    bench_host_validation_regex,
    bench_host_validation_blocklist,
    bench_host_validation_scale,
    bench_rate_limiter_check,
    bench_rate_limiter_clear,
    bench_token_crypto_pipeline,
    bench_token_payload_host_validation,
);

criterion_main!(middleware_benches);
