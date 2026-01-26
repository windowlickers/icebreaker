//! End-to-end throughput benchmarks for the Icebreaker proxy.
//!
//! These benchmarks measure the combined performance of the full request
//! processing pipeline.

use std::time::Duration;

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use http_body_util::BodyExt;

use http::Request;
use icebreaker_bench::{
    create_test_crypto, create_test_payload_with_secret, generate_random_bytes,
};
use icebreaker_common::{
    HmacAlgorithm, InjectConfig, NetworkProtectionConfig, ProcessorConfig, RateLimitConfig,
    Sigv4Config, TokenPayload,
};
use icebreaker_crypto::{CanonicalRequestBuilder, RequestSigner};
use icebreaker_proxy::{
    create_processor, HostValidationConfig, IpFilter, OverlapBuffer, RateLimiter, ScanningBody,
    StreamScanner,
};
use secrecy::SecretString;
use std::net::IpAddr;

/// Benchmarks the full token injection pipeline.
///
/// This simulates what happens when a request comes in with a sealed token:
/// 1. Parse the sealed token
/// 2. Decrypt the token
/// 3. Validate the host
/// 4. Format the header value
fn bench_injection_pipeline(c: &mut Criterion) {
    let crypto = create_test_crypto();
    let secret = "sk_live_abcdef123456789";
    let payload = create_test_payload_with_secret(secret);
    let sealed = crypto.seal(&payload).unwrap();
    let host_config = HostValidationConfig::new().allow_host("api.example.com");

    let inject_config = InjectConfig::bearer("Authorization");

    let mut group = c.benchmark_group("injection_pipeline");

    // Full pipeline
    group.bench_function("full_pipeline", |b| {
        b.iter(|| {
            // 1. Unseal token
            let payload = crypto.unseal(black_box(&sealed)).unwrap();

            // 2. Validate host
            host_config.validate(black_box("api.example.com")).unwrap();

            // 3. Format header value
            let header_value = inject_config.format_value(payload.expose_secret());

            black_box(header_value)
        })
    });

    // Just the crypto part
    group.bench_function("crypto_only", |b| {
        b.iter(|| {
            let payload = crypto.unseal(black_box(&sealed)).unwrap();
            black_box(payload.expose_secret().to_string())
        })
    });

    // Validation + formatting
    group.bench_function("validation_and_format", |b| {
        let payload = crypto.unseal(&sealed).unwrap();
        b.iter(|| {
            host_config.validate(black_box("api.example.com")).unwrap();
            let header_value = inject_config.format_value(payload.expose_secret());
            black_box(header_value)
        })
    });

    group.finish();
}

/// Benchmarks the HMAC signing pipeline.
fn bench_hmac_pipeline(c: &mut Criterion) {
    let crypto = create_test_crypto();
    let secret = "hmac-secret-key-32-bytes-long!!";
    let payload = create_test_payload_with_secret(secret);
    let sealed = crypto.seal(&payload).unwrap();

    let request_body = b"{\"amount\":1000,\"currency\":\"usd\"}";

    let mut group = c.benchmark_group("hmac_pipeline");

    group.bench_function("full_hmac_signing", |b| {
        b.iter(|| {
            // 1. Unseal token to get HMAC key
            let payload = crypto.unseal(black_box(&sealed)).unwrap();
            let key = payload.expose_secret().as_bytes();

            // 2. Build canonical request
            let canonical = CanonicalRequestBuilder::new("POST", "/v1/charges")
                .header("Host", "api.stripe.com")
                .header("Content-Type", "application/json")
                .body(black_box(request_body))
                .build();

            // 3. Sign the request
            let signer = RequestSigner::new(key, HmacAlgorithm::Sha256);
            let signature = signer.sign_hex(canonical.as_bytes());

            black_box(signature)
        })
    });

    // Pre-unsealed key
    let payload = crypto.unseal(&sealed).unwrap();
    let signer = RequestSigner::new(payload.expose_secret().as_bytes(), HmacAlgorithm::Sha256);

    group.bench_function("signing_only", |b| {
        b.iter(|| {
            let canonical = CanonicalRequestBuilder::new("POST", "/v1/charges")
                .header("Host", "api.stripe.com")
                .header("Content-Type", "application/json")
                .body(black_box(request_body))
                .build();

            let signature = signer.sign_hex(canonical.as_bytes());
            black_box(signature)
        })
    });

    group.finish();
}

/// Benchmarks the response scanning pipeline.
fn bench_response_pipeline(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Simulate a real API response
    let secret = "sk_live_abcdef123456789";
    let patterns = vec![secret.as_bytes().to_vec()];

    let response_sizes = [1024, 8 * 1024, 64 * 1024, 256 * 1024];

    let mut group = c.benchmark_group("response_pipeline");

    for size in response_sizes {
        // Clean response (no secret)
        let clean_body = generate_random_bytes(size);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("clean", size),
            &clean_body,
            |b, body_data| {
                b.iter(|| {
                    rt.block_on(async {
                        let body = http_body_util::Full::new(Bytes::from(body_data.clone()));
                        let scanning = ScanningBody::new(body, patterns.clone());
                        black_box(scanning.collect().await)
                    })
                })
            },
        );

        // Response with secret (should detect and abort)
        let mut leaked_body = generate_random_bytes(size);
        let insert_pos = size / 2;
        leaked_body[insert_pos..insert_pos + secret.len()].copy_from_slice(secret.as_bytes());

        group.bench_with_input(
            BenchmarkId::new("leaked", size),
            &leaked_body,
            |b, body_data| {
                b.iter(|| {
                    rt.block_on(async {
                        let body = http_body_util::Full::new(Bytes::from(body_data.clone()));
                        let scanning = ScanningBody::new(body, patterns.clone());
                        // This will error, which is expected
                        black_box(scanning.collect().await)
                    })
                })
            },
        );
    }

    group.finish();
}

/// Benchmarks combined request/response overhead.
fn bench_full_request_cycle(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let crypto = create_test_crypto();
    let secret = "sk_live_abcdef123456789";
    let payload = create_test_payload_with_secret(secret);
    let sealed = crypto.seal(&payload).unwrap();

    let host_config = HostValidationConfig::new().allow_host("api.example.com");
    let inject_config = InjectConfig::bearer("Authorization");
    let patterns = vec![secret.as_bytes().to_vec()];

    let rate_config = RateLimitConfig {
        max_requests: 10000,
        period: Duration::from_secs(60),
        burst: 1000,
    };
    let rate_limiter = RateLimiter::new(rate_config);

    let response_body = generate_random_bytes(4096);

    c.bench_function("full_request_cycle_4kb", |b| {
        b.iter(|| {
            rt.block_on(async {
                // 1. Rate limit check
                rate_limiter.check(black_box("client-ip")).await;

                // 2. Unseal token
                let payload = crypto.unseal(black_box(&sealed)).unwrap();

                // 3. Validate host
                host_config.validate(black_box("api.example.com")).unwrap();

                // 4. Format header (simulates injection)
                let _header = inject_config.format_value(payload.expose_secret());

                // 5. Scan response body
                let body = http_body_util::Full::new(Bytes::from(response_body.clone()));
                let scanning = ScanningBody::new(body, patterns.clone());
                black_box(scanning.collect().await)
            })
        })
    });
}

/// Benchmarks rate limiting under various loads.
fn bench_rate_limit_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let config = RateLimitConfig {
        max_requests: 10000,
        period: Duration::from_secs(60),
        burst: 1000,
    };
    let limiter = RateLimiter::new(config);

    let mut group = c.benchmark_group("rate_limit_throughput");

    // Single key, high throughput
    group.bench_function("single_key_burst", |b| {
        b.iter(|| rt.block_on(async { black_box(limiter.check(black_box("single-key")).await) }))
    });

    // Many keys, simulating many clients
    group.bench_function("many_keys", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let key = format!("client-{}", counter % 1000);
            rt.block_on(async { black_box(limiter.check(black_box(&key)).await) })
        })
    });

    group.finish();
}

/// Benchmarks streaming scan throughput.
fn bench_streaming_scan_throughput(c: &mut Criterion) {
    let secret = b"secret_api_key_value";
    let patterns = vec![secret.to_vec()];

    // Simulate various realistic payload sizes
    let sizes = [
        ("1kb", 1024),
        ("4kb", 4 * 1024),
        ("16kb", 16 * 1024),
        ("64kb", 64 * 1024),
        ("256kb", 256 * 1024),
        ("1mb", 1024 * 1024),
    ];

    let mut group = c.benchmark_group("streaming_scan_throughput");

    for (name, size) in sizes {
        let data = generate_random_bytes(size);
        let chunk_size = 4096;
        let chunks: Vec<Bytes> = data
            .chunks(chunk_size)
            .map(|c| Bytes::copy_from_slice(c))
            .collect();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("scan", name), &chunks, |b, chunks| {
            b.iter(|| {
                let mut scanner = StreamScanner::new(patterns.clone());
                for (i, chunk) in chunks.iter().enumerate() {
                    let is_last = i == chunks.len() - 1;
                    if scanner.scan_chunk(black_box(chunk), is_last) {
                        break;
                    }
                }
                black_box(scanner)
            })
        });
    }

    group.finish();
}

/// Benchmarks memory-efficient overlap buffer for large streams.
fn bench_overlap_buffer_large_stream(c: &mut Criterion) {
    let sizes = [
        ("64kb", 64 * 1024),
        ("256kb", 256 * 1024),
        ("1mb", 1024 * 1024),
    ];
    let chunk_size = 16 * 1024;

    let mut group = c.benchmark_group("overlap_buffer_large_stream");

    for (name, total_size) in sizes {
        let data = generate_random_bytes(total_size);
        let chunks: Vec<Bytes> = data
            .chunks(chunk_size)
            .map(|c| Bytes::copy_from_slice(c))
            .collect();

        group.throughput(Throughput::Bytes(total_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &chunks, |b, chunks| {
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

/// Benchmarks token seal/unseal with realistic concurrent usage.
fn bench_concurrent_token_operations(c: &mut Criterion) {
    let crypto = create_test_crypto();
    let payloads: Vec<_> = (0..100)
        .map(|i| create_test_payload_with_secret(&format!("secret-{:03}", i)))
        .collect();

    let sealed_tokens: Vec<_> = payloads.iter().map(|p| crypto.seal(p).unwrap()).collect();

    let mut group = c.benchmark_group("concurrent_token_ops");

    // Batch unseal
    group.bench_function("batch_unseal_100", |b| {
        b.iter(|| {
            for token in &sealed_tokens {
                black_box(crypto.unseal(black_box(token)).unwrap());
            }
        })
    });

    // Round-robin unseal (simulating different clients)
    group.bench_function("round_robin_unseal", |b| {
        let mut counter = 0usize;
        b.iter(|| {
            let token = &sealed_tokens[counter % sealed_tokens.len()];
            counter += 1;
            black_box(crypto.unseal(black_box(token)).unwrap())
        })
    });

    group.finish();
}

/// Benchmarks the SigV4 signing pipeline.
fn bench_sigv4_pipeline(c: &mut Criterion) {
    let crypto = create_test_crypto();

    // Create a SigV4 payload
    let sigv4_config = Sigv4Config::new("AKIAIOSFODNN7EXAMPLE");
    let payload = TokenPayload::builder(
        SecretString::from("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        ProcessorConfig::Sigv4(sigv4_config.clone()),
    )
    .allowed_host("s3.amazonaws.com")
    .build();

    let sealed = crypto.seal(&payload).unwrap();
    let processor = create_processor(&ProcessorConfig::Sigv4(sigv4_config));

    let mut group = c.benchmark_group("sigv4_pipeline");

    // Full pipeline: unseal + process
    group.bench_function("full_pipeline", |b| {
        b.iter(|| {
            let payload = crypto.unseal(black_box(&sealed)).unwrap();
            let request = Request::builder()
                .method("GET")
                .uri("https://examplebucket.s3.amazonaws.com/test.txt")
                .header("host", "examplebucket.s3.amazonaws.com")
                .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=abc")
                .header("x-amz-date", "20130524T000000Z")
                .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                .body(())
                .unwrap();
            black_box(processor.process(black_box(request), black_box(&payload)))
        })
    });

    // Pre-unsealed token (just processing)
    let unsealed_payload = crypto.unseal(&sealed).unwrap();
    group.bench_function("processing_only", |b| {
        b.iter(|| {
            let request = Request::builder()
                .method("GET")
                .uri("https://examplebucket.s3.amazonaws.com/test.txt")
                .header("host", "examplebucket.s3.amazonaws.com")
                .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=abc")
                .header("x-amz-date", "20130524T000000Z")
                .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                .body(())
                .unwrap();
            black_box(processor.process(black_box(request), black_box(&unsealed_payload)))
        })
    });

    group.finish();
}

/// Benchmarks network protection (SSRF prevention) as part of the request pipeline.
fn bench_network_protection_pipeline(c: &mut Criterion) {
    let filter = IpFilter::new(&NetworkProtectionConfig::default()).unwrap();

    // Simulate DNS resolution results
    let public_ips: Vec<IpAddr> = vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()];
    let private_ips: Vec<IpAddr> =
        vec!["10.0.0.1".parse().unwrap(), "192.168.1.1".parse().unwrap()];

    let mut group = c.benchmark_group("network_protection_pipeline");

    // Validate a batch of public IPs (success case)
    group.bench_function("validate_public_batch", |b| {
        b.iter(|| {
            for ip in &public_ips {
                black_box(filter.validate_ip(black_box(ip))).unwrap();
            }
        })
    });

    // Validate a batch with mixed IPs (should catch private)
    group.bench_function("validate_mixed_batch", |b| {
        let mixed: Vec<IpAddr> = public_ips
            .iter()
            .chain(private_ips.iter())
            .copied()
            .collect();
        b.iter(|| {
            for ip in &mixed {
                let _ = black_box(filter.validate_ip(black_box(ip)));
            }
        })
    });

    group.finish();
}

/// Benchmarks full request cycle with network protection.
fn bench_full_cycle_with_network(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let crypto = create_test_crypto();
    let secret = "sk_live_abcdef123456789";
    let payload = create_test_payload_with_secret(secret);
    let sealed = crypto.seal(&payload).unwrap();

    let host_config = HostValidationConfig::new().allow_host("api.example.com");
    let inject_config = InjectConfig::bearer("Authorization");
    let ip_filter = IpFilter::new(&NetworkProtectionConfig::default()).unwrap();
    let patterns = vec![secret.as_bytes().to_vec()];

    let rate_config = RateLimitConfig {
        max_requests: 10000,
        period: Duration::from_secs(60),
        burst: 1000,
    };
    let rate_limiter = RateLimiter::new(rate_config);

    let response_body = generate_random_bytes(4096);
    let target_ip: IpAddr = "8.8.8.8".parse().unwrap();

    c.bench_function("full_cycle_with_network_4kb", |b| {
        b.iter(|| {
            rt.block_on(async {
                // 1. Rate limit check
                rate_limiter.check(black_box("client-ip")).await;

                // 2. Unseal token
                let payload = crypto.unseal(black_box(&sealed)).unwrap();

                // 3. Validate host
                host_config.validate(black_box("api.example.com")).unwrap();

                // 4. Validate IP (SSRF prevention)
                ip_filter.validate_ip(black_box(&target_ip)).unwrap();

                // 5. Format header (simulates injection)
                let _header = inject_config.format_value(payload.expose_secret());

                // 6. Scan response body
                let body = http_body_util::Full::new(Bytes::from(response_body.clone()));
                let scanning = ScanningBody::new(body, patterns.clone());
                black_box(scanning.collect().await)
            })
        })
    });
}

/// Benchmarks processor overhead comparison in a realistic scenario.
fn bench_processor_overhead_comparison(c: &mut Criterion) {
    let crypto = create_test_crypto();

    // Inject processor
    let inject_payload = create_test_payload_with_secret("sk_live_abcdef123456789");
    let inject_sealed = crypto.seal(&inject_payload).unwrap();
    let inject_config = InjectConfig::bearer("Authorization");

    // SigV4 processor
    let sigv4_config = Sigv4Config::new("AKIAIOSFODNN7EXAMPLE");
    let sigv4_payload = TokenPayload::builder(
        SecretString::from("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        ProcessorConfig::Sigv4(sigv4_config.clone()),
    )
    .allowed_host("s3.amazonaws.com")
    .build();
    let sigv4_sealed = crypto.seal(&sigv4_payload).unwrap();
    let sigv4_processor = create_processor(&ProcessorConfig::Sigv4(sigv4_config));

    let mut group = c.benchmark_group("processor_overhead");

    // Just the unseal (baseline)
    group.bench_function("baseline_unseal", |b| {
        b.iter(|| {
            let _ = crypto.unseal(black_box(&inject_sealed)).unwrap();
        })
    });

    // Unseal + inject (simple)
    group.bench_function("inject_total", |b| {
        b.iter(|| {
            let payload = crypto.unseal(black_box(&inject_sealed)).unwrap();
            let _header = inject_config.format_value(payload.expose_secret());
        })
    });

    // Unseal + SigV4 (complex)
    group.bench_function("sigv4_total", |b| {
        b.iter(|| {
            let payload = crypto.unseal(black_box(&sigv4_sealed)).unwrap();
            let request = Request::builder()
                .method("GET")
                .uri("https://s3.amazonaws.com/bucket/key")
                .header("host", "s3.amazonaws.com")
                .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")
                .header("x-amz-date", "20130524T000000Z")
                .body(())
                .unwrap();
            let _ = black_box(sigv4_processor.process(black_box(request), black_box(&payload)));
        })
    });

    group.finish();
}

criterion_group!(
    throughput_benches,
    bench_injection_pipeline,
    bench_hmac_pipeline,
    bench_response_pipeline,
    bench_full_request_cycle,
    bench_rate_limit_throughput,
    bench_streaming_scan_throughput,
    bench_overlap_buffer_large_stream,
    bench_concurrent_token_operations,
    bench_sigv4_pipeline,
    bench_network_protection_pipeline,
    bench_full_cycle_with_network,
    bench_processor_overhead_comparison,
);

criterion_main!(throughput_benches);
