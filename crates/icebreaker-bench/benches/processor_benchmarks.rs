//! Benchmarks for request processors in icebreaker-proxy.

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use http::Request;

use icebreaker_bench::create_test_crypto;
use icebreaker_common::{
    HmacConfig, InjectBodyConfig, InjectConfig, MultiProcessorConfig, OAuthConfig, OAuthMetadata,
    ProcessorConfig, Sigv4Config, TokenPayload,
};
use icebreaker_proxy::{
    create_processor, HmacProcessor, InjectBodyProcessor, InjectProcessor, RequestProcessor,
    Sigv4Processor,
};
use secrecy::SecretString;

/// Creates a test payload with the given secret and processor config.
fn create_payload(secret: &str, config: ProcessorConfig) -> TokenPayload {
    TokenPayload::builder(SecretString::from(secret), config)
        .allowed_host("api.example.com")
        .build()
}

// ============================================================================
// InjectProcessor Benchmarks
// ============================================================================

/// Benchmarks the InjectProcessor with different configurations.
fn bench_inject_processor(c: &mut Criterion) {
    let mut group = c.benchmark_group("inject_processor");

    // Bearer token injection
    let bearer_config = InjectConfig::bearer("Authorization");
    let bearer_processor = InjectProcessor::new(bearer_config.clone());
    let bearer_payload = create_payload(
        "sk_live_abcdef123456789",
        ProcessorConfig::Inject(bearer_config),
    );

    group.bench_function("bearer", |b| {
        b.iter(|| {
            let request = Request::builder()
                .uri("https://api.example.com/v1/charges")
                .body(())
                .unwrap();
            black_box(bearer_processor.process(black_box(request), black_box(&bearer_payload)))
        })
    });

    // Basic auth injection
    let basic_config = InjectConfig::basic("Authorization");
    let basic_processor = InjectProcessor::new(basic_config.clone());
    let basic_payload = create_payload(
        "dXNlcjpwYXNzd29yZA==",
        ProcessorConfig::Inject(basic_config),
    );

    group.bench_function("basic", |b| {
        b.iter(|| {
            let request = Request::builder()
                .uri("https://api.example.com/v1/data")
                .body(())
                .unwrap();
            black_box(basic_processor.process(black_box(request), black_box(&basic_payload)))
        })
    });

    // Raw header injection
    let raw_config = InjectConfig::raw("X-Api-Key");
    let raw_processor = InjectProcessor::new(raw_config.clone());
    let raw_payload = create_payload("api-key-12345-abcdef", ProcessorConfig::Inject(raw_config));

    group.bench_function("raw", |b| {
        b.iter(|| {
            let request = Request::builder()
                .uri("https://api.example.com/v1/endpoint")
                .body(())
                .unwrap();
            black_box(raw_processor.process(black_box(request), black_box(&raw_payload)))
        })
    });

    group.finish();
}

/// Benchmarks the inject config format_value method.
fn bench_inject_format_value(c: &mut Criterion) {
    let mut group = c.benchmark_group("inject_format_value");

    // Short secret
    let bearer_config = InjectConfig::bearer("Authorization");
    let short_secret = "sk_live_123";
    group.bench_function("bearer_short", |b| {
        b.iter(|| black_box(bearer_config.format_value(black_box(short_secret))))
    });

    // Long secret (like a JWT)
    let long_secret = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA";
    group.bench_function("bearer_long_jwt", |b| {
        b.iter(|| black_box(bearer_config.format_value(black_box(long_secret))))
    });

    // Raw (no prefix/suffix)
    let raw_config = InjectConfig::raw("X-Api-Key");
    group.bench_function("raw", |b| {
        b.iter(|| black_box(raw_config.format_value(black_box(short_secret))))
    });

    group.finish();
}

// ============================================================================
// InjectBodyProcessor Benchmarks
// ============================================================================

/// Benchmarks the InjectBodyProcessor placeholder replacement.
fn bench_inject_body_placeholder(c: &mut Criterion) {
    let config = InjectBodyConfig::default();
    let processor = InjectBodyProcessor::new(config);

    let body_sizes = [64, 256, 1024, 4096];
    let secret = "sk_live_secret_key_12345";

    let mut group = c.benchmark_group("inject_body_placeholder");

    for size in body_sizes {
        // Create body with placeholder in middle
        let mut body = String::with_capacity(size + 20);
        let padding_size = (size - 18) / 2; // 18 = "{{ACCESS_TOKEN}}".len() + 2 for quotes
        body.push_str(&"x".repeat(padding_size));
        body.push_str(r#"{"token":"{{ACCESS_TOKEN}}"}"#);
        body.push_str(&"x".repeat(padding_size));
        let body_bytes = body.into_bytes();

        group.throughput(Throughput::Bytes(body_bytes.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &body_bytes, |b, body| {
            b.iter(|| black_box(processor.replace_placeholder(black_box(body), black_box(secret))))
        });
    }

    group.finish();
}

/// Benchmarks the full process_body async method.
fn bench_process_body_async(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let processor = InjectBodyProcessor::new(InjectBodyConfig::default());
    let secret = "sk_live_secret_key_12345";

    let body_sizes = [256, 1024, 4096, 16384];

    let mut group = c.benchmark_group("process_body_async");

    for size in body_sizes {
        let mut body_str = String::with_capacity(size);
        body_str.push_str(r#"{"data":"#);
        body_str.push_str(&"x".repeat(size - 50));
        body_str.push_str(r#","token":"{{ACCESS_TOKEN}}"}"#);

        group.throughput(Throughput::Bytes(body_str.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &body_str, |b, body| {
            b.iter(|| {
                rt.block_on(async {
                    let req_body = http_body_util::Full::new(Bytes::from(body.clone()));
                    let request = Request::builder()
                        .uri("https://api.example.com/v1/data")
                        .body(req_body)
                        .unwrap();
                    black_box(
                        processor
                            .process_body(black_box(request), black_box(secret))
                            .await,
                    )
                })
            })
        });
    }

    group.finish();
}

// ============================================================================
// HmacProcessor Benchmarks
// ============================================================================

/// Benchmarks the HmacProcessor.
fn bench_hmac_processor(c: &mut Criterion) {
    let config = HmacConfig::default();
    let processor = HmacProcessor::new(config.clone());
    let payload = create_payload(
        "hmac-secret-key-for-signing-32b!",
        ProcessorConfig::InjectHmac(config),
    );

    let mut group = c.benchmark_group("hmac_processor");

    // Simple request
    group.bench_function("simple_request", |b| {
        b.iter(|| {
            let request = Request::builder()
                .method("POST")
                .uri("https://api.example.com/v1/webhook")
                .header("Host", "api.example.com")
                .header("Content-Type", "application/json")
                .body(())
                .unwrap();
            black_box(processor.process(black_box(request), black_box(&payload)))
        })
    });

    // Request with many headers
    group.bench_function("many_headers", |b| {
        b.iter(|| {
            let request = Request::builder()
                .method("POST")
                .uri("https://api.example.com/v1/webhook")
                .header("Host", "api.example.com")
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("Accept-Encoding", "gzip, deflate")
                .header("User-Agent", "icebreaker/1.0")
                .header("X-Request-Id", "req-12345-abcdef")
                .header("X-Correlation-Id", "corr-67890-ghijk")
                .body(())
                .unwrap();
            black_box(processor.process(black_box(request), black_box(&payload)))
        })
    });

    group.finish();
}

// ============================================================================
// Sigv4Processor Benchmarks
// ============================================================================

/// Benchmarks the Sigv4Processor.
fn bench_sigv4_processor(c: &mut Criterion) {
    let config = Sigv4Config::new("AKIAIOSFODNN7EXAMPLE");
    let processor = Sigv4Processor::new(config.clone());
    let payload = create_payload(
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ProcessorConfig::Sigv4(config),
    );

    let mut group = c.benchmark_group("sigv4_processor");

    // S3 GET request
    group.bench_function("s3_get", |b| {
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
            black_box(processor.process(black_box(request), black_box(&payload)))
        })
    });

    // S3 PUT request (with body hash)
    let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    group.bench_function("s3_put", |b| {
        b.iter(|| {
            let request = Request::builder()
                .method("PUT")
                .uri("https://examplebucket.s3.amazonaws.com/test.txt")
                .header("host", "examplebucket.s3.amazonaws.com")
                .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=abc")
                .header("x-amz-date", "20130524T000000Z")
                .header("x-amz-content-sha256", empty_hash)
                .body(())
                .unwrap();
            black_box(processor.process(black_box(request), black_box(&payload)))
        })
    });

    // DynamoDB request
    group.bench_function("dynamodb", |b| {
        b.iter(|| {
            let request = Request::builder()
                .method("POST")
                .uri("https://dynamodb.us-east-1.amazonaws.com/")
                .header("host", "dynamodb.us-east-1.amazonaws.com")
                .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/dynamodb/aws4_request, SignedHeaders=host;x-amz-date;x-amz-target, Signature=abc")
                .header("x-amz-date", "20130524T000000Z")
                .header("x-amz-target", "DynamoDB_20120810.GetItem")
                .body(())
                .unwrap();
            black_box(processor.process(black_box(request), black_box(&payload)))
        })
    });

    // Lambda request
    group.bench_function("lambda", |b| {
        b.iter(|| {
            let request = Request::builder()
                .method("POST")
                .uri("https://lambda.us-west-2.amazonaws.com/2015-03-31/functions/my-function/invocations")
                .header("host", "lambda.us-west-2.amazonaws.com")
                .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-west-2/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")
                .header("x-amz-date", "20130524T000000Z")
                .body(())
                .unwrap();
            black_box(processor.process(black_box(request), black_box(&payload)))
        })
    });

    group.finish();
}

// ============================================================================
// Processor Dispatch Benchmarks
// ============================================================================

/// Benchmarks the processor dispatch mechanism.
fn bench_processor_dispatch(c: &mut Criterion) {
    let inject_config = ProcessorConfig::Inject(InjectConfig::bearer("Authorization"));
    let sigv4_config = ProcessorConfig::Sigv4(Sigv4Config::new("AKIAIOSFODNN7EXAMPLE"));

    let inject_processor = create_processor(&inject_config);
    let sigv4_processor = create_processor(&sigv4_config);

    let inject_payload = create_payload("sk_live_token_12345", inject_config);
    let sigv4_payload = create_payload("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", sigv4_config);

    let mut group = c.benchmark_group("processor_dispatch");

    // Inject via dispatch
    group.bench_function("inject_dispatch", |b| {
        b.iter(|| {
            let request = Request::builder()
                .uri("https://api.example.com/v1/data")
                .body(())
                .unwrap();
            black_box(inject_processor.process(black_box(request), black_box(&inject_payload)))
        })
    });

    // Sigv4 via dispatch
    group.bench_function("sigv4_dispatch", |b| {
        b.iter(|| {
            let request = Request::builder()
                .uri("https://s3.amazonaws.com/bucket/key")
                .header("host", "s3.amazonaws.com")
                .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")
                .header("x-amz-date", "20130524T000000Z")
                .body(())
                .unwrap();
            black_box(sigv4_processor.process(black_box(request), black_box(&sigv4_payload)))
        })
    });

    group.finish();
}

/// Benchmarks create_processor function.
fn bench_create_processor(c: &mut Criterion) {
    let mut group = c.benchmark_group("create_processor");

    let inject_config = ProcessorConfig::Inject(InjectConfig::bearer("Authorization"));
    group.bench_function("inject", |b| {
        b.iter(|| black_box(create_processor(black_box(&inject_config))))
    });

    let hmac_config = ProcessorConfig::InjectHmac(HmacConfig::default());
    group.bench_function("hmac", |b| {
        b.iter(|| black_box(create_processor(black_box(&hmac_config))))
    });

    let inject_body_config = ProcessorConfig::InjectBody(InjectBodyConfig::default());
    group.bench_function("inject_body", |b| {
        b.iter(|| black_box(create_processor(black_box(&inject_body_config))))
    });

    let sigv4_config = ProcessorConfig::Sigv4(Sigv4Config::new("AKIAIOSFODNN7EXAMPLE"));
    group.bench_function("sigv4", |b| {
        b.iter(|| black_box(create_processor(black_box(&sigv4_config))))
    });

    group.finish();
}

// ============================================================================
// Full Pipeline Comparison
// ============================================================================

/// Benchmarks comparing all processor types in a realistic scenario.
fn bench_processor_comparison(c: &mut Criterion) {
    let crypto = create_test_crypto();

    // Create payloads and processors for each type
    let inject_config = ProcessorConfig::Inject(InjectConfig::bearer("Authorization"));
    let inject_payload = create_payload("sk_live_abcdef123456789", inject_config.clone());
    let inject_sealed = crypto.seal(&inject_payload).unwrap();
    let inject_processor = create_processor(&inject_config);

    let hmac_config = ProcessorConfig::InjectHmac(HmacConfig::default());
    let hmac_payload = create_payload("hmac-secret-key-32-bytes-long!!", hmac_config.clone());
    let hmac_sealed = crypto.seal(&hmac_payload).unwrap();
    let hmac_processor = create_processor(&hmac_config);

    let sigv4_config = ProcessorConfig::Sigv4(Sigv4Config::new("AKIAIOSFODNN7EXAMPLE"));
    let sigv4_payload = create_payload(
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        sigv4_config.clone(),
    );
    let sigv4_sealed = crypto.seal(&sigv4_payload).unwrap();
    let sigv4_processor = create_processor(&sigv4_config);

    let mut group = c.benchmark_group("processor_comparison");

    // Inject: unseal + process
    group.bench_function("inject_full", |b| {
        b.iter(|| {
            let payload = crypto.unseal(black_box(&inject_sealed)).unwrap();
            let request = Request::builder()
                .uri("https://api.example.com/v1/data")
                .body(())
                .unwrap();
            black_box(inject_processor.process(black_box(request), black_box(&payload)))
        })
    });

    // HMAC: unseal + process
    group.bench_function("hmac_full", |b| {
        b.iter(|| {
            let payload = crypto.unseal(black_box(&hmac_sealed)).unwrap();
            let request = Request::builder()
                .method("POST")
                .uri("https://api.example.com/v1/webhook")
                .header("Host", "api.example.com")
                .header("Content-Type", "application/json")
                .body(())
                .unwrap();
            black_box(hmac_processor.process(black_box(request), black_box(&payload)))
        })
    });

    // SigV4: unseal + process
    group.bench_function("sigv4_full", |b| {
        b.iter(|| {
            let payload = crypto.unseal(black_box(&sigv4_sealed)).unwrap();
            let request = Request::builder()
                .uri("https://s3.amazonaws.com/bucket/key")
                .header("host", "s3.amazonaws.com")
                .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")
                .header("x-amz-date", "20130524T000000Z")
                .body(())
                .unwrap();
            black_box(sigv4_processor.process(black_box(request), black_box(&payload)))
        })
    });

    group.finish();
}

// ============================================================================
// Multi Processor Benchmarks
// ============================================================================

/// Benchmarks multi-processor chaining with varying processor counts.
fn bench_multi_processor(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_processor");

    // 2 header processors (Inject + Inject)
    let multi_2_config = ProcessorConfig::Multi(MultiProcessorConfig {
        processors: vec![
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            ProcessorConfig::Inject(InjectConfig::raw("X-Api-Key")),
        ],
    });
    let multi_2_processor = create_processor(&multi_2_config);
    let multi_2_payload = create_payload("my-secret-api-key", multi_2_config);

    group.bench_function("2_header_processors", |b| {
        b.iter(|| {
            let request = Request::builder()
                .uri("https://api.example.com/v1/data")
                .body(())
                .unwrap();
            black_box(multi_2_processor.process(black_box(request), black_box(&multi_2_payload)))
        })
    });

    // 3 header processors (Inject + Inject + HMAC)
    let multi_3_config = ProcessorConfig::Multi(MultiProcessorConfig {
        processors: vec![
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            ProcessorConfig::Inject(InjectConfig::raw("X-Api-Key")),
            ProcessorConfig::InjectHmac(HmacConfig::default()),
        ],
    });
    let multi_3_processor = create_processor(&multi_3_config);
    let multi_3_payload = create_payload("hmac-secret-key-for-signing-32b!", multi_3_config);

    group.bench_function("3_header_processors", |b| {
        b.iter(|| {
            let request = Request::builder()
                .method("POST")
                .uri("https://api.example.com/v1/webhook")
                .header("Host", "api.example.com")
                .header("Content-Type", "application/json")
                .body(())
                .unwrap();
            black_box(multi_3_processor.process(black_box(request), black_box(&multi_3_payload)))
        })
    });

    // create_processor for Multi config (measures Vec allocation cost)
    let factory_config = ProcessorConfig::Multi(MultiProcessorConfig {
        processors: vec![
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            ProcessorConfig::Inject(InjectConfig::raw("X-Api-Key")),
            ProcessorConfig::InjectHmac(HmacConfig::default()),
        ],
    });

    group.bench_function("create_multi_3", |b| {
        b.iter(|| black_box(create_processor(black_box(&factory_config))))
    });

    group.finish();
}

// ============================================================================
// OAuth Processor Benchmarks
// ============================================================================

/// Benchmarks the OAuthProcessor with various configurations.
fn bench_oauth_processor(c: &mut Criterion) {
    use icebreaker_proxy::{OAuthProcessor, RequestProcessor};

    let config = OAuthConfig::default();
    let processor = OAuthProcessor::new(config.clone());

    let mut group = c.benchmark_group("oauth_processor");

    // Simple injection (no OAuth metadata)
    let simple_payload = create_payload(
        "oauth-access-token-12345",
        ProcessorConfig::OAuth(config.clone()),
    );

    group.bench_function("simple_no_metadata", |b| {
        b.iter(|| {
            let request = Request::builder()
                .uri("https://api.example.com/v1/data")
                .body(())
                .unwrap();
            black_box(processor.process(black_box(request), black_box(&simple_payload)))
        })
    });

    // With expiry check (non-expired token with OAuthMetadata)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let oauth_metadata = OAuthMetadata::new("google").with_expires_at(now + 60);

    let payload_with_metadata = TokenPayload::builder(
        SecretString::from("valid-access-token-12345"),
        ProcessorConfig::OAuth(config),
    )
    .oauth(oauth_metadata)
    .allowed_host("api.example.com")
    .build();

    group.bench_function("with_expiry_check", |b| {
        b.iter(|| {
            let request = Request::builder()
                .uri("https://api.example.com/v1/data")
                .body(())
                .unwrap();
            black_box(processor.process(black_box(request), black_box(&payload_with_metadata)))
        })
    });

    group.finish();
}

criterion_group!(
    processor_benches,
    bench_inject_processor,
    bench_inject_format_value,
    bench_inject_body_placeholder,
    bench_process_body_async,
    bench_hmac_processor,
    bench_sigv4_processor,
    bench_processor_dispatch,
    bench_create_processor,
    bench_processor_comparison,
    bench_multi_processor,
    bench_oauth_processor,
);

criterion_main!(processor_benches);
