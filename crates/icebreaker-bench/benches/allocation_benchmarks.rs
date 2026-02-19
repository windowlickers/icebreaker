//! Allocation-counting benchmarks using dhat.
//!
//! These benchmarks use dhat's global allocator to count heap allocations
//! per operation, helping identify arena allocation candidates.
//!
//! Run with: cargo bench -p icebreaker-bench --bench allocation_benchmarks

use icebreaker_bench::{
    create_constrained_payload, create_test_crypto, create_test_payload_with_secret,
};
use icebreaker_common::{
    HmacConfig, InjectConfig, MultiProcessorConfig, ProcessorConfig, Sigv4Config,
};
use icebreaker_proxy::{create_processor, generate_scan_patterns};
use secrecy::SecretString;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Runs a closure under dhat profiling and prints allocation stats.
fn profile<F: FnOnce()>(name: &str, f: F) {
    // Take a snapshot before
    let before = dhat::HeapStats::get();

    f();

    // Take a snapshot after
    let after = dhat::HeapStats::get();

    let allocs = after.total_blocks - before.total_blocks;
    let bytes = after.total_bytes - before.total_bytes;

    println!("  {name}:");
    println!("    allocations: {allocs}");
    println!("    bytes allocated: {bytes}");
}

/// Profiles scan pattern generation for various secret types.
fn profile_scan_pattern_generation() {
    println!("\n=== Scan Pattern Generation ===");

    profile("short_5char (below threshold)", || {
        let _patterns = generate_scan_patterns("abc12");
    });

    profile("api_key_22char (alphanumeric)", || {
        let _patterns = generate_scan_patterns("sk_live_abcdef12345678");
    });

    profile("special_chars (url+html encoding)", || {
        let _patterns = generate_scan_patterns("api-key=value&token<>\"test'");
    });

    let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
               eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4g\
               RG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.\
               POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0Ei\
               XLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2\
               B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7Lz\
               Yp1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3p";
    profile("jwt_300char (large secret)", || {
        let _patterns = generate_scan_patterns(jwt);
    });
}

/// Profiles token unseal (deserialization allocations).
fn profile_token_unseal() {
    println!("\n=== Token Unseal ===");

    let crypto = create_test_crypto();
    let payload = create_test_payload_with_secret("sk_live_abcdef123456789");
    let sealed = crypto.seal(&payload).unwrap();

    profile("unseal_simple_inject", || {
        let _payload = crypto.unseal(&sealed).unwrap();
    });

    // With constrained payload (more fields to deserialize)
    let constrained = create_constrained_payload("sk_live_abcdef123456789");
    let sealed_constrained = crypto.seal(&constrained).unwrap();

    profile("unseal_constrained", || {
        let _payload = crypto.unseal(&sealed_constrained).unwrap();
    });
}

/// Profiles the full validation pipeline.
fn profile_full_validation_pipeline() {
    println!("\n=== Full Validation Pipeline ===");

    let crypto = create_test_crypto();
    let payload = create_constrained_payload("sk_live_abcdef123456789");
    let sealed = crypto.seal(&payload).unwrap();

    profile(
        "unseal + validate_host + validate_method + validate_path",
        || {
            let payload = crypto.unseal(&sealed).unwrap();
            let _host = payload.validate_host("api.example.com");
            let _method = payload.validate_method("GET");
            let _path = payload.validate_path("/api/v1/users");
        },
    );

    profile("validate_path with regex (pattern only)", || {
        let payload = crypto.unseal(&sealed).unwrap();
        // Path not in exact list, falls through to regex
        let _path = payload.validate_path("/api/v2/widgets");
    });
}

/// Profiles SigV4 processor allocations.
fn profile_sigv4_processing() {
    println!("\n=== SigV4 Processing ===");

    let sigv4_config = ProcessorConfig::Sigv4(Sigv4Config::new("AKIAIOSFODNN7EXAMPLE"));
    let processor = create_processor(&sigv4_config);

    let payload = icebreaker_common::TokenPayload::builder(
        SecretString::from("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        sigv4_config,
    )
    .allowed_host("s3.amazonaws.com")
    .build();

    profile("sigv4_s3_get", || {
        let request = http::Request::builder()
            .method("GET")
            .uri("https://examplebucket.s3.amazonaws.com/test.txt")
            .header("host", "examplebucket.s3.amazonaws.com")
            .header(
                "authorization",
                "AWS4-HMAC-SHA256 \
                 Credential=AKIAIOSFODNN7EXAMPLE/20130524/\
                 us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;\
                 x-amz-date, Signature=abc",
            )
            .header("x-amz-date", "20130524T000000Z")
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .body(())
            .unwrap();
        let _processed = processor.process(request, &payload);
    });
}

/// Profiles Multi processor dispatch allocations.
fn profile_multi_processor_dispatch() {
    println!("\n=== Multi Processor Dispatch ===");

    let multi_config = ProcessorConfig::Multi(MultiProcessorConfig {
        processors: vec![
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            ProcessorConfig::Inject(InjectConfig::raw("X-Api-Key")),
            ProcessorConfig::InjectHmac(HmacConfig::default()),
        ],
    });
    let processor = create_processor(&multi_config);

    let payload = icebreaker_common::TokenPayload::builder(
        SecretString::from("my-secret-key-for-testing-32b!"),
        multi_config,
    )
    .allowed_host("api.example.com")
    .build();

    profile("multi_3_processors", || {
        let request = http::Request::builder()
            .method("POST")
            .uri("https://api.example.com/v1/webhook")
            .header("Host", "api.example.com")
            .header("Content-Type", "application/json")
            .body(())
            .unwrap();
        let _processed = processor.process(request, &payload);
    });
}

/// Profiles the complete request cycle.
fn profile_complete_request_cycle() {
    println!("\n=== Complete Request Cycle ===");

    let crypto = create_test_crypto();
    let secret = "sk_live_abcdef123456789";
    let payload = create_constrained_payload(secret);
    let sealed = crypto.seal(&payload).unwrap();

    profile(
        "unseal -> validate -> process -> generate_scan_patterns",
        || {
            let payload = crypto.unseal(&sealed).unwrap();
            let _host = payload.validate_host("api.example.com");
            let _method = payload.validate_method("GET");
            let _path = payload.validate_path("/api/v1/users");

            let processor = create_processor(&payload.processor);
            let request = http::Request::builder()
                .uri("https://api.example.com/api/v1/users")
                .body(())
                .unwrap();
            let _processed = processor.process(request, &payload);

            let _patterns = generate_scan_patterns(payload.expose_secret());
        },
    );
}

fn main() {
    let _profiler = dhat::Profiler::new_heap();

    println!("Icebreaker Allocation Profiling");
    println!("===============================");

    profile_scan_pattern_generation();
    profile_token_unseal();
    profile_full_validation_pipeline();
    profile_sigv4_processing();
    profile_multi_processor_dispatch();
    profile_complete_request_cycle();

    println!("\n===============================");
    println!("Profiling complete.");
}
