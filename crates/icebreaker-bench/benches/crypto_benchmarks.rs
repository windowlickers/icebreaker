//! Benchmarks for cryptographic operations in icebreaker-crypto.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use icebreaker_bench::{create_test_crypto, create_test_payload, PAYLOAD_SIZES};
use icebreaker_common::HmacAlgorithm;
use icebreaker_crypto::{
    compute_signature, derive_keypair, verify_signature, CanonicalRequestBuilder, Keypair,
    MasterKeyManager, RequestSigner,
};

/// Benchmarks keypair generation.
fn bench_keypair_generation(c: &mut Criterion) {
    c.bench_function("keypair_generate", |b| {
        b.iter(|| black_box(Keypair::generate()))
    });
}

/// Benchmarks key derivation from master key.
fn bench_key_derivation(c: &mut Criterion) {
    let master_key = b"master-key-for-benchmark-32bytes";

    c.bench_function("hkdf_derive_keypair", |b| {
        b.iter(|| black_box(derive_keypair(black_box(master_key), "bench-key", 1).unwrap()))
    });
}

/// Benchmarks master key manager keypair derivation.
fn bench_master_key_manager(c: &mut Criterion) {
    let manager = MasterKeyManager::new("bench-key", b"master-key-for-benchmark-32bytes".to_vec());

    c.bench_function("master_key_manager_derive", |b| {
        b.iter(|| black_box(manager.derive_keypair(black_box(1)).unwrap()))
    });
}

/// Benchmarks token sealing with various payload sizes.
fn bench_token_seal(c: &mut Criterion) {
    let crypto = create_test_crypto();

    let mut group = c.benchmark_group("token_seal");
    for size in PAYLOAD_SIZES {
        let payload = create_test_payload(*size);
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| black_box(crypto.seal(black_box(&payload)).unwrap()))
        });
    }
    group.finish();
}

/// Benchmarks token unsealing with various payload sizes.
fn bench_token_unseal(c: &mut Criterion) {
    let crypto = create_test_crypto();

    let mut group = c.benchmark_group("token_unseal");
    for size in PAYLOAD_SIZES {
        let payload = create_test_payload(*size);
        let sealed = crypto.seal(&payload).unwrap();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| black_box(crypto.unseal(black_box(&sealed)).unwrap()))
        });
    }
    group.finish();
}

/// Benchmarks HMAC signature computation for different algorithms.
fn bench_hmac_compute(c: &mut Criterion) {
    let key = b"secret-hmac-key-for-benchmarks!";
    let message = b"The quick brown fox jumps over the lazy dog";

    let mut group = c.benchmark_group("hmac_compute");

    group.bench_function("sha256", |b| {
        b.iter(|| {
            black_box(compute_signature(
                black_box(key),
                black_box(message),
                HmacAlgorithm::Sha256,
            ))
        })
    });

    group.bench_function("sha512", |b| {
        b.iter(|| {
            black_box(compute_signature(
                black_box(key),
                black_box(message),
                HmacAlgorithm::Sha512,
            ))
        })
    });

    group.finish();
}

/// Benchmarks HMAC signature verification.
fn bench_hmac_verify(c: &mut Criterion) {
    let key = b"secret-hmac-key-for-benchmarks!";
    let message = b"The quick brown fox jumps over the lazy dog";
    let signature = compute_signature(key, message, HmacAlgorithm::Sha256);

    let mut group = c.benchmark_group("hmac_verify");

    group.bench_function("sha256_valid", |b| {
        b.iter(|| {
            black_box(verify_signature(
                black_box(key),
                black_box(message),
                black_box(&signature),
                HmacAlgorithm::Sha256,
            ))
        })
    });

    // Benchmark with invalid signature (timing should be constant)
    let mut invalid_sig = signature.clone();
    invalid_sig[0] ^= 0xFF;
    group.bench_function("sha256_invalid", |b| {
        b.iter(|| {
            black_box(verify_signature(
                black_box(key),
                black_box(message),
                black_box(&invalid_sig),
                HmacAlgorithm::Sha256,
            ))
        })
    });

    group.finish();
}

/// Benchmarks RequestSigner operations.
fn bench_request_signer(c: &mut Criterion) {
    let signer = RequestSigner::new(b"secret-key", HmacAlgorithm::Sha256);
    let message = b"POST\n/api/data\n\nhost:api.example.com\n";

    let mut group = c.benchmark_group("request_signer");

    group.bench_function("sign", |b| {
        b.iter(|| black_box(signer.sign(black_box(message))))
    });

    group.bench_function("sign_hex", |b| {
        b.iter(|| black_box(signer.sign_hex(black_box(message))))
    });

    group.bench_function("sign_base64", |b| {
        b.iter(|| black_box(signer.sign_base64(black_box(message))))
    });

    group.finish();
}

/// Benchmarks canonical request building.
fn bench_canonical_request(c: &mut Criterion) {
    let body = b"{\"key\":\"value\",\"data\":[1,2,3,4,5]}";

    c.bench_function("canonical_request_build", |b| {
        b.iter(|| {
            black_box(
                CanonicalRequestBuilder::new("POST", "/api/v1/data")
                    .query("page=1&limit=100")
                    .header("Host", "api.example.com")
                    .header("Content-Type", "application/json")
                    .header("X-Request-ID", "abc123")
                    .body(black_box(body))
                    .build(),
            )
        })
    });
}

/// Benchmarks HMAC with varying message sizes.
fn bench_hmac_message_sizes(c: &mut Criterion) {
    let key = b"secret-hmac-key-for-benchmarks!";
    let message_sizes = [64, 256, 1024, 4096, 16384];

    let mut group = c.benchmark_group("hmac_message_size");
    for size in message_sizes {
        let message: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &message, |b, msg| {
            b.iter(|| {
                black_box(compute_signature(
                    black_box(key),
                    black_box(msg),
                    HmacAlgorithm::Sha256,
                ))
            })
        });
    }
    group.finish();
}

criterion_group!(
    crypto_benches,
    bench_keypair_generation,
    bench_key_derivation,
    bench_master_key_manager,
    bench_token_seal,
    bench_token_unseal,
    bench_hmac_compute,
    bench_hmac_verify,
    bench_request_signer,
    bench_canonical_request,
    bench_hmac_message_sizes,
);

criterion_main!(crypto_benches);
