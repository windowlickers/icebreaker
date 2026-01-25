//! Benchmarks for network protection (SSRF prevention) in icebreaker-proxy.

use std::net::IpAddr;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use icebreaker_common::NetworkProtectionConfig;
use icebreaker_proxy::IpFilter;

/// Benchmarks IP filter creation with default config.
fn bench_ip_filter_creation(c: &mut Criterion) {
    let config = NetworkProtectionConfig::default();

    c.bench_function("ip_filter_create_default", |b| {
        b.iter(|| black_box(IpFilter::new(black_box(&config)).unwrap()))
    });
}

/// Benchmarks IP filter creation with custom blocked CIDRs.
fn bench_ip_filter_creation_custom(c: &mut Criterion) {
    let config = NetworkProtectionConfig {
        blocked_cidrs: vec![
            "203.0.113.0/24".to_string(),
            "198.51.100.0/24".to_string(),
            "192.0.2.0/24".to_string(),
        ],
        allowed_cidrs: vec!["10.0.0.0/24".to_string()],
        blocked_hostnames: vec!["internal.example.com".to_string()],
        ..Default::default()
    };

    c.bench_function("ip_filter_create_custom", |b| {
        b.iter(|| black_box(IpFilter::new(black_box(&config)).unwrap()))
    });
}

/// Benchmarks IP validation for public addresses (should pass quickly).
fn bench_ip_filter_public_v4(c: &mut Criterion) {
    let filter = IpFilter::new(&NetworkProtectionConfig::default()).unwrap();

    let public_ips: Vec<IpAddr> = vec![
        "8.8.8.8".parse().unwrap(),
        "1.1.1.1".parse().unwrap(),
        "208.67.222.222".parse().unwrap(),
        "9.9.9.9".parse().unwrap(),
    ];

    let mut group = c.benchmark_group("ip_filter_public_v4");

    for ip in public_ips {
        group.bench_with_input(BenchmarkId::from_parameter(&ip), &ip, |b, ip| {
            b.iter(|| black_box(filter.is_allowed(black_box(ip))))
        });
    }

    group.finish();
}

/// Benchmarks IP validation for blocked addresses.
fn bench_ip_filter_blocked(c: &mut Criterion) {
    let filter = IpFilter::new(&NetworkProtectionConfig::default()).unwrap();

    let mut group = c.benchmark_group("ip_filter_blocked");

    // Loopback
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    group.bench_function("loopback", |b| {
        b.iter(|| black_box(filter.check_ip(black_box(&loopback))))
    });

    // Private (10.x)
    let private_10: IpAddr = "10.0.0.1".parse().unwrap();
    group.bench_function("private_10", |b| {
        b.iter(|| black_box(filter.check_ip(black_box(&private_10))))
    });

    // Private (172.16.x)
    let private_172: IpAddr = "172.16.0.1".parse().unwrap();
    group.bench_function("private_172", |b| {
        b.iter(|| black_box(filter.check_ip(black_box(&private_172))))
    });

    // Private (192.168.x)
    let private_192: IpAddr = "192.168.1.1".parse().unwrap();
    group.bench_function("private_192", |b| {
        b.iter(|| black_box(filter.check_ip(black_box(&private_192))))
    });

    // Link-local
    let link_local: IpAddr = "169.254.1.1".parse().unwrap();
    group.bench_function("link_local", |b| {
        b.iter(|| black_box(filter.check_ip(black_box(&link_local))))
    });

    // CGN
    let cgn: IpAddr = "100.64.0.1".parse().unwrap();
    group.bench_function("cgn", |b| {
        b.iter(|| black_box(filter.check_ip(black_box(&cgn))))
    });

    // Multicast
    let multicast: IpAddr = "224.0.0.1".parse().unwrap();
    group.bench_function("multicast", |b| {
        b.iter(|| black_box(filter.check_ip(black_box(&multicast))))
    });

    group.finish();
}

/// Benchmarks IPv6 validation.
fn bench_ip_filter_v6(c: &mut Criterion) {
    let filter = IpFilter::new(&NetworkProtectionConfig::default()).unwrap();

    let mut group = c.benchmark_group("ip_filter_v6");

    // Public IPv6
    let public: IpAddr = "2001:4860:4860::8888".parse().unwrap();
    group.bench_function("public", |b| {
        b.iter(|| black_box(filter.is_allowed(black_box(&public))))
    });

    // Loopback IPv6
    let loopback: IpAddr = "::1".parse().unwrap();
    group.bench_function("loopback", |b| {
        b.iter(|| black_box(filter.check_ip(black_box(&loopback))))
    });

    // Private IPv6 (ULA)
    let private: IpAddr = "fc00::1".parse().unwrap();
    group.bench_function("private_ula", |b| {
        b.iter(|| black_box(filter.check_ip(black_box(&private))))
    });

    // Link-local IPv6
    let link_local: IpAddr = "fe80::1".parse().unwrap();
    group.bench_function("link_local", |b| {
        b.iter(|| black_box(filter.check_ip(black_box(&link_local))))
    });

    // Documentation
    let documentation: IpAddr = "2001:db8::1".parse().unwrap();
    group.bench_function("documentation", |b| {
        b.iter(|| black_box(filter.check_ip(black_box(&documentation))))
    });

    group.finish();
}

/// Benchmarks IP filter with custom blocked CIDRs.
fn bench_ip_filter_custom_cidrs(c: &mut Criterion) {
    // Create a filter with custom blocked CIDRs
    let config = NetworkProtectionConfig {
        blocked_cidrs: vec![
            "203.0.113.0/24".to_string(),
            "198.51.100.0/24".to_string(),
            "192.0.2.0/24".to_string(),
            "233.252.0.0/24".to_string(),
            "198.18.0.0/15".to_string(),
        ],
        ..Default::default()
    };
    let filter = IpFilter::new(&config).unwrap();

    let mut group = c.benchmark_group("ip_filter_custom_cidrs");

    // Address in first blocked CIDR
    let in_first: IpAddr = "203.0.113.50".parse().unwrap();
    group.bench_function("in_first_cidr", |b| {
        b.iter(|| black_box(filter.check_ip(black_box(&in_first))))
    });

    // Address in last blocked CIDR
    let in_last: IpAddr = "198.18.5.5".parse().unwrap();
    group.bench_function("in_last_cidr", |b| {
        b.iter(|| black_box(filter.check_ip(black_box(&in_last))))
    });

    // Address not in any blocked CIDR
    let not_blocked: IpAddr = "8.8.8.8".parse().unwrap();
    group.bench_function("not_blocked", |b| {
        b.iter(|| black_box(filter.check_ip(black_box(&not_blocked))))
    });

    group.finish();
}

/// Benchmarks IP filter with allowed CIDR overrides.
fn bench_ip_filter_allowed_overrides(c: &mut Criterion) {
    let config = NetworkProtectionConfig {
        block_private: true,
        allowed_cidrs: vec!["10.0.0.0/24".to_string(), "10.1.0.0/24".to_string()],
        ..Default::default()
    };
    let filter = IpFilter::new(&config).unwrap();

    let mut group = c.benchmark_group("ip_filter_allowed_overrides");

    // Address in allowed CIDR (overrides private block)
    let allowed: IpAddr = "10.0.0.50".parse().unwrap();
    group.bench_function("in_allowed_cidr", |b| {
        b.iter(|| black_box(filter.is_allowed(black_box(&allowed))))
    });

    // Address not in allowed CIDR (should be blocked as private)
    let blocked: IpAddr = "10.2.0.50".parse().unwrap();
    group.bench_function("not_in_allowed_cidr", |b| {
        b.iter(|| black_box(filter.is_allowed(black_box(&blocked))))
    });

    group.finish();
}

/// Benchmarks hostname blocking.
fn bench_ip_filter_hostname(c: &mut Criterion) {
    let config = NetworkProtectionConfig {
        blocked_hostnames: vec![
            "localhost".to_string(),
            "internal.example.com".to_string(),
            "secret.corp.internal".to_string(),
            "metadata.google.internal".to_string(),
            "169.254.169.254".to_string(),
        ],
        ..Default::default()
    };
    let filter = IpFilter::new(&config).unwrap();

    let mut group = c.benchmark_group("ip_filter_hostname");

    // First blocked hostname
    group.bench_function("blocked_first", |b| {
        b.iter(|| black_box(filter.is_hostname_blocked(black_box("localhost"))))
    });

    // Last blocked hostname
    group.bench_function("blocked_last", |b| {
        b.iter(|| black_box(filter.is_hostname_blocked(black_box("169.254.169.254"))))
    });

    // Not blocked hostname
    group.bench_function("not_blocked", |b| {
        b.iter(|| black_box(filter.is_hostname_blocked(black_box("api.example.com"))))
    });

    // Case-insensitive match
    group.bench_function("case_insensitive", |b| {
        b.iter(|| black_box(filter.is_hostname_blocked(black_box("LOCALHOST"))))
    });

    group.finish();
}

/// Benchmarks permissive filter (should be very fast).
fn bench_ip_filter_permissive(c: &mut Criterion) {
    let filter = IpFilter::permissive();

    let mut group = c.benchmark_group("ip_filter_permissive");

    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    group.bench_function("loopback", |b| {
        b.iter(|| black_box(filter.is_allowed(black_box(&loopback))))
    });

    let private: IpAddr = "10.0.0.1".parse().unwrap();
    group.bench_function("private", |b| {
        b.iter(|| black_box(filter.is_allowed(black_box(&private))))
    });

    group.finish();
}

/// Benchmarks full validate_ip flow (with Result return).
fn bench_ip_filter_validate(c: &mut Criterion) {
    let filter = IpFilter::new(&NetworkProtectionConfig::default()).unwrap();

    let mut group = c.benchmark_group("ip_filter_validate");

    // Should succeed
    let public: IpAddr = "8.8.8.8".parse().unwrap();
    group.bench_function("success", |b| {
        b.iter(|| black_box(filter.validate_ip(black_box(&public))))
    });

    // Should fail
    let private: IpAddr = "10.0.0.1".parse().unwrap();
    group.bench_function("failure", |b| {
        b.iter(|| black_box(filter.validate_ip(black_box(&private))))
    });

    group.finish();
}

/// Benchmarks batch IP validation (simulating DNS resolution check).
fn bench_ip_filter_batch(c: &mut Criterion) {
    let filter = IpFilter::new(&NetworkProtectionConfig::default()).unwrap();

    // Simulate multiple resolved IPs for a single hostname
    let ips: Vec<IpAddr> = vec![
        "8.8.8.8".parse().unwrap(),
        "8.8.4.4".parse().unwrap(),
        "2001:4860:4860::8888".parse().unwrap(),
        "2001:4860:4860::8844".parse().unwrap(),
    ];

    c.bench_function("ip_filter_batch_4_ips", |b| {
        b.iter(|| {
            for ip in &ips {
                if !filter.is_allowed(black_box(ip)) {
                    return false;
                }
            }
            true
        })
    });
}

criterion_group!(
    network_benches,
    bench_ip_filter_creation,
    bench_ip_filter_creation_custom,
    bench_ip_filter_public_v4,
    bench_ip_filter_blocked,
    bench_ip_filter_v6,
    bench_ip_filter_custom_cidrs,
    bench_ip_filter_allowed_overrides,
    bench_ip_filter_hostname,
    bench_ip_filter_permissive,
    bench_ip_filter_validate,
    bench_ip_filter_batch,
);

criterion_main!(network_benches);
