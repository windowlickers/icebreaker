# Rust Audit — crates/

**Coverage:** 76 files across 8 crates (icebreaker, -common, -crypto, -proxy, -sso, -nonce, -cli, -bench)

## P0
- `crates/icebreaker-sso/src/endpoints/callback.rs:~200` / `refresh.rs:~200` / `error.rs` — `CallbackResponse::error` and `RefreshResponse::error` send `SsoError::to_string()` verbatim as HTTP response body, leaking configured hostnames, full redirect URIs, and raw upstream OAuth response bodies to clients. No `client_message()` sanitization analogous to `TokenizerError`. (error-clarity)

## P1
- `crates/icebreaker-proxy/src/network/ip_filter.rs:32` — `make_net` panic surface via `unreachable!` reachable from public `IpFilter::new()`/`check_ip()`. Use `.expect(...)` with rationale or const-eval the statics. (error-clarity)
- `crates/icebreaker-proxy/src/middleware/token_injection.rs:197` — `poll_ready` discards inner-service error with `|_|`; operators get no cause. (error-clarity)
- `crates/icebreaker-proxy/src/middleware/token_injection.rs:434` — `inner.call(...).map_err(|_| ...)` discards the actual hyper/transport error; "upstream request failed" is unactionable. (error-clarity)
- `crates/icebreaker-sso/src/endpoints/callback.rs:177` and `refresh.rs:175` — `response.text().await.unwrap_or_default()` masks body-read failures as empty `reason`. (error-clarity)
- `crates/icebreaker-sso/src/config.rs:40-57` — `expand_env_var` byte-index slicing panics on multi-byte `${` boundaries; `env::var(...).unwrap_or_default()` silently substitutes empty for missing/invalid-UTF-8 vars (security-sensitive config). (idiom)
- `crates/icebreaker-common/src/token.rs:625` — `ReplayProtection::nonce: String`. Primitive obsession on a cryptographic nonce; same for `SealedToken::key_id` and `VersionedKeypair::key_id`. (idiom)
- `crates/icebreaker-common/src/processor.rs:261` — `Sigv4Config::access_key: String` is primitive obsession for an AWS access-key ID; newtype prevents confusion with the payload secret. (idiom)
- `crates/icebreaker-cli/src/main.rs:823` — `serve` command: 305 lines, cyclomatic ≈25 (limits 100/8). Extract setup phases. (complexity)
- `crates/icebreaker-cli/src/main.rs:1478` — `seal` command: 152 lines, cyclomatic ≈21. Extract `build_processor_config`/`build_token_payload`. (complexity)
- `crates/icebreaker-cli/src/main.rs:262` — 161-char line in doc comment. (complexity)
- `crates/icebreaker-proxy/src/middleware/token_injection.rs:200` — `TokenInjectionService::call` 216 lines; extract `validate_host`/`validate_method`/`validate_path`/`check_ip`/`run_processor`. (complexity)
- `crates/icebreaker-proxy/src/body/overlap_buffer.rs:151` — `contains_pattern` returns `true` for empty needle; if `generate_scan_patterns` ever emits an empty vec, every response chunk fires a leak alert. Guard at `StreamScanner::add_pattern` instead. (vacuous)
- `crates/icebreaker-crypto/src/auth_validation.rs:572, 775, 940` — three tautological tests where expected values are derived by calling the same function under test (`derive_api_key_hmac_key`, `hash_api_key`). Replace with known-answer constants or behavioral assertions. (vacuous)
- `crates/icebreaker-proxy/src/processor/hmac.rs:157` — `test_hmac_signature_injection` asserts only that the signature header is "hex-shaped"; never verifies the actual HMAC value matches an independent computation. (test-shape)
- `crates/icebreaker-common/src/token.rs:136` — `SealedToken::from_header` rejection paths (bad base64, valid base64 of `{}`, wrong prefix) untested. (test-shape)
- `crates/icebreaker-proxy/src/body/overlap_buffer.rs:28` — `OverlapBuffer::new(0)`, empty non-last chunks, and exact-boundary pattern splits untested. (test-shape)
- `crates/icebreaker-proxy/src/processor/inject_body.rs:55` — `replace_placeholder` at byte 0, ending at last byte, or as entire body — untested off-by-one paths. (test-shape)
- `crates/icebreaker-proxy/src/network/ip_filter.rs:120` — `IpFilter::new` invalid-CIDR `Err` paths untested. (test-shape)
- `crates/icebreaker-crypto/src/auth_validation.rs:521` — `validate_mtls` rejection when `subject_pattern` configured but `subject_dn` absent — untested security branch. (test-shape)

## P2
- Missing `#[must_use]` cluster: `ResponseScanLayer::new`/`with_patterns` (response_scan.rs:171-186), `IpFilter::new`/`permissive` (ip_filter.rs:120-156), `TokenInjectionLayer::new` (token_injection.rs:128), `ValidatingConnector::new` (validating_connector.rs:46). (idiom)
- Oversized module cluster (>500 lines): `common/src/token.rs` (1111), `cli/src/main.rs` (1250), `proxy/middleware/token_injection.rs` (983), `proxy/middleware/response_scan.rs` (839), `crypto/auth_validation.rs` (625), `sso/endpoints/refresh.rs` (538), `proxy/network/ip_filter.rs` (536). (complexity)
- `crates/icebreaker-common/src/token.rs:484-521` — `TokenPayloadBuilder` methods take `Vec<String>` by value; accept `impl Into<Vec<String>>` for caller flexibility. (idiom)
- `crates/icebreaker-sso/src/transaction/state.rs:51,69,76,82` — builder methods take bare `String` instead of `impl Into<String>`. (idiom)
- `crates/icebreaker-common/src/processor.rs:301` — `MultiProcessorConfig::validate` returns `Result<(), String>` then callers wrap to `TokenizerError`; produce `TokenizerError::InvalidPayload` directly. (idiom)
- `crates/icebreaker-proxy/src/tls/acceptor.rs` — hand-rolled `impl Display`/`Error` for `TlsAcceptorError`; convert to `#[derive(thiserror::Error)]` for consistency. (error-clarity)
- `crates/icebreaker-crypto/src/auth_validation.rs:278-309` — `parse_proxy_authorization` is a strict subset of `parse_custom_auth_header` and never called by production code; delete it. (vacuous)
- `crates/icebreaker-proxy/src/middleware/token_injection.rs:277` — `split(':').next().unwrap_or(h)` is clearer as `split_once(':').map_or(h, |(host, _)| host)`. (idiom)
- `crates/icebreaker-proxy/src/body/scanning.rs:73-80` — manual for-loop over `headers.values()` is a clean `any(...)` iterator chain. (idiom)
- `crates/icebreaker-proxy/src/network/ip_filter.rs:264-365` — `is_loopback`/`is_link_local`/`is_reserved_v6`/`is_private_v6` use `&self` but read no fields; could be free functions. (idiom)
- `crates/icebreaker-crypto/src/auth_validation.rs:115` — `ConnectionInfo::rate_limit_key` allocates a `String` each call; return `Cow<'_, str>`. (idiom)
- `crates/icebreaker-sso/src/transaction/cookie.rs:23` — `CookieManager` missing `Clone` derive; all fields are cloneable. (idiom)
- `crates/icebreaker-common/src/token.rs:263` — `anchor_pattern` branch-coverage gaps (`^`-only, `$`-only) and missing idempotence test. (test-shape)
- `crates/icebreaker-proxy/src/middleware/token_injection.rs:70` — `generate_scan_patterns` tests assert presence using the same encoding call as the production code (self-mirror). Decode each variant back and compare to original. (test-shape)
- `crates/icebreaker-proxy/src/processor/sigv4.rs:41` — `extract_credential_scope`/`extract_signed_headers` `None` branches (missing/malformed fields) under-tested. (test-shape)
- `crates/icebreaker-nonce/src/store.rs:250` — sliding-TTL extension on nonce reuse is unverified. (test-shape)
- `crates/icebreaker-crypto/src/sealed_box.rs:605-612` — `test_builder_method_sets_require_expiration` only checks field-set-then-read; the behavioral test elsewhere already covers it. (vacuous)

**Cross-cutting suggestion (P1/P2):** several test gaps (`SealedToken` roundtrip, `generate_scan_patterns`, `replace_placeholder`, `anchor_pattern`, `OverlapBuffer`, `IpFilter` CIDR matching) are structurally suited to property-based testing. `proptest` is not yet a dev-dependency — adding it once would address multiple findings.

## By agent
- idiom-auditor: 17
- error-clarity: 7
- complexity-scout: 13
- test-shape: 10
- vacuous-logic: 6
- inline: 0
