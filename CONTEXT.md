# Domain Glossary

Terms used throughout Icebreaker's code and docs. Keep names in code aligned
with this vocabulary.

## Admission

The pipeline that decides whether a request may proceed and prepares it for
upstream forwarding: decrypt the sealed token, validate client authentication,
enforce the token's host/method/path constraints, check replay protection,
then inject the secret and attach forwarding metadata (upstream scheme, scan
patterns). In token-optional mode, admission passes a token-less request
through unchanged, gated only by the static host policy.

Module: `TokenAdmission` in `crates/icebreaker-proxy/src/admission.rs`, with
`admit()` as its interface. The `TokenInjectionLayer` middleware is a thin
Tower adapter around it.

## Sealed token

An encrypted, self-contained credential (`SealedToken`) carrying the secret,
its processor config, and the constraints admission enforces. All proxy state
lives in sealed tokens; there is no database.

## Processor

The strategy that applies a token's secret to a request: header injection,
HMAC signing, OAuth, body placeholder replacement, SigV4 re-signing, or a
Multi chain. Header processors run synchronously during admission; body
processors require body collection and run separately.

## Response scanning

Leak detection on the way back: admission attaches scan patterns (encoded
variants of the injected secret), and the response-scan middleware blocks
response bodies or headers that contain them.

## Token-optional mode

An opt-in mode where requests without a token are forwarded without injection,
gated by a static host policy (allow/deny lists, port-aware).

## Bump (TLS interception)

Terminating a CONNECT client's TLS with a minted leaf certificate, running the
normal middleware stack on the decrypted stream, and re-originating TLS to the
real upstream. Hosts that pin certificates are tunneled instead (no-bump).
