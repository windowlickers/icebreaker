//! Request processors for different token injection strategies.
//!
//! # Architecture
//!
//! Processors are split into two phases:
//!
//! 1. **Header phase** ([`RequestProcessor::process`]): Synchronous, generic over body type.
//!    Used by most processors to modify headers, add signatures, etc.
//!
//! 2. **Body phase** ([`Processor::process_body`]): Async, requires concrete body type.
//!    Used by processors that need to modify request bodies (e.g., placeholder injection).
//!
//! # Factory Pattern
//!
//! Each processor type implements the [`ProcessorFactory`] trait, enabling
//! configuration-driven processor creation. The [`Processor`] enum provides
//! type-safe dispatch while keeping each processor module self-contained.
//!
//! ## Adding a New Processor
//!
//! 1. Create a new module with the processor implementation
//! 2. Implement [`RequestProcessor`] for the processor type (for header-only processors)
//! 3. Or add body processing support to [`Processor`] enum (for body processors)
//! 4. Implement [`ProcessorFactory`] for the config type
//! 5. Add the variant to the [`define_processors!`] macro invocation
//! 6. Add the config variant to [`ProcessorConfig`] in `icebreaker-common`

mod hmac;
mod inject;
mod inject_body;
mod oauth;
mod sigv4;

#[cfg(test)]
pub(crate) mod test_utils;

use bytes::Bytes;
use http::Request;
use http_body::Body;
use http_body_util::BodyExt;
use icebreaker_common::{
    HmacConfig, InjectBodyConfig, InjectConfig, OAuthConfig, ProcessorConfig, Result, Sigv4Config,
    TokenPayload,
};

pub use hmac::HmacProcessor;
pub use inject::InjectProcessor;
pub use inject_body::InjectBodyProcessor;
pub use oauth::OAuthProcessor;
pub use sigv4::Sigv4Processor;

/// Trait for request processors that modify headers.
///
/// This trait has generic methods, making it not dyn-compatible.
/// Use the [`Processor`] enum for dynamic dispatch.
///
/// Note: Processors that need to modify the request body should not implement
/// this trait. Instead, body processing is handled separately through
/// [`Processor::process_body`].
pub trait RequestProcessor: Send + Sync {
    /// Processes a request, injecting secrets into headers as configured.
    fn process<B>(&self, request: Request<B>, payload: &TokenPayload) -> Result<Request<B>>;
}

/// Trait for creating processors from configuration.
///
/// Implement this trait on configuration types to enable factory-based
/// processor creation. Each processor module is responsible for its own
/// factory implementation.
pub trait ProcessorFactory {
    /// The processor type this factory creates.
    type Processor: RequestProcessor;

    /// Creates a processor from the configuration.
    fn create_processor(&self) -> Self::Processor;
}

// Implement ProcessorFactory for each config type
impl ProcessorFactory for InjectConfig {
    type Processor = InjectProcessor;

    fn create_processor(&self) -> Self::Processor {
        InjectProcessor::new(self.clone())
    }
}

impl ProcessorFactory for HmacConfig {
    type Processor = HmacProcessor;

    fn create_processor(&self) -> Self::Processor {
        HmacProcessor::new(self.clone())
    }
}

impl ProcessorFactory for OAuthConfig {
    type Processor = OAuthProcessor;

    fn create_processor(&self) -> Self::Processor {
        OAuthProcessor::new(self.clone())
    }
}

// Note: InjectBodyConfig doesn't implement ProcessorFactory because
// InjectBodyProcessor handles body modification, not header processing.
// Body processing is handled separately through Processor::process_body().

impl ProcessorFactory for Sigv4Config {
    type Processor = Sigv4Processor;

    fn create_processor(&self) -> Self::Processor {
        Sigv4Processor::new(self.clone())
    }
}

/// Macro to define the processor enum with automatic dispatch implementation.
///
/// This macro generates:
/// - The `Processor` enum with the specified variants
/// - `process()` method that dispatches to the correct processor
/// - `From` implementations for each processor type
macro_rules! define_header_processors {
    (
        $(
            $(#[$meta:meta])*
            $variant:ident($processor:ty)
        ),* $(,)?
    ) => {
        $(
            impl From<$processor> for Processor {
                fn from(processor: $processor) -> Self {
                    Processor::$variant(processor)
                }
            }
        )*
    };
}

/// A concrete processor enum that dispatches to the correct implementation.
///
/// This enum handles two types of processing:
/// - **Header processors**: Implement [`RequestProcessor`] and modify headers synchronously
/// - **Body processors**: Require async body collection and modification
///
/// Use [`Processor::process`] for header modifications and [`Processor::process_body`]
/// for body modifications. Check [`Processor::is_body_processor`] to determine which
/// method to use.
#[derive(Debug, Clone)]
pub enum Processor {
    /// Simple header injection.
    Inject(InjectProcessor),
    /// HMAC signature injection.
    Hmac(HmacProcessor),
    /// OAuth token injection.
    OAuth(OAuthProcessor),
    /// Request body placeholder injection.
    InjectBody(InjectBodyProcessor),
    /// AWS Signature Version 4 signing.
    Sigv4(Sigv4Processor),
}

impl Processor {
    /// Processes a request by modifying headers.
    ///
    /// For body processors, this is a no-op that returns the request unchanged.
    /// Use [`Self::process_body`] for body modifications.
    pub fn process<B>(&self, request: Request<B>, payload: &TokenPayload) -> Result<Request<B>> {
        match self {
            Processor::Inject(p) => p.process(request, payload),
            // HMAC with body signing defers to process_body
            Processor::Hmac(p) if p.config().sign_body => Ok(request),
            Processor::Hmac(p) => p.process(request, payload),
            Processor::OAuth(p) => p.process(request, payload),
            Processor::Sigv4(p) => p.process(request, payload),
            // Body processors don't modify headers
            Processor::InjectBody(_) => Ok(request),
        }
    }

    /// Returns true if this processor modifies the request body.
    ///
    /// Body processors require special handling in middleware where the body
    /// type is concrete and can be collected asynchronously.
    ///
    /// Note: HMAC processors with `sign_body: true` also return `true` here
    /// because they need access to the body content to compute the signature.
    #[must_use]
    pub fn is_body_processor(&self) -> bool {
        match self {
            Processor::InjectBody(_) => true,
            Processor::Hmac(p) => p.config().sign_body,
            _ => false,
        }
    }

    /// Processes a request body, replacing placeholders with secrets.
    ///
    /// This method is only meaningful for body processors. For header-only
    /// processors, this returns the request unchanged (wrapped in a `Full` body).
    ///
    /// # Errors
    ///
    /// Returns an error if the body cannot be collected or processed.
    pub async fn process_body<B>(
        &self,
        request: Request<B>,
        payload: &TokenPayload,
    ) -> Result<Request<http_body_util::Full<Bytes>>>
    where
        B: Body,
        B::Error: std::fmt::Display,
    {
        match self {
            Processor::InjectBody(p) => p.process_body(request, payload.expose_secret()).await,
            // HMAC with body signing needs to include body hash in signature
            Processor::Hmac(p) if p.config().sign_body => {
                p.process_body_signing(request, payload).await
            }
            // Non-body processors: convert body to Full<Bytes> unchanged
            _ => {
                let (parts, body) = request.into_parts();
                let body_bytes = body
                    .collect()
                    .await
                    .map_err(|e| {
                        icebreaker_common::TokenizerError::HttpError(format!(
                            "failed to collect body: {e}"
                        ))
                    })?
                    .to_bytes();
                Ok(Request::from_parts(
                    parts,
                    http_body_util::Full::new(body_bytes),
                ))
            }
        }
    }

    /// Returns the body processor configuration if this is a body processor.
    ///
    /// This is useful for middleware that needs to access the configuration
    /// without processing the body.
    #[must_use]
    pub fn body_config(&self) -> Option<&InjectBodyConfig> {
        match self {
            Processor::InjectBody(p) => Some(p.config()),
            _ => None,
        }
    }
}

// Generate From implementations for header processors
define_header_processors! {
    /// Simple header injection.
    Inject(InjectProcessor),
    /// HMAC signature injection.
    Hmac(HmacProcessor),
    /// OAuth token injection.
    OAuth(OAuthProcessor),
    /// AWS Signature Version 4 signing.
    Sigv4(Sigv4Processor),
}

impl From<InjectBodyProcessor> for Processor {
    fn from(processor: InjectBodyProcessor) -> Self {
        Processor::InjectBody(processor)
    }
}

/// Creates a processor from a configuration.
///
/// This function uses the [`ProcessorFactory`] trait to delegate processor
/// creation to the configuration types for header processors. Body processors
/// are created directly.
pub fn create_processor(config: &ProcessorConfig) -> Processor {
    match config {
        ProcessorConfig::Inject(c) => c.create_processor().into(),
        ProcessorConfig::InjectHmac(c) => c.create_processor().into(),
        ProcessorConfig::OAuth(c) => c.create_processor().into(),
        // InjectBody doesn't use ProcessorFactory since it's a body processor
        ProcessorConfig::InjectBody(c) => InjectBodyProcessor::new(c.clone()).into(),
        ProcessorConfig::Sigv4(c) => c.create_processor().into(),
    }
}

#[cfg(test)]
mod processor_tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use icebreaker_common::{HmacAlgorithm, HmacConfig, InjectBodyConfig};
    use test_utils::create_test_payload;

    #[test]
    fn test_hmac_is_body_processor_when_sign_body_true() {
        let config = HmacConfig {
            signature_header: "X-Signature".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            signed_headers: vec!["host".to_string()],
            timestamp_header: None,
            sign_body: true,
        };
        let processor = Processor::Hmac(HmacProcessor::new(config));

        assert!(processor.is_body_processor());
    }

    #[test]
    fn test_hmac_is_not_body_processor_when_sign_body_false() {
        let config = HmacConfig {
            signature_header: "X-Signature".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            signed_headers: vec!["host".to_string()],
            timestamp_header: None,
            sign_body: false,
        };
        let processor = Processor::Hmac(HmacProcessor::new(config));

        assert!(!processor.is_body_processor());
    }

    #[test]
    fn test_inject_body_is_body_processor() {
        let processor =
            Processor::InjectBody(InjectBodyProcessor::new(InjectBodyConfig::default()));
        assert!(processor.is_body_processor());
    }

    #[test]
    fn test_inject_is_not_body_processor() {
        let config = icebreaker_common::InjectConfig::bearer("Authorization");
        let processor = Processor::Inject(InjectProcessor::new(config));
        assert!(!processor.is_body_processor());
    }

    #[test]
    fn test_hmac_process_skips_when_sign_body_true() {
        let config = HmacConfig {
            signature_header: "X-Signature".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            signed_headers: vec!["host".to_string()],
            timestamp_header: None,
            sign_body: true,
        };
        let processor = Processor::Hmac(HmacProcessor::new(config));
        let payload = create_test_payload(
            "hmac-secret-key",
            ProcessorConfig::InjectHmac(HmacConfig::default()),
        );

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header("host", "api.example.com")
            .body(())
            .expect("request should build");

        let processed = processor
            .process(request, &payload)
            .expect("should process");

        // Should NOT have signature header (deferred to process_body)
        assert!(processed.headers().get("X-Signature").is_none());
    }

    #[tokio::test]
    async fn test_processor_process_body_dispatches_to_hmac() {
        let config = HmacConfig {
            signature_header: "X-Signature".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            signed_headers: vec!["host".to_string()],
            timestamp_header: None,
            sign_body: true,
        };
        let processor = Processor::Hmac(HmacProcessor::new(config));
        let payload = create_test_payload(
            "hmac-secret-key",
            ProcessorConfig::InjectHmac(HmacConfig::default()),
        );

        let body = http_body_util::Full::new(Bytes::from("{\"data\":\"test\"}"));
        let request = Request::builder()
            .method("POST")
            .uri("https://api.example.com/data")
            .header("host", "api.example.com")
            .body(body)
            .expect("request should build");

        let processed = processor
            .process_body(request, &payload)
            .await
            .expect("should process");

        // Should have signature header
        assert!(processed.headers().get("X-Signature").is_some());

        // Body should be preserved
        let body_bytes = processed
            .into_body()
            .collect()
            .await
            .expect("should collect body")
            .to_bytes();
        assert_eq!(body_bytes.as_ref(), b"{\"data\":\"test\"}");
    }

    #[tokio::test]
    async fn test_processor_process_body_passes_through_for_non_body_hmac() {
        let config = HmacConfig {
            signature_header: "X-Signature".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            signed_headers: vec!["host".to_string()],
            timestamp_header: None,
            sign_body: false, // Not a body processor
        };
        let processor = Processor::Hmac(HmacProcessor::new(config));
        let payload = create_test_payload(
            "hmac-secret-key",
            ProcessorConfig::InjectHmac(HmacConfig::default()),
        );

        let body = http_body_util::Full::new(Bytes::from("{\"data\":\"test\"}"));
        let request = Request::builder()
            .method("POST")
            .uri("https://api.example.com/data")
            .header("host", "api.example.com")
            .body(body)
            .expect("request should build");

        let processed = processor
            .process_body(request, &payload)
            .await
            .expect("should process");

        // Should NOT have signature header (non-body processor path)
        assert!(processed.headers().get("X-Signature").is_none());

        // Body should be preserved
        let body_bytes = processed
            .into_body()
            .collect()
            .await
            .expect("should collect body")
            .to_bytes();
        assert_eq!(body_bytes.as_ref(), b"{\"data\":\"test\"}");
    }
}
