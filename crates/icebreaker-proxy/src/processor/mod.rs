//! Request processors for different token injection strategies.

mod hmac;
mod inject;
mod inject_body;
mod oauth;
mod sigv4;

use http::Request;
use icebreaker_common::{ProcessorConfig, Result, TokenPayload};

pub use hmac::HmacProcessor;
pub use inject::InjectProcessor;
pub use inject_body::{process_body, InjectBodyProcessor};
pub use oauth::OAuthProcessor;
pub use sigv4::Sigv4Processor;

/// Trait for request processors.
pub trait RequestProcessor: Send + Sync {
    /// Processes a request, injecting secrets as configured.
    fn process<B>(&self, request: Request<B>, payload: &TokenPayload) -> Result<Request<B>>;
}

/// A concrete processor enum that dispatches to the correct implementation.
///
/// This is used instead of `Box<dyn RequestProcessor>` because the trait
/// has generic methods which are not dyn-compatible.
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
    /// Processes a request, injecting secrets as configured.
    pub fn process<B>(&self, request: Request<B>, payload: &TokenPayload) -> Result<Request<B>> {
        match self {
            Processor::Inject(p) => p.process(request, payload),
            Processor::Hmac(p) => p.process(request, payload),
            Processor::OAuth(p) => p.process(request, payload),
            Processor::InjectBody(p) => p.process(request, payload),
            Processor::Sigv4(p) => p.process(request, payload),
        }
    }

    /// Returns true if this processor requires body modification.
    ///
    /// Processors that modify the request body need special handling
    /// in middleware where the body type is concrete.
    #[must_use]
    pub fn requires_body_modification(&self) -> bool {
        matches!(self, Processor::InjectBody(_))
    }
}

/// Creates a processor from a configuration.
pub fn create_processor(config: &ProcessorConfig) -> Processor {
    match config {
        ProcessorConfig::Inject(inject_config) => {
            Processor::Inject(InjectProcessor::new(inject_config.clone()))
        }
        ProcessorConfig::InjectHmac(hmac_config) => {
            Processor::Hmac(HmacProcessor::new(hmac_config.clone()))
        }
        ProcessorConfig::OAuth(oauth_config) => {
            Processor::OAuth(OAuthProcessor::new(oauth_config.clone()))
        }
        ProcessorConfig::InjectBody(inject_body_config) => {
            Processor::InjectBody(InjectBodyProcessor::new(inject_body_config.clone()))
        }
        ProcessorConfig::Sigv4(sigv4_config) => {
            Processor::Sigv4(Sigv4Processor::new(sigv4_config.clone()))
        }
    }
}
