//! Request processors for different token injection strategies.

mod hmac;
mod inject;
mod oauth;

use http::Request;
use icebreaker_common::{ProcessorConfig, Result, TokenPayload};

pub use hmac::HmacProcessor;
pub use inject::InjectProcessor;
pub use oauth::OAuthProcessor;

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
}

impl Processor {
    /// Processes a request, injecting secrets as configured.
    pub fn process<B>(&self, request: Request<B>, payload: &TokenPayload) -> Result<Request<B>> {
        match self {
            Processor::Inject(p) => p.process(request, payload),
            Processor::Hmac(p) => p.process(request, payload),
            Processor::OAuth(p) => p.process(request, payload),
        }
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
    }
}
