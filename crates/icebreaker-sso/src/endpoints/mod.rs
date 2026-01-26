//! HTTP endpoint handlers for the SSO service.
//!
//! The SSO service exposes the following endpoints:
//!
//! - `GET /<provider>/start` - Initiate OAuth flow
//! - `GET /<provider>/callback` - Handle OAuth callback
//! - `POST /<provider>/refresh` - Refresh access tokens
//! - `GET /health` - Health check

mod callback;
mod health;
mod refresh;
mod start;

pub use callback::handle_callback;
pub use health::handle_health;
pub use refresh::handle_refresh;
pub use start::handle_start;

use std::collections::HashMap;

/// Query parameters for the start endpoint.
#[derive(Debug, Clone)]
pub struct StartParams {
    /// Client redirect URI for after the flow completes.
    pub redirect_uri: Option<String>,

    /// Client state to pass through the flow.
    pub state: Option<String>,

    /// Additional parameters to forward to the OAuth provider.
    pub extra: HashMap<String, String>,
}

impl StartParams {
    /// Parses query parameters from a URI query string.
    #[must_use]
    pub fn from_query(query: Option<&str>) -> Self {
        let mut redirect_uri = None;
        let mut state = None;
        let mut extra = HashMap::new();

        if let Some(query) = query {
            for pair in query.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    let key = urlencoding::decode(key).unwrap_or_default();
                    let value = urlencoding::decode(value).unwrap_or_default();

                    match key.as_ref() {
                        "redirect_uri" => redirect_uri = Some(value.to_string()),
                        "state" => state = Some(value.to_string()),
                        _ => {
                            extra.insert(key.to_string(), value.to_string());
                        }
                    }
                }
            }
        }

        Self {
            redirect_uri,
            state,
            extra,
        }
    }
}

/// Query parameters for the callback endpoint.
#[derive(Debug, Clone)]
pub struct CallbackParams {
    /// Authorization code from the OAuth provider.
    pub code: Option<String>,

    /// State parameter for CSRF verification.
    pub state: Option<String>,

    /// Error code if the OAuth flow failed.
    pub error: Option<String>,

    /// Error description.
    pub error_description: Option<String>,
}

impl CallbackParams {
    /// Parses query parameters from a URI query string.
    #[must_use]
    pub fn from_query(query: Option<&str>) -> Self {
        let mut code = None;
        let mut state = None;
        let mut error = None;
        let mut error_description = None;

        if let Some(query) = query {
            for pair in query.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    let key = urlencoding::decode(key).unwrap_or_default();
                    let value = urlencoding::decode(value).unwrap_or_default();

                    match key.as_ref() {
                        "code" => code = Some(value.to_string()),
                        "state" => state = Some(value.to_string()),
                        "error" => error = Some(value.to_string()),
                        "error_description" => error_description = Some(value.to_string()),
                        _ => {}
                    }
                }
            }
        }

        Self {
            code,
            state,
            error,
            error_description,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_params_parsing() {
        let params = StartParams::from_query(Some(
            "redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&state=mystate&hd=example.com",
        ));

        assert_eq!(
            params.redirect_uri,
            Some("https://example.com/callback".to_string())
        );
        assert_eq!(params.state, Some("mystate".to_string()));
        assert_eq!(params.extra.get("hd"), Some(&"example.com".to_string()));
    }

    #[test]
    fn test_callback_params_parsing() {
        let params = CallbackParams::from_query(Some("code=auth_code_123&state=mystate"));

        assert_eq!(params.code, Some("auth_code_123".to_string()));
        assert_eq!(params.state, Some("mystate".to_string()));
        assert!(params.error.is_none());
    }

    #[test]
    fn test_callback_error_parsing() {
        let params = CallbackParams::from_query(Some(
            "error=access_denied&error_description=User%20denied%20access",
        ));

        assert!(params.code.is_none());
        assert_eq!(params.error, Some("access_denied".to_string()));
        assert_eq!(
            params.error_description,
            Some("User denied access".to_string())
        );
    }
}
