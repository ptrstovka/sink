//! Opt-in CORS policy for public tunneled HTTP traffic.

use std::str::FromStr;

use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header::*};
use thiserror::Error;

use crate::config::ControlServerAddr;

/// An exact HTTP(S) origin, or `*` for any origin without credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorsOrigin(String);

impl FromStr for CorsOrigin {
    type Err = CorsError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "*" {
            return Ok(Self(value.to_owned()));
        }
        if value
            .split_once("://")
            .is_none_or(|(_, rest)| rest.find('/').is_some_and(|index| &rest[index..] != "/"))
        {
            return Err(CorsError::InvalidOrigin);
        }
        let origin: ControlServerAddr = value.parse().map_err(|_| CorsError::InvalidOrigin)?;
        if value.contains('*') {
            return Err(CorsError::InvalidOrigin);
        }
        Ok(Self(origin.as_url().origin().ascii_serialization()))
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CorsError {
    #[error(
        "CORS origin must be an http(s) origin without a path, query, credentials, or fragment, or '*'"
    )]
    InvalidOrigin,
    #[error("--cors-allow-origin '*' cannot be combined with other origins")]
    MixedWildcard,
    #[error("--cors-allow-credentials requires concrete --cors-allow-origin values, without '*'")]
    CredentialsRequireOrigins,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CorsPolicy {
    origins: Vec<CorsOrigin>,
    credentials: bool,
}

impl CorsPolicy {
    pub(crate) fn new(origins: Vec<CorsOrigin>, credentials: bool) -> Result<Self, CorsError> {
        let wildcard = origins.iter().any(|origin| origin.0 == "*");
        if wildcard && origins.len() != 1 {
            return Err(CorsError::MixedWildcard);
        }
        if credentials && (origins.is_empty() || wildcard) {
            return Err(CorsError::CredentialsRequireOrigins);
        }
        Ok(Self {
            origins,
            credentials,
        })
    }

    pub(crate) fn evaluate<B>(&self, request: &Request<B>) -> CorsDecision {
        if self.origins.is_empty() {
            return CorsDecision::default();
        }
        let headers = request.headers();
        let origin = single_header(headers, ORIGIN);
        let valid_origin = origin.and_then(|value| {
            let text = value.to_str().ok()?;
            // Browser Origin values are serialized origins, not URLs with paths.
            let parsed = text.parse::<CorsOrigin>().ok()?;
            (parsed.0 != "*" && parsed.0 == text).then_some(value)
        });
        let wildcard = self.origins[0].0 == "*";
        let allowed = valid_origin.filter(|value| {
            wildcard
                || self
                    .origins
                    .iter()
                    .any(|origin| value.as_bytes() == origin.0.as_bytes())
        });
        let mut decision = CorsDecision {
            enabled: true,
            ..CorsDecision::default()
        };
        if let Some(origin) = allowed {
            decision.headers.insert(
                ACCESS_CONTROL_ALLOW_ORIGIN,
                if wildcard {
                    HeaderValue::from_static("*")
                } else {
                    origin.clone()
                },
            );
            if self.credentials {
                decision.headers.insert(
                    ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    HeaderValue::from_static("true"),
                );
            }
        }
        if request.method() == Method::OPTIONS
            && headers.contains_key(ORIGIN)
            && headers.contains_key(ACCESS_CONTROL_REQUEST_METHOD)
        {
            let method = single_header(headers, ACCESS_CONTROL_REQUEST_METHOD)
                .filter(|value| Method::from_bytes(value.as_bytes()).is_ok());
            let requested_headers = requested_headers(headers);
            let status = if valid_origin.is_none() || method.is_none() || requested_headers.is_err()
            {
                StatusCode::BAD_REQUEST
            } else if allowed.is_none() {
                StatusCode::FORBIDDEN
            } else {
                if let Some(method) = method {
                    decision
                        .headers
                        .insert(ACCESS_CONTROL_ALLOW_METHODS, method.clone());
                }
                if let Ok(Some(headers)) = requested_headers {
                    decision
                        .headers
                        .insert(ACCESS_CONTROL_ALLOW_HEADERS, headers);
                }
                StatusCode::NO_CONTENT
            };
            if status != StatusCode::NO_CONTENT {
                decision.headers.clear();
            }
            decision.preflight = Some(status);
            decision
                .headers
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        }
        decision
    }
}

fn single_header(headers: &HeaderMap, name: HeaderName) -> Option<&HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn requested_headers(headers: &HeaderMap) -> Result<Option<HeaderValue>, ()> {
    let mut names = Vec::new();
    for value in headers.get_all(ACCESS_CONTROL_REQUEST_HEADERS) {
        for name in value.to_str().map_err(|_| ())?.split(',') {
            let name = HeaderName::from_bytes(name.trim().as_bytes()).map_err(|_| ())?;
            names.push(name.to_string());
        }
    }
    if names.is_empty() {
        Ok(None)
    } else {
        HeaderValue::from_str(&names.join(", "))
            .map(Some)
            .map_err(|_| ())
    }
}

#[derive(Default)]
pub(crate) struct CorsDecision {
    enabled: bool,
    headers: HeaderMap,
    pub(crate) preflight: Option<StatusCode>,
}

impl CorsDecision {
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn apply(&self, headers: &mut HeaderMap) {
        if !self.enabled {
            return;
        }
        // Own the complete upstream CORS response policy when explicitly enabled.
        let names: Vec<_> = headers
            .keys()
            .filter(|name| name.as_str().starts_with("access-control-"))
            .cloned()
            .collect();
        for name in names {
            headers.remove(name);
        }
        headers.extend(self.headers.clone());
        if !headers.get_all(VARY).iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim() == "*" || token.trim().eq_ignore_ascii_case("origin"))
            })
        }) {
            headers.append(VARY, HeaderValue::from_static("Origin"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(origins: &[&str], credentials: bool) -> CorsPolicy {
        CorsPolicy::new(
            origins
                .iter()
                .map(|value| value.parse().expect("origin"))
                .collect(),
            credentials,
        )
        .expect("policy")
    }

    fn response(policy: &CorsPolicy, origin: Option<&str>) -> HeaderMap {
        let mut request = Request::builder();
        if let Some(origin) = origin {
            request = request.header(ORIGIN, origin);
        }
        let decision = policy.evaluate(&request.body(()).expect("request"));
        let mut headers = HeaderMap::new();
        headers.append(
            ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("https://upstream.test"),
        );
        headers.append(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        headers.insert(
            ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        headers.insert(
            ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("secret"),
        );
        headers.insert(VARY, HeaderValue::from_static("Accept-Encoding"));
        decision.apply(&mut headers);
        headers
    }

    #[test]
    fn explicit_origins_credentials_and_upstream_override() {
        let policy = policy(&["https://app.example.com", "http://localhost:3000"], true);
        for origin in ["https://app.example.com", "http://localhost:3000"] {
            let headers = response(&policy, Some(origin));
            assert_eq!(headers[ACCESS_CONTROL_ALLOW_ORIGIN], origin);
            assert_eq!(
                headers.get_all(ACCESS_CONTROL_ALLOW_ORIGIN).iter().count(),
                1
            );
            assert_eq!(headers[ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
            assert!(!headers.contains_key(ACCESS_CONTROL_EXPOSE_HEADERS));
            assert_eq!(headers.get_all(VARY).iter().count(), 2);
            assert_eq!(headers[VARY], "Accept-Encoding");
        }
        for origin in [
            None,
            Some("https://evil.test"),
            Some("https://app.example.com.evil.test"),
            Some("http://app.example.com"),
            Some("https://app.example.com:8443"),
            Some("https://app.example.com/"),
            Some("*"),
        ] {
            let headers = response(&policy, origin);
            assert!(!headers.contains_key(ACCESS_CONTROL_ALLOW_ORIGIN));
            assert!(!headers.contains_key(ACCESS_CONTROL_ALLOW_CREDENTIALS));
            assert_eq!(headers.get_all(VARY).iter().count(), 2);
        }
    }

    #[test]
    fn wildcard_and_disabled_defaults() {
        let headers = response(&policy(&["*"], false), Some("https://any.test"));
        assert_eq!(headers[ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert!(!headers.contains_key(ACCESS_CONTROL_ALLOW_CREDENTIALS));
        assert_eq!(headers.get_all(VARY).iter().count(), 2);
        let headers = response(&CorsPolicy::default(), Some("https://any.test"));
        assert_eq!(
            headers.get_all(ACCESS_CONTROL_ALLOW_ORIGIN).iter().count(),
            2
        );
        assert!(headers.contains_key(ACCESS_CONTROL_EXPOSE_HEADERS));
    }

    #[test]
    fn vary_is_not_duplicated_and_duplicate_origins_are_rejected() {
        let policy = policy(&["https://app.example.com"], false);
        let request = Request::builder()
            .header(ORIGIN, "https://app.example.com")
            .body(())
            .expect("request");
        for vary in ["Accept-Encoding, origin", "*"] {
            let mut headers = HeaderMap::new();
            headers.insert(VARY, HeaderValue::from_str(vary).expect("vary"));
            policy.evaluate(&request).apply(&mut headers);
            assert_eq!(headers.get_all(VARY).iter().count(), 1);
        }
        let mut request = request;
        request
            .headers_mut()
            .append(ORIGIN, HeaderValue::from_static("https://app.example.com"));
        let mut headers = HeaderMap::new();
        policy.evaluate(&request).apply(&mut headers);
        assert!(!headers.contains_key(ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    #[test]
    fn preflight_validates_and_echoes_method_and_headers() {
        let policy = policy(&["https://app.example.com"], true);
        for (origin, method, names, expected) in [
            (
                "https://app.example.com",
                "PATCH",
                "Authorization, X-App",
                StatusCode::NO_CONTENT,
            ),
            (
                "https://other.test",
                "PATCH",
                "Authorization",
                StatusCode::FORBIDDEN,
            ),
            ("garbage", "PATCH", "Authorization", StatusCode::BAD_REQUEST),
            (
                "https://app.example.com",
                "bad method",
                "Authorization",
                StatusCode::BAD_REQUEST,
            ),
            (
                "https://app.example.com",
                "PATCH",
                "bad header",
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let request = Request::builder()
                .method(Method::OPTIONS)
                .header(ORIGIN, origin)
                .header(ACCESS_CONTROL_REQUEST_METHOD, method)
                .header(ACCESS_CONTROL_REQUEST_HEADERS, names)
                .body(())
                .expect("request");
            let decision = policy.evaluate(&request);
            assert_eq!(decision.preflight, Some(expected));
            let mut headers = HeaderMap::new();
            decision.apply(&mut headers);
            assert_eq!(headers[CACHE_CONTROL], "no-store");
            if expected == StatusCode::NO_CONTENT {
                assert_eq!(headers[ACCESS_CONTROL_ALLOW_METHODS], "PATCH");
                assert_eq!(
                    headers[ACCESS_CONTROL_ALLOW_HEADERS],
                    "authorization, x-app"
                );
                assert_eq!(headers[ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
            } else {
                assert!(!headers.contains_key(ACCESS_CONTROL_ALLOW_ORIGIN));
            }
        }
        let request = Request::builder()
            .method(Method::OPTIONS)
            .header(ORIGIN, "https://app.example.com")
            .body(())
            .expect("request");
        assert_eq!(policy.evaluate(&request).preflight, None);
        let request = Request::builder()
            .method(Method::OPTIONS)
            .header(ORIGIN, "https://app.example.com")
            .header(ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .body(())
            .expect("request");
        assert_eq!(CorsPolicy::default().evaluate(&request).preflight, None);
    }
}
