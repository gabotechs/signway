use std::ops::Add;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use hyper::http::HeaderName;
use hyper::{HeaderMap, Request};
use time::{Duration, OffsetDateTime, PrimitiveDateTime};
use url::Url;

use crate::signing::signing_functions::LONG_DATETIME;

use super::signing_functions;

#[derive(Debug, Clone)]
pub(crate) struct SignRequest {
    pub proxy_url: Url,
    pub expiry: u32,
    pub datetime: PrimitiveDateTime,
    pub method: String,
    pub headers: Option<HeaderMap>,
    pub body: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct SignInfo {
    pub signature: String,
    pub id: String,
    pub include_body: bool,
}

impl SignRequest {
    pub(crate) fn from_signed_request<T>(req: &Request<T>) -> Result<(Self, SignInfo)> {
        let mut uri = req.uri().to_string();
        // TODO: is there a better way to parse just the query params here?
        if uri.starts_with('/') {
            uri = "http://localhost".to_string() + &uri;
        }
        let url = Url::parse(&uri)?;

        let mut x_algorithm: Option<String> = None;
        let mut x_credential: Option<String> = None;
        let mut x_date: Option<String> = None;
        let mut x_expires: Option<String> = None;
        let mut x_signed_headers: Option<String> = None;
        let mut x_signed_body: Option<bool> = None;
        let mut x_proxy: Option<String> = None;
        let mut x_signature: Option<String> = None;
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                signing_functions::X_ALGORITHM => x_algorithm = Some(v.to_string()),
                signing_functions::X_CREDENTIAL => x_credential = Some(v.to_string()),
                signing_functions::X_EXPIRES => x_expires = Some(v.to_string()),
                signing_functions::X_DATE => x_date = Some(v.to_string()),
                signing_functions::X_SIGNED_HEADERS => x_signed_headers = Some(v.to_string()),
                signing_functions::X_PROXY => x_proxy = Some(v.to_string()),
                signing_functions::X_SIGNED_BODY => x_signed_body = Some(&v == "true"),
                signing_functions::X_SIGNATURE => x_signature = Some(v.to_string()),
                _ => {}
            }
        }

        if x_algorithm.is_none() {
            return Err(anyhow!("missing {}", signing_functions::X_ALGORITHM));
        }

        let datetime = x_date.ok_or_else(|| anyhow!("missing {}", signing_functions::X_DATE))?;
        let datetime = PrimitiveDateTime::parse(&datetime, LONG_DATETIME)?;

        let expiry =
            x_expires.ok_or_else(|| anyhow!("missing {}", signing_functions::X_EXPIRES))?;
        let expiry = u32::from_str(&expiry)
            .map_err(|_| anyhow!("invalid {}", signing_functions::X_EXPIRES))?;

        let now = OffsetDateTime::now_utc();
        let now = PrimitiveDateTime::new(now.date(), now.time());
        let expiry_datetime = datetime.add(Duration::seconds(expiry as i64));
        if now.gt(&expiry_datetime) {
            return Err(anyhow!("Request has expired"));
        }

        let signed_headers = x_signed_headers
            .ok_or_else(|| anyhow!("missing {}", signing_functions::X_SIGNED_HEADERS))?;

        let mut headers = HeaderMap::new();
        // TODO: where does this come from
        for header in signed_headers.split(';') {
            if header.is_empty() {
                continue;
            }
            let value = req.headers().get(header).ok_or_else(|| {
                anyhow!("header {header} should be signed but it is missing in the request")
            })?;
            headers.insert(HeaderName::try_from(header.to_string())?, value.clone());
        }

        let signing_request = SignRequest {
            proxy_url: Url::parse(
                &x_proxy.ok_or_else(|| anyhow!("missing {}", signing_functions::X_PROXY))?,
            )?,
            expiry,
            datetime,
            method: req.method().to_string(),
            headers: Some(headers),
            body: None,
        };

        let credential =
            x_credential.ok_or_else(|| anyhow!("missing {}", signing_functions::X_CREDENTIAL))?;
        let credential_parts = credential.split('/'); // TODO: where does this come from
        let id = credential_parts
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("invalid {}", signing_functions::X_CREDENTIAL))?;

        if id.is_empty() {
            return Err(anyhow!("invalid {}", signing_functions::X_CREDENTIAL));
        }

        let signing_info = SignInfo {
            signature: x_signature
                .ok_or_else(|| anyhow!("missing {}", signing_functions::X_SIGNATURE))?,
            id: id.to_string(),
            include_body: x_signed_body
                .ok_or_else(|| anyhow!("missing {}", signing_functions::X_SIGNED_BODY))?,
        };

        Ok((signing_request, signing_info))
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Sub;

    use lazy_static::lazy_static;

    use signing_functions::{
        LONG_DATETIME, X_ALGORITHM, X_CREDENTIAL, X_DATE, X_EXPIRES, X_PROXY, X_SIGNATURE,
        X_SIGNED_BODY, X_SIGNED_HEADERS,
    };

    use crate::body::string_to_body;

    use super::*;

    lazy_static! {
        static ref NOW: OffsetDateTime = OffsetDateTime::now_utc();
        static ref NOW_FMT: String = NOW.format(LONG_DATETIME).unwrap();
    }

    #[test]
    fn missing_algorithm() {
        let req = Request::builder()
            .method("POST")
            .uri("/foo")
            .body(string_to_body("body"))
            .unwrap();

        let err = SignRequest::from_signed_request(&req).unwrap_err();

        assert_eq!(err.to_string(), format!("missing {X_ALGORITHM}"))
    }

    #[test]
    fn missing_date() {
        let req = Request::builder()
            .method("POST")
            .uri(format!("/foo?{X_ALGORITHM}=asdf"))
            .body(string_to_body("body"))
            .unwrap();

        let err = SignRequest::from_signed_request(&req).unwrap_err();

        assert_eq!(err.to_string(), format!("missing {X_DATE}"))
    }

    #[test]
    fn missing_expires() {
        let now: &str = &NOW_FMT;
        let req = Request::builder()
            .method("POST")
            .uri(&format!("/foo?{X_ALGORITHM}=asdf&{X_DATE}={now}"))
            .body(string_to_body("body"))
            .unwrap();

        let err = SignRequest::from_signed_request(&req).unwrap_err();

        assert_eq!(err.to_string(), format!("missing {X_EXPIRES}"))
    }

    #[test]
    fn missing_signed_headers() {
        let now: &str = &NOW_FMT;
        let req = Request::builder()
            .method("POST")
            .uri(&format!(
                "/foo?{X_ALGORITHM}=asdf&{X_DATE}={now}&{X_EXPIRES}=60"
            ))
            .body(string_to_body("body"))
            .unwrap();

        let err = SignRequest::from_signed_request(&req).unwrap_err();

        assert_eq!(err.to_string(), format!("missing {X_SIGNED_HEADERS}"))
    }

    #[test]
    fn expired_request() {
        let now: &str = &NOW
            .sub(Duration::seconds(61))
            .format(LONG_DATETIME)
            .unwrap();
        let req = Request::builder()
            .method("POST")
            .uri(&format!(
                "/foo?{X_ALGORITHM}=asdf&{X_DATE}={now}&{X_EXPIRES}=60"
            ))
            .body(string_to_body("body"))
            .unwrap();

        let err = SignRequest::from_signed_request(&req).unwrap_err();

        assert_eq!(err.to_string(), "Request has expired")
    }

    #[test]
    fn missing_host_header() {
        let now: &str = &NOW_FMT;
        let req = Request::builder()
            .method("POST")
            .uri(&format!(
                "/foo?{X_ALGORITHM}=asdf&{X_DATE}={now}&{X_EXPIRES}=60&{X_SIGNED_HEADERS}=host"
            ))
            .body(string_to_body("body"))
            .unwrap();

        let err = SignRequest::from_signed_request(&req).unwrap_err();

        assert_eq!(
            err.to_string(),
            "header host should be signed but it is missing in the request"
        )
    }

    #[test]
    fn missing_proxy() {
        let now: &str = &NOW_FMT;
        let req = Request::builder()
            .method("POST")
            .uri(&format!(
                "/foo?{X_ALGORITHM}=asdf&{X_DATE}={now}&{X_EXPIRES}=60&{X_SIGNED_HEADERS}=host"
            ))
            .header("HOST", "localhost:3000")
            .body(string_to_body("body"))
            .unwrap();

        let err = SignRequest::from_signed_request(&req).unwrap_err();

        assert_eq!(err.to_string(), format!("missing {X_PROXY}"))
    }

    #[test]
    fn missing_credential() {
        let now: &str = &NOW_FMT;
        let req = Request::builder()
            .method("POST")
            .uri(&format!(
                "/foo?{X_ALGORITHM}=asdf&{X_DATE}={now}&{X_EXPIRES}=60&{X_SIGNED_HEADERS}=host&{X_PROXY}=https://github.com"
            ))
            .header("HOST", "localhost:3000")
            .body(string_to_body("body"))
            .unwrap();

        let err = SignRequest::from_signed_request(&req).unwrap_err();

        assert_eq!(err.to_string(), format!("missing {X_CREDENTIAL}"))
    }

    #[test]
    fn missing_signature() {
        let now: &str = &NOW_FMT;
        let req = Request::builder()
            .method("POST")
            .uri(&format!(
                "/foo?{X_ALGORITHM}=asdf&{X_DATE}={now}&{X_EXPIRES}=60&{X_SIGNED_HEADERS}=host&{X_PROXY}=https://github.com&{X_CREDENTIAL}=asdf"
            ))
            .header("HOST", "localhost:3000")
            .body(string_to_body("body"))
            .unwrap();

        let err = SignRequest::from_signed_request(&req).unwrap_err();

        assert_eq!(err.to_string(), format!("missing {X_SIGNATURE}"))
    }

    #[test]
    fn missing_signed_body() {
        let now: &str = &NOW_FMT;
        let req = Request::builder()
            .method("POST")
            .uri(&format!(
                "/foo?{X_ALGORITHM}=asdf&{X_DATE}={now}&{X_EXPIRES}=60&{X_SIGNED_HEADERS}=host&{X_PROXY}=https://github.com&{X_CREDENTIAL}=asdf&{X_SIGNATURE}=asdf"
            ))
            .header("HOST", "localhost:3000")
            .body(string_to_body("body"))
            .unwrap();

        let err = SignRequest::from_signed_request(&req).unwrap_err();

        assert_eq!(err.to_string(), format!("missing {X_SIGNED_BODY}"))
    }

    #[test]
    fn happy_path() {
        let now: &str = &NOW_FMT;
        let req = Request::builder()
            .method("POST")
            .uri(&format!(
                "/foo?{X_ALGORITHM}=asdf&{X_DATE}={now}&{X_EXPIRES}=60&{X_SIGNED_HEADERS}=host&{X_PROXY}=https://github.com&{X_CREDENTIAL}=asdf&{X_SIGNATURE}=asdf&{X_SIGNED_BODY}=true"
            ))
            .header("HOST", "localhost:3000")
            .body(string_to_body("body"))
            .unwrap();

        let (sign_req, info) = SignRequest::from_signed_request(&req).unwrap();
        assert_eq!(sign_req.proxy_url.to_string(), "https://github.com/");
        assert_eq!(sign_req.expiry, 60);
        assert_eq!(sign_req.method, "POST");
        assert!(sign_req.body.is_none());

        assert_eq!(info.id, "asdf");
        assert!(info.include_body);
        assert_eq!(info.signature, "asdf")
    }
}
