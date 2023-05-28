use std::collections::HashMap;
use std::str::FromStr;
use std::string::ToString;

use anyhow::Result;
use axum::http::{HeaderMap, HeaderName};
use hmac::Hmac;
use hmac::Mac;
use sha2::Sha256;
use time::OffsetDateTime;
use url::Url;

use crate::signing;

type HmacSha256 = Hmac<Sha256>;

pub struct Signer {
    id: String,
    secret: String,
    host: String,
    extend_headers: Option<HeaderMap>,
}

pub struct SignRequest {
    url: String,
    expiry: u32,
    datetime: OffsetDateTime,
    method: String,
    headers: Option<HeaderMap>,
    queries: Option<HashMap<String, String>>,
    body: Option<String>,
}

const X_SIGNATURE: &str = "X-Sup-Signature";

impl Signer {
    pub fn new(id: &str, secret: &str, host: &str) -> Self {
        Self {
            id: id.to_string(),
            secret: secret.to_string(),
            host: host.to_string(),
            extend_headers: None,
        }
    }

    fn extend_header(mut self, k: &str, v: &str) -> Result<Self> {
        if let Some(extend_headers) = self.extend_headers.as_mut() {
            extend_headers.insert(HeaderName::from_str(k)?, v.parse()?);
        } else {
            let mut extend_headers = HeaderMap::new();
            extend_headers.insert(HeaderName::from_str(k)?, v.parse()?);
            self.extend_headers = Some(extend_headers)
        }
        Ok(self)
    }

    fn url_no_signed(&self, req: &SignRequest) -> Result<Url> {
        Ok(Url::parse(&format!(
            "{}{}{}",
            Url::parse(&self.host)?,
            signing::authorization_query_params_no_sig(
                &self.id,
                &req.datetime,
                req.expiry,
                &Url::parse(&req.url)?,
                match &req.headers {
                    Some(headers) => Some(headers),
                    None => None,
                },
            )?,
            &signing::flatten_queries(match &req.queries {
                Some(queries) => Some(queries),
                None => None,
            },),
        ))?)
    }

    fn canonical_request(&self, req: &SignRequest) -> Result<String> {
        let mut headers = HeaderMap::new();
        if let Some(custom_headers) = &req.headers {
            for (k, v) in custom_headers.iter() {
                headers.insert(k.clone(), v.clone());
            }
        }
        Ok(signing::canonical_request(
            &req.method,
            &self.url_no_signed(req)?,
            &headers,
            req.body.as_ref().unwrap_or(&String::new()),
        ))
    }

    fn signed_authorization(&self, req: &SignRequest) -> Result<String> {
        let canonical_request = self.canonical_request(req)?;
        let to_sign = signing::string_to_sign(&req.datetime, &canonical_request);

        let mut hmac =
            HmacSha256::new_from_slice(&signing::signing_key(&req.datetime, &self.secret)?)?;
        hmac.update(to_sign.as_bytes());
        let signature = hex::encode(hmac.finalize().into_bytes());
        Ok(signature)
    }

    pub fn get_signed_url(&self, req: &SignRequest) -> Result<String> {
        Ok(format!(
            "{}&{X_SIGNATURE}{}",
            self.url_no_signed(req)?,
            self.signed_authorization(req)?
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request() -> SignRequest {
        SignRequest {
            url: "https://github.com".to_string(),
            expiry: 600,
            datetime: OffsetDateTime::UNIX_EPOCH,
            method: "POST".to_string(),
            headers: None,
            queries: None,
            body: None,
        }
    }

    #[test]
    fn creates_canonical_request() {
        let signer = Signer::new("foo", "secret", "http://localhost:3000");

        let canonical_req = signer.canonical_request(&base_request());

        assert_eq!(
            canonical_req.unwrap(),
            "\
POST
/
X-Sup-Algorithm=SUP1-HMAC-SHA256&X-Sup-Credential=foo%2F19700101&X-Sup-Date=19700101T000000Z&X-Sup-Expires=600&X-Sup-Proxy=https%3A%2F%2Fgithub.com%2F&X-Sup-SignedHeaders=Host



",
        )
    }

    #[test]
    fn creates_the_non_signed_url() {
        let signer = Signer::new("foo", "secret", "http://localhost:3000");

        let non_signed_url = signer.url_no_signed(&base_request()).unwrap();

        assert_eq!(
            non_signed_url.to_string(),
            "http://localhost:3000/?X-Sup-Algorithm=SUP1-HMAC-SHA256&X-Sup-Credential=foo%2F19700101&X-Sup-Date=19700101T000000Z&X-Sup-Expires=600&X-Sup-Proxy=https%3A%2F%2Fgithub.com%2F&X-Sup-SignedHeaders=Host"
        )
    }

    #[test]
    fn creates_a_signed_authorization() {
        let signer = Signer::new("foo", "secret", "http://localhost:3000");

        let signed_authorization = signer.signed_authorization(&base_request()).unwrap();

        assert_eq!(
            signed_authorization,
            "1fdc94423fff3f3626e2aa31c8a34c360e63f5906d84f14888a8c7c1bd1b00ad"
        )
    }

    #[test]
    fn creates_a_signed_url() {
        let signer = Signer::new("foo", "secret", "http://localhost:3000");

        let signed_url = signer.get_signed_url(&base_request()).unwrap();

        assert_eq!(
            signed_url,
            "http://localhost:3000/?X-Sup-Algorithm=SUP1-HMAC-SHA256&X-Sup-Credential=foo%2F19700101&X-Sup-Date=19700101T000000Z&X-Sup-Expires=600&X-Sup-SignedHeaders=X-Sup-Proxy%3BHost&X-Sup-Signature7ca526c0d2f0225ee90e6388356239b5c5722a9ee4a70a4744d4c35234d117fc"
        )
    }
}
