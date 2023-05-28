use std::string::ToString;

use anyhow::Result;
use hmac::Hmac;
use hmac::Mac;
use hyper::HeaderMap;
use sha2::Sha256;
use url::Url;

use crate::sign_request::SignRequest;
use crate::signing;

type HmacSha256 = Hmac<Sha256>;

pub struct Signer {
    id: String,
    secret: String,
    host: Url,
}

impl Signer {
    pub fn new(id: &str, secret: &str, host: Url) -> Self {
        Self {
            id: id.to_string(),
            secret: secret.to_string(),
            host,
        }
    }

    fn url_no_signed(&self, req: &SignRequest) -> Result<Url> {
        Ok(Url::parse(&format!(
            "{}{}{}",
            &self.host,
            signing::authorization_query_params_no_sig(
                &self.id,
                &req.datetime,
                req.expiry,
                &req.url,
                match &req.headers {
                    Some(headers) => Some(headers),
                    None => None,
                },
                req.body.is_some()
            )?,
            &signing::flatten_queries(match &req.queries {
                Some(queries) => Some(queries),
                None => None,
            }),
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

    pub fn get_signature(&self, req: &SignRequest) -> Result<String> {
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
            "{}&{}={}",
            self.url_no_signed(req)?,
            signing::X_SIGNATURE,
            self.get_signature(req)?
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn base_request() -> SignRequest {
        SignRequest {
            url: Url::parse("https://github.com").unwrap(),
            expiry: 600,
            datetime: OffsetDateTime::UNIX_EPOCH,
            method: "POST".to_string(),
            headers: None,
            queries: None,
            body: None,
        }
    }

    fn signer() -> Signer {
        Signer::new(
            "foo",
            "secret",
            Url::parse("http://localhost:3000").unwrap(),
        )
    }

    #[test]
    fn creates_canonical_request() {
        let canonical_req = signer().canonical_request(&base_request());

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
        let non_signed_url = signer().url_no_signed(&base_request()).unwrap();

        assert_eq!(
            non_signed_url.to_string(),
            "http://localhost:3000/?X-Sup-Algorithm=SUP1-HMAC-SHA256&X-Sup-Credential=foo%2F19700101&X-Sup-Date=19700101T000000Z&X-Sup-Expires=600&X-Sup-Proxy=https%3A%2F%2Fgithub.com%2F&X-Sup-SignedHeaders=Host"
        )
    }

    #[test]
    fn creates_a_signed_authorization() {
        let signed_authorization = signer().get_signature(&base_request()).unwrap();

        assert_eq!(
            signed_authorization,
            "1fdc94423fff3f3626e2aa31c8a34c360e63f5906d84f14888a8c7c1bd1b00ad"
        )
    }

    #[test]
    fn creates_a_signed_url() {
        let signed_url = signer().get_signed_url(&base_request()).unwrap();

        assert_eq!(
            signed_url,
            "http://localhost:3000/?X-Sup-Algorithm=SUP1-HMAC-SHA256&X-Sup-Credential=foo%2F19700101&X-Sup-Date=19700101T000000Z&X-Sup-Expires=600&X-Sup-Proxy=https%3A%2F%2Fgithub.com%2F&X-Sup-SignedHeaders=Host&X-Sup-Signature=1fdc94423fff3f3626e2aa31c8a34c360e63f5906d84f14888a8c7c1bd1b00ad"
        )
    }
}
