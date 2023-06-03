use std::string::ToString;

use anyhow::Result;
use hmac::Hmac;
use hmac::Mac;
use hyper::{HeaderMap, Uri};
use sha2::Sha256;

use super::sign_request::SignRequest;
use crate::signing::signing_functions;

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct UrlSigner {
    id: String,
    secret: String,
}

impl UrlSigner {
    pub(crate) fn new(id: &str, secret: &str) -> Self {
        Self {
            id: id.to_string(),
            secret: secret.to_string(),
        }
    }

    fn url_no_signed(&self, req: &SignRequest) -> String {
        format!(
            "/{}",
            signing_functions::authorization_query_params_no_sig(
                &self.id,
                &req.datetime,
                req.expiry,
                &req.proxy_url,
                match &req.headers {
                    Some(headers) => Some(headers),
                    None => None,
                },
                req.body.is_some()
            )
        )
    }

    fn canonical_request(&self, req: &SignRequest) -> Result<String> {
        Ok(signing_functions::canonical_request(
            &req.method,
            &Uri::try_from(&self.url_no_signed(req))?,
            &req.headers.clone().unwrap_or(HeaderMap::new()),
            req.body.as_ref().unwrap_or(&String::new()),
        ))
    }

    pub(crate) fn get_signature(&self, req: &SignRequest) -> Result<String> {
        let canonical_request = self.canonical_request(req)?;
        let to_sign = signing_functions::string_to_sign(&req.datetime, &canonical_request);

        let signing_key = &signing_functions::signing_key(&req.datetime, &self.secret)?;
        let mut hmac = HmacSha256::new_from_slice(signing_key)?;
        hmac.update(to_sign.as_bytes());
        let signature = hex::encode(hmac.finalize().into_bytes());
        Ok(signature)
    }

    #[cfg(test)]
    pub(crate) fn get_signed_url(&self, host: &str, req: &SignRequest) -> Result<String> {
        Ok(format!(
            "{host}{}&{}={}",
            self.url_no_signed(req),
            signing_functions::X_SIGNATURE,
            self.get_signature(req)?
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::{OffsetDateTime, PrimitiveDateTime};
    use url::Url;

    fn base_request() -> SignRequest {
        let epoch = OffsetDateTime::UNIX_EPOCH;
        SignRequest {
            proxy_url: Url::parse("https://github.com").unwrap(),
            expiry: 600,
            datetime: PrimitiveDateTime::new(epoch.date(), epoch.time()),
            method: "POST".to_string(),
            headers: None,
            body: None,
        }
    }

    fn signer() -> UrlSigner {
        UrlSigner::new("foo", "secret")
    }

    #[test]
    fn creates_canonical_request() {
        let canonical_req = signer().canonical_request(&base_request());

        assert_eq!(
            canonical_req.unwrap(),
            "\
POST
/
X-Sw-Algorithm=SW1-HMAC-SHA256&X-Sw-Body=false&X-Sw-Credential=foo%2F19700101&X-Sw-Date=19700101T000000Z&X-Sw-Expires=600&X-Sw-Proxy=https%3A%2F%2Fgithub.com%2F&X-Sw-SignedHeaders=



",
        )
    }

    #[test]
    fn creates_the_non_signed_url() {
        let non_signed_url = signer().url_no_signed(&base_request());

        assert_eq!(
            non_signed_url,
            "/?X-Sw-Algorithm=SW1-HMAC-SHA256&X-Sw-Credential=foo%2F19700101&X-Sw-Date=19700101T000000Z&X-Sw-Expires=600&X-Sw-Proxy=https%3A%2F%2Fgithub.com%2F&X-Sw-SignedHeaders=&X-Sw-Body=false"
        )
    }

    #[test]
    fn creates_a_signed_authorization() {
        let signed_authorization = signer().get_signature(&base_request()).unwrap();

        assert_eq!(
            signed_authorization,
            "ed15db76d806155fd5119e093a0f030063c90d943dfdd27e011a9044a77a90a6"
        )
    }

    #[test]
    fn creates_a_signed_url() {
        let signed_url = signer()
            .get_signed_url("http://localhost:3000", &base_request())
            .unwrap();

        assert_eq!(
            signed_url,
            "http://localhost:3000/?X-Sw-Algorithm=SW1-HMAC-SHA256&X-Sw-Credential=foo%2F19700101&X-Sw-Date=19700101T000000Z&X-Sw-Expires=600&X-Sw-Proxy=https%3A%2F%2Fgithub.com%2F&X-Sw-SignedHeaders=&X-Sw-Body=false&X-Sw-Signature=ed15db76d806155fd5119e093a0f030063c90d943dfdd27e011a9044a77a90a6"
        )
    }
}
