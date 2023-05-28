use std::collections::HashMap;
use std::ops::Add;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use hyper::http::HeaderName;
use hyper::{HeaderMap, Request};
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::signing;

pub struct SignRequest {
    pub url: Url,
    pub expiry: u32,
    pub datetime: OffsetDateTime,
    pub method: String,
    pub headers: Option<HeaderMap>,
    pub queries: Option<HashMap<String, String>>,
    pub body: Option<String>,
}

pub struct SignInfo {
    pub signature: String,
    pub id: String,
    pub proxy_url: Url,
    pub include_body: bool,
}

impl SignRequest {
    pub fn from_req<T>(req: &Request<T>) -> Result<(Self, SignInfo)> {
        let url = Url::parse(&req.uri().to_string())?;

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
                signing::X_ALGORITHM => x_algorithm = Some(v.to_string()),
                signing::X_CREDENTIAL => x_credential = Some(v.to_string()),
                signing::X_EXPIRES => x_expires = Some(v.to_string()),
                signing::X_DATE => x_date = Some(v.to_string()),
                signing::X_SIGNED_HEADERS => x_signed_headers = Some(v.to_string()),
                signing::X_PROXY => x_proxy = Some(v.to_string()),
                signing::X_SIGNED_BODY => x_signed_body = Some(&v == "true"),
                signing::X_SIGNATURE => x_signature = Some(v.to_string()),
                _ => {}
            }
        }

        let datetime = x_date.ok_or_else(|| anyhow!("missing {}", signing::X_DATE))?;
        let datetime = OffsetDateTime::parse(&datetime, signing::LONG_DATETIME)?;

        let expiry = x_expires.ok_or_else(|| anyhow!("missing {}", signing::X_EXPIRES))?;
        let expiry =
            u32::from_str(&expiry).map_err(|_| anyhow!("invalid {}", signing::X_EXPIRES))?;

        let now = OffsetDateTime::now_utc();
        let expiry_datetime = datetime.add(Duration::seconds(expiry as i64));
        if now.gt(&expiry_datetime) {
            return Err(anyhow!("Request has expired"));
        }

        let signed_headers =
            x_signed_headers.ok_or_else(|| anyhow!("missing {}", signing::X_SIGNED_HEADERS))?;

        let mut headers = HeaderMap::new();
        // TODO: where does this come from
        for header in signed_headers.split(';') {
            let value = req.headers().get(header).ok_or_else(|| {
                anyhow!("header {header} should be signed but it is missing in the request")
            })?;
            headers.insert(HeaderName::try_from(header.to_string())?, value.clone());
        }

        let signing_request = SignRequest {
            url: Url::parse(&x_proxy.ok_or_else(|| anyhow!("missing {}", signing::X_PROXY))?)?,
            expiry,
            datetime,
            method: req.method().to_string(),
            headers: Some(headers),
            queries: None,
            body: None,
        };

        let credential =
            x_credential.ok_or_else(|| anyhow!("missing {}", signing::X_CREDENTIAL))?;
        let credential_parts = credential.split('/'); // TODO: where does this come from
        let id = credential_parts
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("invalid {}", signing::X_CREDENTIAL))?;

        let signing_info = SignInfo {
            signature: x_signature.ok_or_else(|| anyhow!("missing {}", signing::X_SIGNATURE))?,
            id: id.to_string(),
            proxy_url: signing_request.url.clone(),
            include_body: x_signed_body
                .ok_or_else(|| anyhow!("missing {}", signing::X_SIGNED_BODY))?,
        };

        Ok((signing_request, signing_info))
    }
}
