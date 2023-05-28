use std::collections::HashMap;
use std::fmt::Write as _;
use std::str;

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use time::{macros::format_description, OffsetDateTime};
use url::Url;

use axum::http::HeaderMap;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

const LONG_DATETIME: &[time::format_description::FormatItem<'static>] =
    format_description!("[year][month][day]T[hour][minute][second]Z");

const SHORT_DATE: &[time::format_description::FormatItem<'static>] =
    format_description!("[year][month][day]");

type HmacSha256 = Hmac<Sha256>;

// https://perishablepress.com/stop-using-unsafe-characters-in-urls/
const FRAGMENT: &AsciiSet = &CONTROLS
    // URL_RESERVED
    .add(b':')
    .add(b'?')
    .add(b'#')
    .add(b'[')
    .add(b']')
    .add(b'@')
    .add(b'!')
    .add(b'$')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b';')
    .add(b'=')
    // URL_UNSAFE
    .add(b'"')
    .add(b' ')
    .add(b'<')
    .add(b'>')
    .add(b'%')
    .add(b'{')
    .add(b'}')
    .add(b'|')
    .add(b'\\')
    .add(b'^')
    .add(b'`');

const FRAGMENT_SLASH: &AsciiSet = &FRAGMENT.add(b'/');

const X_ALGORITHM: &str = "X-Sup-Algorithm";
const ALGORITHM: &str = "SUP1-HMAC-SHA256";
const X_CREDENTIAL: &str = "X-Sup-Credential";
const X_DATE: &str = "X-Sup-Date";
const X_EXPIRES: &str = "X-Sup-Expires";
const X_SIGNED_HEADERS: &str = "X-Sup-SignedHeaders";
pub const X_PROXY: &str = "X-Sup-Proxy";
pub const HOST: &str = "Host";

pub fn canonical_uri_string(uri: &Url) -> String {
    let decoded = percent_encoding::percent_decode_str(uri.path()).decode_utf8_lossy();
    utf8_percent_encode(&decoded, FRAGMENT).to_string()
}

pub fn canonical_query_string(uri: &Url) -> String {
    let mut params: Vec<(String, String)> = uri
        .query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    params.sort();
    let params: Vec<String> = params
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                utf8_percent_encode(k, FRAGMENT_SLASH),
                utf8_percent_encode(v, FRAGMENT_SLASH)
            )
        })
        .collect();
    params.join("&")
}

pub fn canonical_header_string(headers: &HeaderMap) -> String {
    let mut keyvalues = headers
        .iter()
        .map(|(key, value)| key.as_str().to_lowercase() + ":" + value.to_str().unwrap().trim())
        .collect::<Vec<String>>();
    keyvalues.sort();
    keyvalues.join("\n")
}

pub fn signed_header_string(headers: &HeaderMap) -> String {
    let mut keys = headers
        .keys()
        .map(|key| key.as_str().to_lowercase())
        .collect::<Vec<String>>();
    keys.sort();
    keys.join(";")
}

pub fn canonical_request(method: &str, url: &Url, headers: &HeaderMap, body: &str) -> String {
    format!(
        "{method}\n{uri}\n{query_string}\n{headers}\n\n{signed}\n{body}",
        uri = canonical_uri_string(url),
        query_string = canonical_query_string(url),
        headers = canonical_header_string(headers),
        signed = signed_header_string(headers),
    )
}

pub fn scope_string(datetime: &OffsetDateTime) -> String {
    datetime.format(SHORT_DATE).unwrap()
}

pub fn string_to_sign(datetime: &OffsetDateTime, canonical_req: &str) -> String {
    let mut hasher = Sha256::default();
    hasher.update(canonical_req.as_bytes());
    format!(
        "{ALGORITHM}\n{timestamp}\n{scope}\n{hash}",
        timestamp = datetime.format(LONG_DATETIME).unwrap(),
        scope = scope_string(datetime),
        hash = hex::encode(hasher.finalize().as_slice())
    )
}

pub fn signing_key(datetime: &OffsetDateTime, secret_key: &str) -> Result<Vec<u8>> {
    let secret = format!("{ALGORITHM}{secret_key}");
    let mut date_hmac = HmacSha256::new_from_slice(secret.as_bytes())?;
    date_hmac.update(datetime.format(SHORT_DATE).unwrap().as_bytes());
    Ok(date_hmac.finalize().into_bytes().to_vec())
}

pub fn authorization_query_params_no_sig(
    access_key: &str,
    datetime: &OffsetDateTime,
    expires: u32,
    proxy_url: &Url,
    custom_headers: Option<&HeaderMap>,
) -> Result<String> {
    let credentials = format!("{}/{}", access_key, scope_string(datetime));

    let mut signed_headers = vec![HOST.to_string()];
    if let Some(custom_headers) = &custom_headers {
        for k in custom_headers.keys() {
            signed_headers.push(k.to_string())
        }
    }
    let signed_headers = signed_headers.join(";");

    let proxy_url = proxy_url.scheme().to_string()
        + "://"
        + &proxy_url
            .host()
            .ok_or_else(|| anyhow!("Invalid host in url"))?
            .to_string()
        + proxy_url.path();

    let credentials = utf8_percent_encode(&credentials, FRAGMENT_SLASH);
    let signed_headers = utf8_percent_encode(&signed_headers, FRAGMENT_SLASH);
    let proxy_url = utf8_percent_encode(&proxy_url, FRAGMENT_SLASH);
    let long_date = datetime.format(LONG_DATETIME).unwrap();

    Ok(format!(
        "?{X_ALGORITHM}={ALGORITHM}\
            &{X_CREDENTIAL}={credentials}\
            &{X_DATE}={long_date}\
            &{X_EXPIRES}={expires}\
            &{X_PROXY}={proxy_url}\
            &{X_SIGNED_HEADERS}={signed_headers}",
    ))
}

pub fn flatten_queries(queries: Option<&HashMap<String, String>>) -> String {
    match queries {
        None => String::new(),
        Some(queries) => {
            let mut query_str = String::new();
            for (k, v) in queries {
                write!(
                    query_str,
                    "&{}={}",
                    utf8_percent_encode(k, FRAGMENT_SLASH),
                    utf8_percent_encode(v, FRAGMENT_SLASH),
                )
                .unwrap();
            }
            query_str
        }
    }
}
