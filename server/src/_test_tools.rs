#[cfg(test)]
pub(crate) mod tests {
    use hyper::Request;
    use std::collections::HashMap;
    use std::error::Error;
    use std::str::FromStr;

    use anyhow::{anyhow, Context};
    use async_trait::async_trait;
    use http_body_util::Full;
    use hyper::header::HeaderName;
    use hyper::{HeaderMap, Response, StatusCode, Uri};
    use serde::de::DeserializeOwned;
    use time::{OffsetDateTime, PrimitiveDateTime};
    use url::Url;

    use crate::signing::{ElementsToSign, UrlSigner};
    use crate::sw_body::{empty, sw_body_from_str, SwBody};
    use crate::{GetSecretResponse, SecretGetter, SecretGetterResult};

    #[derive(Clone, Debug)]
    pub(crate) struct ReqBuilder<'a> {
        method: String,
        query_params: HashMap<String, String>,
        headers: HashMap<String, String>,
        body: Option<&'a str>,
        url: String,
        expiry: u32,
    }

    impl<'a> Default for ReqBuilder<'a> {
        fn default() -> Self {
            ReqBuilder {
                method: "GET".to_string(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: None,
                url: "https://postman-echo.com/get".to_string(),
                expiry: 10,
            }
        }
    }

    impl<'a> ReqBuilder<'a> {
        pub(crate) fn query(mut self, k: &str, v: &str) -> Self {
            self.query_params.insert(k.to_string(), v.to_string());
            self
        }
        pub(crate) fn header(mut self, k: &str, v: &str) -> Self {
            self.headers.insert(k.to_string(), v.to_string());
            self
        }

        fn build_uri(&self) -> anyhow::Result<Uri> {
            let mut path_params = "".to_string();
            for (k, v) in self.query_params.iter() {
                path_params += &format!("&{k}={v}");
            }
            if !path_params.is_empty() {
                path_params = "?".to_string() + path_params.strip_prefix('&').unwrap()
            }
            Ok(Uri::try_from(self.url.clone() + &path_params)?)
        }

        fn build_headers(&self) -> anyhow::Result<Option<HeaderMap>> {
            let mut header_map = HeaderMap::new();
            for (k, v) in self.headers.iter() {
                header_map.insert(HeaderName::try_from(k)?, v.parse()?);
            }
            if header_map.is_empty() {
                Ok(None)
            } else {
                Ok(Some(header_map))
            }
        }

        pub(crate) fn build(self) -> anyhow::Result<Request<SwBody<'a>>> {
            let body = match self.body {
                Some(b) => sw_body_from_str(b),
                None => empty(),
            };

            let mut builder = Request::builder();

            for (k, v) in self.headers.iter() {
                builder = builder.header(k, v);
            }

            Ok(builder
                .uri(self.build_uri()?)
                .method(self.method.as_str())
                .body(body)?)
        }

        pub(crate) fn sign(mut self, id: &str, secret: &str, host: &str) -> anyhow::Result<Self> {
            let now = OffsetDateTime::now_utc();
            let sign_request = ElementsToSign {
                proxy_url: Url::parse(&self.build_uri()?.to_string())?,
                expiry: self.expiry,
                datetime: PrimitiveDateTime::new(now.date(), now.time()),
                method: self.method.clone(),
                headers: self.build_headers()?,
                body: self.body.map(|e| e.to_string()),
            };

            let signer = UrlSigner::new(id, secret);
            let signed = signer.get_signed_url(host, &sign_request)?;

            let signed_url = Url::parse(&signed)?;

            self.url = signed_url.scheme().to_string()
                + "://"
                + &signed_url.host().unwrap().to_string()
                + signed_url.path();
            self.query_params = HashMap::new();
            for (k, v) in signed_url.query_pairs() {
                self.query_params.insert(k.to_string(), v.to_string());
            }

            Ok(self)
        }

        pub(crate) fn post(mut self) -> Self {
            self.method = "POST".to_string();
            self.url = "https://postman-echo.com/post".to_string();
            self
        }

        pub(crate) fn body(mut self, v: &str) -> Self {
            self.body = Some(v);
            self
        }
    }

    pub(crate) fn json_path<T: DeserializeOwned>(
        response: &str,
        path: &[&str],
    ) -> anyhow::Result<T> {
        let mut value = &serde_json::from_str::<serde_json::Value>(response)?;
        for p in path {
            if let Ok(index) = usize::from_str(p) {
                value = value
                    .get(index)
                    .context(anyhow!("'{}' field not found while deserializing", p))?;
            } else {
                value = value
                    .get(p)
                    .context(anyhow!("'{}' field not found while deserializing", p))?;
            }
        }
        Ok(serde_json::from_value::<T>(value.clone())?)
    }

    pub(crate) struct InMemorySecretGetter(pub(crate) HashMap<String, SecretGetterResult>);

    #[async_trait]
    impl SecretGetter for InMemorySecretGetter {
        async fn get_secret<'a>(&self, id: &str) -> Result<GetSecretResponse<'a>, Box<dyn Error>> {
            let secret = match self.0.get(id).cloned() {
                Some(a) => a,
                None => {
                    return Ok(GetSecretResponse::EarlyResponse(
                        Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .body(Full::default())
                            .unwrap(),
                    ));
                }
            };

            Ok(GetSecretResponse::Secret(secret))
        }
    }
}
