use hyper::{Body, Request};

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;

    use hyper::header::HeaderName;
    use hyper::{HeaderMap, Uri};
    use time::{OffsetDateTime, PrimitiveDateTime};
    use url::Url;

    use crate::signing::{SignRequest, UrlSigner};

    use super::*;

    #[derive(Clone, Debug)]
    pub struct ReqBuilder {
        method: String,
        query_params: HashMap<String, String>,
        headers: HashMap<String, String>,
        body: Option<String>,
        url: String,
        expiry: u32,
    }

    impl Default for ReqBuilder {
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

    impl ReqBuilder {
        pub fn query(mut self, k: &str, v: &str) -> Self {
            self.query_params.insert(k.to_string(), v.to_string());
            self
        }
        pub fn header(mut self, k: &str, v: &str) -> Self {
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

        pub fn build(&self) -> anyhow::Result<Request<Body>> {
            let body = match &self.body {
                Some(b) => Body::from(b.to_string()),
                None => Body::empty(),
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

        pub fn sign(mut self, id: &str, secret: &str, host: &str) -> anyhow::Result<Self> {
            let now = OffsetDateTime::now_utc();
            let sign_request = SignRequest {
                proxy_url: Url::parse(&self.build_uri()?.to_string())?,
                expiry: self.expiry,
                datetime: PrimitiveDateTime::new(now.date(), now.time()),
                method: self.method.clone(),
                headers: self.build_headers()?,
                queries: None,
                body: self.body.clone(),
            };

            let signer = UrlSigner::new(id, secret, Url::parse(host)?);
            let signed = signer.get_signed_url(&sign_request)?;

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

        pub fn method(mut self, v: &str) -> Self {
            self.method = v.to_string();
            self
        }
    }
}
