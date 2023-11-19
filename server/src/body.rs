use anyhow::{anyhow, Result};
use http_body_util::BodyExt;
use hyper::body::Body;

pub(crate) async fn body_to_string<B: Body>(body: impl Into<B>, length: usize) -> Result<String> {
    let mut data = vec![];
    for chunk in body.into().collect().await {
        data.extend_from_slice(chunk.to_bytes().as_ref());
        if data.len() > length {
            return Err(anyhow!("too big"));
        }
    }
    Ok(String::from_utf8(data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use hyper::body::Bytes;

    #[tokio::test]
    async fn converts_from_string_to_body_and_back() {
        let result = body_to_string::<Full<Bytes>>("foo", 3).await.unwrap();
        assert_eq!(result, "foo")
    }

    #[tokio::test]
    async fn fails_to_read_long_body() {
        let err = body_to_string::<Full<Bytes>>("foo", 2).await.unwrap_err();
        assert_eq!(err.to_string(), "too big")
    }

    #[tokio::test]
    async fn works_with_a_really_long_body() {
        let len = 1e8 as usize;

        body_to_string::<Full<Bytes>>("a", len).await.unwrap();
    }
}
