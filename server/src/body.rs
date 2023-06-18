use anyhow::{anyhow, Result};
use hyper::body::HttpBody;
use hyper::Body;

pub(crate) async fn body_to_string(mut body: Body, length: usize) -> Result<String> {
    let mut data = vec![];

    let mut chunk = body.data().await;
    while chunk.is_some() {
        data.extend_from_slice(&chunk.unwrap()?);
        if data.len() > length {
            return Err(anyhow!("too big"));
        }
        chunk = body.data().await;
    }

    Ok(String::from_utf8(data)?)
}

pub(crate) fn string_to_body(str: &str) -> Body {
    Body::from(str.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn converts_from_string_to_body_and_back() {
        let body = string_to_body("foo");

        let result = body_to_string(body, 3).await.unwrap();
        assert_eq!(result, "foo")
    }

    #[tokio::test]
    async fn fails_to_read_long_body() {
        let body = string_to_body("foo");

        let err = body_to_string(body, 2).await.unwrap_err();
        assert_eq!(err.to_string(), "too big")
    }

    #[tokio::test]
    async fn works_with_a_really_long_body() {
        let len = 1e8 as usize;
        let body = string_to_body(&"a".repeat(len));

        body_to_string(body, len).await.unwrap();
    }
}
