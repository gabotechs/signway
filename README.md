# Signway

[![Coverage Status](https://coveralls.io/repos/github/gabotechs/signway/badge.svg)](https://coveralls.io/github/gabotechs/signway)

A gateway that proxies signed urls to other APIs.


## Config entry

```rust
struct Config {
    id: String,
    secret: String,
    extend_headers: HashMap<String, String>
}
```

- `id` is public, it will be publicly present in the signed URL.
- `secret` is private. It is used for creating the URL signature, so 
both server and signer proxy should now it.
- `extend_headers` is private. They will be automatically included in the
request made by signer proxy to the final API. It's only known to the
signer proxy.

## Signing a Request

```rust
use std::collections::HashMap;

struct SignRequest {
    id: String,
    secret: String,
    url: String,
    method: String,
    headers: Option<HashMap<String, String>>,
    body: Option<String>
}

impl SignRequest {
    fn example() -> Self {
        Self {
            id: "foo",
            method: "POST",
            secret: "super secret",
            url: "https://api.openai.com/v1/chat/completions",
            headers: Some(HashMap::from([
                ("Content-Type", "application/json")
            ])),
            body: Some("{
             \"model\": \"gpt-3.5-turbo\",
             \"messages\": [{\"role\": \"user\", \"content\": \"Say this is a test!\"}],
             \"temperature\": 0.7
           }")
        }
    }
}
```

1. Create The canonical request 
   ```
   POST
   https://api.openai.com/v1/chat/completions 
   X-Version=0&X-Id=foo%2F20230527&X-Date=20230527T134607Z&X-Expires=600&X-SignedHeaders=content-type
   content-type:application/json

   content-type
   {
     "model": "gpt-3.5-turbo",
     "messages": [{"role": "user", "content": "Say this is a test!"}],
     "temperature": 0.7
   }
   ```
2. Create The string that will ultimately be signed
   ```c
   0 // The algorithm version
   20230527T134607Z // The datetime when the request was issued
   20230527 // The date when the request was issued
   32869dfb8ae196fccf406b8f595d976625c2f7404e99056d6da2fb8644d24e06 // The signed canonical request (see above ^)
   ```
3. Create the signing key
   ```
   
   ```
