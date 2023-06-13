# Using Signway with OpenAI's API

This example will use Signway's Python SDK for creating signed URLs, and will use
Signway's docker image for proxying the verified signed requests to OpenAI's api,
so you will need:
- [Python +3.9](https://www.python.org/downloads/) or greater installed in you system
- [Docker](https://docs.docker.com/engine/install/) installed in your system
- An [OpenAI's Api key](https://platform.openai.com/account/api-keys)

## Choose an `id` and a `secret` for configuring Signway

```bash
export SW_ID="app-id"
export SW_SECRET="super-secure-string"
```

You don't need to necessarily use this values, but if you want to just copy-paste those
that's fine.

Don't forget to also export your OpenAI api key, this should be a valid OpenAI key for
this example to work.

```bash
export OPENAI_TOKEN="your valid openai api key goes here"
```

## Launching the Signway server

Open a terminal and launch the Signway server:

```bash
docker run -p 3000:3000 gabotechs/signway $SW_ID $SW_SECRET \
 --header "Authorization: Bearer $OPENAI_TOKEN"
```

This Signway server will only accept requests correctly signed using `$SW_ID` and `$SW_SECRET`.

## Creating a signed URL using the Python SDK

Create a new virtual environment and install the Python SDK:

```bash
python3 -m venv venv
source venv/bin/activate
pip install signway-sdk
```

Remember to also export here the same `id` and `secret` from before:

```bash
export SW_ID="app-id"
export SW_SECRET="super-secure-string"
```

Create a new Python file called `sign.py` and paste this content:

```python
# sign.py
from signway_sdk import sign_url
import os

print(sign_url(
    id=os.environ['SW_ID'],
    secret=os.environ['SW_SECRET'],
    host="http://localhost:3000",
    proxy_url="https://api.openai.com/v1/completions",
    expiry=10,
    method="POST"
))
```

Executing this script within the `venv` will output a URL that looks like this:

```bash
$ python sign.py

http://localhost:3000/?X-Sw-Algorithm=SW1-HMAC-SHA256&X-Sw-Credential=app-id%2F20230613&X-Sw-Date=20230613T162311Z&X-Sw-Expires=300&X-Sw-Proxy=https%3A%2F%2Fapi.openai.com%2Fv1%2Fchat%2Fcompletions&X-Sw-SignedHeaders=&X-Sw-Body=false&X-Sw-Signature=ebf9dcd8fb2f298af7744a0dbbc96b10d21b38f6e85292f1e06605873088f6e5
```

Note that the URL points to your Signway server running in the localhost, but it
has the `X-Sw-Proxy` query parameter set to `https://api.openai.com/v1/completions`.
This tells signway where should the request be proxy-ed.

## Querying Open AI


Now, try to make a request with `curl` as if you wanted to query directly OpenAI's API but
passing through Signway:

```bash
curl $(python sign.py) \
-H "Content-Type: application/json" \
-d '{"model": "text-davinci-003", "prompt": "Say this is a test"}'
```

If the `OPENAI_TOKEN` set while launching Signway is valid, you should have received an actual response
from OpenAI, and you didn't need to provide any token in the `curl` request. Signway added
it for you.

## Let the URL expire

Try this now, store the signed URL in an env variable:

```bash
export SIGNED_URL=$(python sign.py)
```

We configured the script to sign URLs with an expiration date of 10 seconds, so
wait 10 seconds and do the request again:

```bash
curl $SIGNED_URL \
-H "Content-Type: application/json" \
-d '{"model": "text-davinci-003", "prompt": "Say this is a test"}'
```

If you are quick copy-pasting this commands in a terminal, you may have seen
the request succeed, but after the configured 10s have passed, the request will be rejected.

## Sign more things

Right now, the `Content-Type` header and the body are not signed, so consumer of
the signed URL are allowed to do whatever they want with those things.

You can be more restrictive, and also sign both, so that users consuming the signed
URL are forced to pass the headers and the body that you want.

For that, edit the Python script:

```python
# sign.py
from signway_sdk import sign_url
import os

print(sign_url(
    id=os.environ['SW_ID'],
    secret=os.environ['SW_SECRET'],
    host="http://localhost:3000",
    proxy_url="https://api.openai.com/v1/completions",
    expiry=10,
    method="POST",
    headers={"Content-Type": "application/json"},
    body='{"model": "text-davinci-003", "prompt": "Say this is a test"}'
))
```

Now, try to make again the request with `curl`:

```bash
curl $(python sign.py) \
-H "Content-Type: application/json" \
-d '{"model": "text-davinci-003", "prompt": "Say this is a test"}'
```

That should work, as the provided header and body are the same that were declared in
the signature, but what if the body changes for example?

```bash
curl $(python sign.py) \
-H "Content-Type: application/json" \
-d '{"model": "text-davinci-003", "prompt": "Say this is NOT a test"}'
```

You will get rejected by Signway, as the body now is contributing to the URL's signature.
