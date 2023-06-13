# What is Signway?

Signway is a server that proxies authentic pre-signed requests to the specified
destination, adding the appropriate authentication headers if necessary.

## What does it do?

It was initially designed for working with APIs that stream their response, like
[OpenAI's ChatGPT API](https://platform.openai.com/docs/guides/gpt). 

The problem starts when the backend that queries
OpenAI's API wants to re-stream the response back to the frontend, sending
the data progressively chunk by chunk as it comes. This can get tricky or 
be even be impossible depending on the backend's stack.

Instead of re-streaming the response from backend to frontend, why not let the
frontend do the request to OpenAI itself? without Signway, the answer is simple:

because OpenAI's key would be leaked.

Signway proposes the following solution:
- In the backend, instead of querying OpenAI's API, create a pre-signed URL with
a short expiration time.
- Send the pre-signed URL back to the frontend.
- Let the frontend do the request itself to OpenAI using that pre-signed URL before it
expires.
- The request will pass through Signway, who will verify that the signature is 
authentic and has not expired, and if successful, it will proxy the request
to OpenAI's API, adding the authentication header if necessary.

With this, the frontend can query OpenAI's API passing through Signway, and it
will be almost like a direct request to OpenAI. 

## What can be used for?

Not only OpenAI's API, but almost any API. Signway is a fast gateway written
in Rust, designed specifically for high throughput, so it can be used for leveraging
any heavy IO task.
