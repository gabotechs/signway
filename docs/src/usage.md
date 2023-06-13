# Using Docker

Signway is meant to be used with [Docker](https://docs.docker.com/engine/install/), so if
you want to launch Signway locally for testing it, make sure you have it installed in
your machine https://docs.docker.com/engine/install.

# Running Signway

The image is publicly available, so you can run Signway with:

```bash
docker run gabotechs/signway "<my-id>" "<my-secret>"
```

`<my-id>`: you can choose pretty much whatever you want, as it is meant to
be public, so there is no need for extra security while storing this one.

`<my-secret>`: you want to choose a secure string. Think of this as a password,
you do not want other people to guess it. If you are using Signway in production, 
make sure to store this secret securely, as you will need it for creating URL signatures.

# Adding headers to the proxy-ed request

Imagine that you want to use Signway with OpenAI's API.

You do not want your users to
see your OpenAI's API key, but if they are the ones making the request through Signway...
then who sets the `Authorization: Bearer <openai-token>` header?

You can configure Signway to add that header automatically for you:

```bash
docker run gabotechs/signway <my-id> <my-secret> \
  --header "Authorization: Bearer <openai-token>"
```

Whenever anyone does a request through Signway, and the signature of that request
is authentic, an additional `Authorization: Bearer <openai-token>` header will be added
to the request.
