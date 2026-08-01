# SDXCloudflare

A reusable pattern for keeping a third-party API key (OpenAI, etc.) off the client and out of the
app binary: a Cloudflare Worker holds the real key server-side, and the app authenticates to the
Worker per-request using Apple App Attest — Secure Enclave key attestation plus signed, replay-proof
assertions — instead of shipping any static credential.

This repo has two halves that are reused very differently:

## `Sources/SDXCloudflare` — a real Swift Package dependency

Add this folder as a local Swift Package dependency (`File → Add Package Dependencies… → Add
Local…` in Xcode) to any app that needs to call a proxied API. It gives you:

```swift
let client = SDXProxyClient(configuration: .init(proxyBaseURL: URL(string: "https://your-proxy.workers.dev")!))
let responseData = try await client.responses(body: requestBodyJSON)
```

`SDXProxyClient` transparently registers a Secure Enclave key on first use, attests it with Apple,
and signs every subsequent request — the calling app never sees or handles the upstream API key.

Import it once, configure it with your deployed Worker's URL, and use `send(path:body:)` (generic)
or `responses(body:)` (sugar for an OpenAI-Responses-API-shaped proxy) in place of a direct
`URLSession` call to the third-party API.

## `server/` — a Worker *template*, not a package

Workers aren't distributed via Swift Package Manager, and every app needs its own Cloudflare
account resources (KV namespace IDs, Worker names, Apple App ID). So `server/` is not "installed" —
it's copied out of this repo into a new app-specific location (or forked on a branch) and
customized:

1. Copy `server/` into your own project (or a private ops repo).
2. Fill in the placeholders in `server/wrangler.toml` (`REPLACE_WITH_...` values) — see
   `server/SETUP.md` for the exact commands.
3. Deploy with `wrangler deploy` (dev) and `wrangler deploy --env production`.

The TypeScript source (`src/index.ts`, `src/appattest.ts`, `src/appleRoot.ts`, `src/util.ts`) is
app-agnostic — the only per-app values are in `wrangler.toml` (`APP_ID`, KV namespace IDs, Worker
names) and Worker secrets (`OPENAI_API_KEY`, `DEV_BYPASS_TOKEN`), never in source.

## How the two halves agree with each other

Both sides default to the same header names (`X-Proxy-Key-Id`, `X-Proxy-Assertion`,
`X-Proxy-Client-Data`, `X-Proxy-Dev-Token`), the same KV binding name (`PROXY_KV`), and the same
default paths (`attest/challenge`, `attest/register`, `v1/responses`). Change these only if you
need two independent SDXCloudflare-based proxies to coexist inside one app — `SDXProxyConfiguration`
exposes them as overridable, but the shared defaults are what let the Swift client and the Worker
template be dropped into a new app together with zero wiring.
