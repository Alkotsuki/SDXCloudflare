# SDXCloudflare proxy Worker (template)

Holds a **single shared upstream API key** (e.g. OpenAI) server-side and forwards
requests from your app to `/v1/responses`. The app ships with **no** upstream
credentials; each request is authenticated with **Apple App Attest** so only
genuine, unmodified copies of the app on real devices can use the key.

```
app ──App Attest assertion──▶ Worker ──Bearer <shared key>──▶ upstream (/v1/responses)
                                │                             (optionally via AI Gateway)
                                └── KV: device public keys, one-time challenges, daily counters
```

Streaming (SSE) and any response-chaining tool calls pass through unchanged — the
Worker forwards the request body verbatim and streams the response body back
as-is.

This folder is a **template**, not a package — copy it into your app (or a
private ops repo) and customize `wrangler.toml` for your own Cloudflare account,
KV namespaces, and Apple App ID. See [SETUP.md](SETUP.md).

## Two environments

One `wrangler.toml` deploys **two** Workers — a dev/sandbox one and a production
one — each with its own KV namespace, vars, and secrets:

| Worker | Deploy | `APPATTEST_ENV` | App Attest env | App build |
|---|---|---|---|---|
| `<yourapp>-proxy-dev` | `npx wrangler deploy` | `development` | sandbox | Debug (dev entitlements) |
| `<yourapp>-proxy` | `npx wrangler deploy --env production` | `production` | production | Release/AppStore (prod entitlements) |

A build's `appattest-environment` entitlement and the Worker's `APPATTEST_ENV`
**must match** (the app picks the matching Worker URL via `#if DEBUG`).

## Endpoints

| Method | Path                 | Purpose |
|--------|----------------------|---------|
| POST   | `/attest/challenge`  | Issue a one-time challenge (5-min TTL). |
| POST   | `/attest/register`   | Verify an App Attest attestation; store the device's public key. Once per install. |
| POST   | `/v1/responses`      | Verify the per-request assertion, then proxy upstream. |

## Security model

- **Attestation (once/install):** validates the Apple cert chain to the
  [App Attest Root CA](src/appleRoot.ts), the nonce
  `SHA256(authData ‖ SHA256(challenge))`, the App ID (`rpIdHash`), the
  environment `aaguid`, and that `keyId == SHA256(publicKey)`. Stores the EC P-256
  public key + initial counter in KV.
- **Assertion (every request):** verifies the ECDSA signature with the stored key,
  the App ID, a strictly-increasing counter (replay protection), a consumed
  one-time challenge, and that `bodySHA256` in the signed client data matches the
  body actually forwarded upstream (request binding).
- **Abuse caps:** a coarse per-device daily request cap in KV, plus a global
  `KILL_SWITCH`. Put a **Cloudflare AI Gateway** endpoint in `OPENAI_BASE_URL` for
  real rate-limiting, caching, and spend analytics in front of the upstream API.

## Setup & deploy

See **[SETUP.md](SETUP.md)** for the full step-by-step guide.

The short version:

```bash
cd server
npm install
npx wrangler login
npx wrangler kv namespace create PROXY_KV           # dev id  → wrangler.toml
npx wrangler kv namespace create PROXY_KV --preview  # preview_id → wrangler.toml
npx wrangler kv namespace create PROXY_KV_PROD       # prod id → [env.production]

npx wrangler secret put OPENAI_API_KEY                   # dev worker
npx wrangler secret put OPENAI_API_KEY --env production  # prod worker

npx wrangler deploy                   # <yourapp>-proxy-dev
npx wrangler deploy --env production  # <yourapp>-proxy
```

Then point your app at the printed URLs (see the Swift package's own README for
the client side).

## Dev / Simulator

App Attest does not work in the Simulator. For a **non-production** deployment
(`APPATTEST_ENV != "production"`) the Worker accepts requests carrying
`X-Proxy-Dev-Token: <DEV_BYPASS_TOKEN>` and skips attestation. Never set
`DEV_BYPASS_TOKEN` on the production Worker.

## Notes / limitations

- KV is eventually consistent and not transactional, so the daily counter and the
  assertion counter update are best-effort under high concurrency. The
  strictly-increasing assertion counter still blocks straightforward replays; use
  a Durable Object per `keyId` if you need hard serialization.
- `compatibility_flags = ["nodejs_compat"]` is required (the CBOR/X.509 libraries
  rely on it).
