# Cloudflare setup — step by step

This guide deploys **two** Workers from one `wrangler.toml` — a dev/sandbox Worker
and a production Worker — and wires your app so each build type talks to the
right one.

| Worker | Deploy command | `APPATTEST_ENV` | App Attest env | Used by app build |
|---|---|---|---|---|
| `<yourapp>-proxy-dev` | `npx wrangler deploy` | `development` | sandbox | **Debug** (dev entitlements) |
| `<yourapp>-proxy` | `npx wrangler deploy --env production` | `production` | production | **Release / AppStore** (prod entitlements) |

> **The golden rule:** a build's `appattest-environment` entitlement and the
> Worker's `APPATTEST_ENV` **must match**. The entitlement decides which App Attest
> environment the device uses (and therefore the `aaguid` it sends); the Worker
> validates against that `aaguid`. Mismatch ⇒ `aaguid mismatch` at registration.

**Prerequisites:** Node.js 18+ and npm, plus your Apple **Team ID** + **bundle id**
(find your Team ID at https://developer.apple.com/account → Membership; App ID =
`<TeamID>.<bundle id>`).

---

## 1. Copy this folder into your app

Copy `server/` out of `SDXCloudflare` into your own app repo (or a private ops
repo) — it's a template, not a shared dependency, since every app needs its own
Cloudflare account resources.

## 2. Install dependencies

```bash
cd server
npm install
```

Wrangler (Cloudflare's CLI) installs locally, so every command below uses
`npx wrangler …`.

## 3. Log in

```bash
npx wrangler login      # authorize in the browser
npx wrangler whoami     # confirm the right account
```

## 4. Create the KV namespaces (one per environment)

Each environment gets its own KV namespace so dev and prod device records,
challenges, and counters stay isolated.

```bash
# Dev namespace (+ a preview namespace for `wrangler dev`):
npx wrangler kv namespace create PROXY_KV
npx wrangler kv namespace create PROXY_KV --preview
# Production namespace:
npx wrangler kv namespace create PROXY_KV_PROD
```

Paste the printed ids into [`wrangler.toml`](wrangler.toml):
- dev `id` / `preview_id` → the top-level `[[kv_namespaces]]`
- prod `id` → `[[env.production.kv_namespaces]]`

## 5. Fill in the vars in `wrangler.toml`

Named environments **do not inherit** `[vars]`/`[[kv_namespaces]]`, so both blocks
are spelled out. Replace every `REPLACE_WITH_*` placeholder:

```toml
# default (dev)                              |  [env.production]
APP_ID = "<TeamID>.<bundle id>"               # same in both
APPATTEST_ENV = "development"                 # dev   → sandbox
APPATTEST_ENV = "production"                  # prod  → production
```

## 6. Set the secrets (per environment)

Secrets are scoped to each Worker, so set the upstream API key **twice**:

```bash
npx wrangler secret put OPENAI_API_KEY                   # dev worker
npx wrangler secret put OPENAI_API_KEY --env production  # prod worker
```

Optional dev-only bypass so the **Simulator** (no App Attest) can reach the dev
Worker — set it only on the dev (non-production) Worker, and make it a random
opaque string, not anything shaped like a real API key:

```bash
openssl rand -hex 32                      # generate a random token
npx wrangler secret put DEV_BYPASS_TOKEN  # paste it in — dev worker only
```

If you enable Authenticated Gateway (step 7a), you'll also set `AI_GATEWAY_TOKEN`
on both Workers.

## 7. (Recommended) Cloudflare AI Gateway

AI Gateway gives rate-limiting, caching, and spend analytics, and hides the key
further.

1. Dashboard → **AI → AI Gateway → Create Gateway**.
2. Copy its OpenAI endpoint:
   `https://gateway.ai.cloudflare.com/v1/<account_id>/<gateway>/openai`
3. Put it in `OPENAI_BASE_URL` in **both** the dev and `[env.production]` blocks of
   `wrangler.toml`. To skip AI Gateway, leave `OPENAI_BASE_URL = "https://api.openai.com"`.

### 7a. Authenticated Gateway (recommended)

By default a gateway is open to anyone who knows its URL. Lock it down so only this
Worker can use it:

1. AI Gateway → your gateway → **Settings** → enable **Authenticated Gateway**.
2. Create an **authorization token** (in that settings panel) and copy it.
3. Set it as a Worker secret on **both** environments — the Worker sends it as the
   `cf-aig-authorization` header:
   ```bash
   npx wrangler secret put AI_GATEWAY_TOKEN                   # dev worker
   npx wrangler secret put AI_GATEWAY_TOKEN --env production  # prod worker
   ```

> If Authenticated Gateway is **off**, skip this — the Worker simply omits the
> header. If it's **on** but the secret is missing, the gateway returns
> `AiGatewayError ... "Unauthorized"` (code 2009).

## 8. Deploy both Workers

```bash
npx wrangler deploy                   # → <yourapp>-proxy-dev  (development)
npx wrangler deploy --env production  # → <yourapp>-proxy      (production)
```

Each prints its URL, e.g. `https://<yourapp>-proxy-dev.<sub>.workers.dev` and
`https://<yourapp>-proxy.<sub>.workers.dev`.

## 9. Smoke-test

```bash
curl -s -X POST https://<yourapp>-proxy-dev.<sub>.workers.dev/attest/challenge
#   → {"challenge":"…"}
curl -s -X POST https://<yourapp>-proxy.<sub>.workers.dev/v1/responses -d '{}'
#   → {"error":"Missing App Attest headers"}   (HTTP 401)
```

## 10. Wire the app

- **Per-build entitlements** select the App Attest environment (development vs.
  production), wired via `CODE_SIGN_ENTITLEMENTS` per build configuration.
- **Per-build URL**, using `SDXProxyConfiguration(proxyBaseURL:)`:
  ```swift
  #if DEBUG
  static let proxyBaseURL = URL(string: "https://<yourapp>-proxy-dev.<sub>.workers.dev")!
  #else
  static let proxyBaseURL = URL(string: "https://<yourapp>-proxy.<sub>.workers.dev")!
  #endif
  ```
- Enable the **App Attest** capability for your app target (Signing &
  Capabilities → + Capability → App Attest). The entitlement value comes from the
  per-configuration entitlements file above; no provisioning-profile change needed.
- For the Simulator dev path, set `devBypassToken` (in `SDXProxyConfiguration`) to
  the same string you passed to `wrangler secret put DEV_BYPASS_TOKEN`.

## 11. Verify end to end (real device)

App Attest only runs on real hardware.

1. **Switching a device between environments?** Delete & reinstall the app first —
   an App Attest key is bound to the environment it was created in, so a device that
   registered under one env must generate a fresh key for the other. A clean install
   forces re-registration.
2. Run the Debug build on a physical device, trigger a proxied request. First call
   registers (`/attest/register`), then proxies.
3. Tail logs while testing:
   ```bash
   npx wrangler tail                   # dev worker
   npx wrangler tail --env production  # prod worker
   ```

## Day-2 operations

- **Kill switch:** set `KILL_SWITCH = "1"` in the relevant block and redeploy that
  env — all proxy traffic returns 503.
- **Spend / rate limits:** AI Gateway dashboard; plus the per-device daily cap
  (`DAILY_REQUEST_CAP`).
- **Rotate the upstream key:** `npx wrangler secret put OPENAI_API_KEY [--env production]`
  — no app update needed.
- **Logs:** `npx wrangler tail [--env production]`.

## Troubleshooting

- **`aaguid mismatch: device sent "X", server expects "Y" env`** — the build's
  entitlement and the Worker's `APPATTEST_ENV` disagree. Align them (Debug ⇄
  `development`/dev Worker; Release/AppStore ⇄ `production`/prod Worker) and, if the
  device already registered under the other env, delete & reinstall the app.
- **`Device not registered`** — registration never completed for this `keyId`;
  reinstall to re-register.
- **`AiGatewayError ... "Unauthorized"` (code 2009)** — AI Gateway has Authenticated
  Gateway enabled but the Worker isn't sending the token. Set `AI_GATEWAY_TOKEN` on
  both Workers (step 7a), or disable Authenticated Gateway in the gateway settings.
- **`tsyringe requires a reflect polyfill`** on deploy — ensure
  `import 'reflect-metadata'` is the first import (already done in `src/index.ts` and
  `src/appattest.ts`) and `reflect-metadata` is in `dependencies`.
