# SDXCloudflare

A reusable pattern for keeping a third-party API key (OpenAI, etc.) off the client and out of the
app binary: a Cloudflare Worker holds the real key server-side, and the app authenticates to the
Worker per-request with a Firebase App Check token instead of shipping any static credential.

This repo has two halves that are reused very differently:

## `Sources/SDXCloudflare` — a real Swift Package dependency

Add this folder as a local Swift Package dependency (`File → Add Package Dependencies… → Add
Local…` in Xcode) to any app that needs to call a proxied API. It gives you:

```swift
let client = SDXProxyClient(configuration: .init(proxyBaseURL: URL(string: "https://your-proxy.workers.dev")!))
let responseData = try await client.responses(body: requestBodyJSON)
```

`SDXProxyClient` attaches a Firebase App Check token to every request — the calling app never sees
or handles the upstream API key. The package depends on `FirebaseAppCheck`; the host app installs
the provider and configures Firebase once at launch:

```swift
#if DEBUG
let debugToken: String? = "<UUID registered once in Firebase console → App Check → Manage debug tokens>"
#else
let debugToken: String? = nil
#endif
AppCheck.setAppCheckProviderFactory(SDXAppCheckProviderFactory(debugToken: debugToken))
FirebaseApp.configure()
```

`SDXAppCheckProviderFactory` uses App Attest on devices and the debug token on the Simulator, so
every Simulator and teammate works without registering each one. Keep the debug token out of
Release builds: whoever has it can pass App Check.

**Upgrading from the App Attest version:** `challengePath`/`registerPath` and the App Attest error
cases are gone (`SDXProxyError.appCheckFailed` replaces them). The Worker still accepts App Attest,
so app versions already in the store keep working.

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

The TypeScript source (`src/*.ts`) is app-agnostic — the only per-app values are in
`wrangler.toml` (`FIREBASE_PROJECT_NUMBER`, legacy `APP_ID`, KV namespace IDs, Worker names) and
Worker secrets (`OPENAI_API_KEY`, `DEV_BYPASS_TOKEN`), never in source.

## How the two halves agree with each other

Both sides default to the same header names (`X-Firebase-AppCheck`, `X-Proxy-Install-Id`,
`X-Proxy-Dev-Token`), the same KV binding name (`PROXY_KV`), and the same default path
(`v1/responses`). Change these only if you
need two independent SDXCloudflare-based proxies to coexist inside one app — `SDXProxyConfiguration`
exposes them as overridable, but the shared defaults are what let the Swift client and the Worker
template be dropped into a new app together with zero wiring.
