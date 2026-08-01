import Foundation

/// Everything `SDXProxyClient` needs to talk to a specific deployed Worker.
///
/// There is deliberately no App ID / bundle ID field here: App Attest scopes key generation and
/// attestation to the running app's own environment automatically, so the client never needs to
/// know or send it. Only the Worker (server-side) needs the App ID, to verify the attestation.
public struct SDXProxyConfiguration: Sendable {
    /// Base URL of the deployed Worker, e.g. `https://stage-yourapp-proxy.<account>.workers.dev`.
    public let proxyBaseURL: URL

    /// Sent as the dev-bypass header instead of an App Attest assertion. Only meaningful on the
    /// Simulator, where App Attest is unavailable, and only accepted by a Worker whose
    /// `APPATTEST_ENV` is not `production`. Must be `nil` in Release/AppStore builds.
    ///
    /// This should be a random opaque string (e.g. `openssl rand -hex 32`), never anything shaped
    /// like a real API key — it is compared verbatim against a Worker-side secret, not derived
    /// from or related to the upstream API's own credentials.
    public let devBypassToken: String?

    /// Keychain account under which the attested App Attest `keyId` is persisted.
    public let keychainAccount: String

    /// Prefix for the headers this client attaches (`<prefix>-Key-Id`, `<prefix>-Assertion`,
    /// `<prefix>-Client-Data`, `<prefix>-Dev-Token`). Only override this if a single app needs two
    /// independent SDXCloudflare-based proxies to coexist without header collisions.
    public let headerPrefix: String

    /// Path (relative to `proxyBaseURL`) that `responses(body:)` posts to.
    public let responsesPath: String

    /// Path (relative to `proxyBaseURL`) that issues one-time App Attest challenges.
    public let challengePath: String

    /// Path (relative to `proxyBaseURL`) that registers an attested device key.
    public let registerPath: String

    /// Timeout for the proxied request itself (not the attestation/challenge round-trips, which
    /// use `URLSession`'s default).
    public let requestTimeout: TimeInterval

    public init(
        proxyBaseURL: URL,
        devBypassToken: String? = nil,
        keychainAccount: String = "SDXProxyAppAttestKeyId",
        headerPrefix: String = "X-Proxy",
        responsesPath: String = "v1/responses",
        challengePath: String = "attest/challenge",
        registerPath: String = "attest/register",
        requestTimeout: TimeInterval = 60
    ) {
        self.proxyBaseURL = proxyBaseURL
        self.devBypassToken = devBypassToken
        self.keychainAccount = keychainAccount
        self.headerPrefix = headerPrefix
        self.responsesPath = responsesPath
        self.challengePath = challengePath
        self.registerPath = registerPath
        self.requestTimeout = requestTimeout
    }
}
