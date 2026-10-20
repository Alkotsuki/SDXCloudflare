import Foundation

/// Everything `SDXProxyClient` needs to talk to a specific deployed Worker.
///
/// There is deliberately no Firebase field here: App Check reads the project from the host app's
/// `FirebaseApp.configure()`. Only the Worker needs the project number, to verify tokens.
public struct SDXProxyConfiguration: Sendable {
    /// Base URL of the deployed Worker, e.g. `https://stage-yourapp-proxy.<account>.workers.dev`.
    public let proxyBaseURL: URL

    /// Sent as the dev-bypass header instead of an App Check token. Only meaningful on the
    /// Simulator (an alternative to App Check's debug provider), and only accepted by a Worker whose
    /// `APPATTEST_ENV` is not `production`. Must be `nil` in Release/AppStore builds.
    ///
    /// This should be a random opaque string (e.g. `openssl rand -hex 32`), never anything shaped
    /// like a real API key — it is compared verbatim against a Worker-side secret, not derived
    /// from or related to the upstream API's own credentials.
    public let devBypassToken: String?

    /// Keychain account under which the per-install id (the Worker's rate-limit key) is persisted.
    public let keychainAccount: String

    /// Prefix for the headers this client attaches (`<prefix>-Install-Id`, `<prefix>-Dev-Token`).
    /// Only override this if a single app needs two independent SDXCloudflare-based proxies to
    /// coexist without header collisions.
    public let headerPrefix: String

    /// Path (relative to `proxyBaseURL`) that `responses(body:)` posts to.
    public let responsesPath: String

    /// Timeout for the proxied request itself (not the App Check token fetch).
    public let requestTimeout: TimeInterval

    public init(
        proxyBaseURL: URL,
        devBypassToken: String? = nil,
        keychainAccount: String = "SDXProxyInstallId",
        headerPrefix: String = "X-Proxy",
        responsesPath: String = "v1/responses",
        requestTimeout: TimeInterval = 60
    ) {
        self.proxyBaseURL = proxyBaseURL
        self.devBypassToken = devBypassToken
        self.keychainAccount = keychainAccount
        self.headerPrefix = headerPrefix
        self.responsesPath = responsesPath
        self.requestTimeout = requestTimeout
    }
}
