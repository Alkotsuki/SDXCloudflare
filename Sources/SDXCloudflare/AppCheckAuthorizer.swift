import FirebaseAppCheck
import Foundation

/// Authorizes outgoing requests to a Worker using Firebase App Check.
///
/// The Worker holds the shared upstream API key; the App Check token proves the request comes from
/// a genuine copy of the app (attested by whichever provider the host app installed — App Attest,
/// DeviceCheck, or the debug provider). The Firebase SDK caches and refreshes the token, so a
/// request usually costs no extra round-trip. Each request carries:
///   - `X-Firebase-AppCheck` — the token, verified by the Worker against Firebase's public keys.
///   - `<prefix>-Install-Id` — a random per-install id the Worker keys its daily cap on.
///
/// The host app must call `AppCheck.setAppCheckProviderFactory(_:)` (normally with
/// `SDXAppCheckProviderFactory`) and then `FirebaseApp.configure()` before the first request.
///
/// On the Simulator a dev bypass token is sent instead of App Check, if the configuration provides
/// one; the Worker accepts it only in its non-production environment.
actor AppCheckAuthorizer {
    private let configuration: SDXProxyConfiguration
    private let keychain: KeychainStore

    /// In-memory cache of the install id to avoid a Keychain read per request.
    private var cachedInstallId: String?

    init(configuration: SDXProxyConfiguration, keychain: KeychainStore) {
        self.configuration = configuration
        self.keychain = keychain
    }

    /// Attaches authorization headers to `request`.
    func authorize(_ request: inout URLRequest) async throws {
        if useDevBypass, let devBypassToken = configuration.devBypassToken {
            request.setValue(devBypassToken, forHTTPHeaderField: "\(configuration.headerPrefix)-Dev-Token")
            return
        }

        let token: String
        do {
            token = try await AppCheck.appCheck().token(forcingRefresh: false).token
        } catch {
            throw SDXProxyError.appCheckFailed(error.localizedDescription)
        }
        request.setValue(token, forHTTPHeaderField: "X-Firebase-AppCheck")
        request.setValue(await installId(), forHTTPHeaderField: "\(configuration.headerPrefix)-Install-Id")
    }

    private func installId() async -> String {
        if let cachedInstallId { return cachedInstallId }
        if let stored = try? await keychain.load(account: configuration.keychainAccount), !stored.isEmpty {
            cachedInstallId = stored
            return stored
        }
        let fresh = UUID().uuidString
        try? await keychain.save(fresh, account: configuration.keychainAccount)
        cachedInstallId = fresh
        return fresh
    }

    /// True only for Simulator builds, and only when a build-time dev bypass token is configured.
    private nonisolated var useDevBypass: Bool {
        #if targetEnvironment(simulator)
        return configuration.devBypassToken != nil
        #else
        return false
        #endif
    }
}
