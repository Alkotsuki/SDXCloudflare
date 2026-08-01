import CryptoKit
import DeviceCheck
import Foundation

/// Authorizes outgoing requests to a Worker using Apple App Attest.
///
/// The Worker holds the shared upstream API key; this authorizer proves each request comes from a
/// genuine, unmodified copy of the app. Flow:
///   1. **Register once per install** — generate a Secure Enclave key, attest it with Apple against
///      a server challenge, and POST the attestation to the Worker. The `keyId` is persisted to the
///      Keychain only after the Worker accepts it, so a stored `keyId` means "registered".
///   2. **Per request** — fetch a one-time challenge, sign client data (`{challenge, bodySHA256}`)
///      with the attested key, and attach the `keyId`, assertion, and client data as headers. The
///      Worker verifies the signature, the strictly-increasing counter (replay protection), and
///      that `bodySHA256` matches the body it forwards upstream.
///
/// On the Simulator (where App Attest is unavailable) a dev bypass token is sent instead, if the
/// configuration provides one; the Worker accepts it only in its non-production environment.
actor AppAttestAuthorizer {
    private let configuration: SDXProxyConfiguration
    private let service = DCAppAttestService.shared
    private let keychain: KeychainStore
    private let session: URLSession
    private let encoder = JSONEncoder()

    /// In-memory cache of the registered `keyId` to avoid a Keychain read per request.
    private var cachedKeyId: String?

    init(configuration: SDXProxyConfiguration, keychain: KeychainStore, session: URLSession) {
        self.configuration = configuration
        self.keychain = keychain
        self.session = session
    }

    /// Whether the proxy can be reached from this build/device. Used to gate proxy-backed
    /// affordances in the UI before any request is attempted.
    nonisolated var isAvailable: Bool {
        if useDevBypass { return true }
        return DCAppAttestService.shared.isSupported
    }

    /// Attaches authorization headers to `request`, signing over the exact `body` that will be
    /// sent. Registers the device on first use.
    func authorize(_ request: inout URLRequest, body: Data) async throws {
        if useDevBypass {
            guard let devBypassToken = configuration.devBypassToken else {
                throw SDXProxyError.appAttestUnsupported
            }
            request.setValue(devBypassToken, forHTTPHeaderField: "\(configuration.headerPrefix)-Dev-Token")
            return
        }

        guard service.isSupported else { throw SDXProxyError.appAttestUnsupported }

        let challenge = try await fetchChallenge()
        let bodyHash = Data(SHA256.hash(data: body)).base64EncodedString()
        let clientData = ClientData(challenge: challenge, bodySHA256: bodyHash)
        let clientDataBytes: Data
        do {
            clientDataBytes = try encoder.encode(clientData)
        } catch {
            throw SDXProxyError.assertionFailed(error.localizedDescription)
        }
        let clientDataHash = Data(SHA256.hash(data: clientDataBytes))

        let (keyId, assertion) = try await signedAssertion(clientDataHash: clientDataHash)

        request.setValue(keyId, forHTTPHeaderField: "\(configuration.headerPrefix)-Key-Id")
        request.setValue(assertion.base64EncodedString(), forHTTPHeaderField: "\(configuration.headerPrefix)-Assertion")
        request.setValue(clientDataBytes.base64EncodedString(), forHTTPHeaderField: "\(configuration.headerPrefix)-Client-Data")
    }

    /// `DCError` codes that mean the *local key material* is unusable (stale, from a different App
    /// Attest environment, or otherwise rejected) rather than a transient/server issue — worth
    /// discarding and regenerating. `.invalidKey` is Apple's documented case; `.invalidInput` is
    /// included because a leftover key from earlier dev/prod environment switches has been observed
    /// to surface as `invalidInput` on `generateAssertion` too.
    private func isKeyUnusable(_ error: Error) -> Bool {
        guard let dcError = error as? DCError else { return false }
        return dcError.code == .invalidKey || dcError.code == .invalidInput
    }

    /// Signs `clientDataHash` with the registered key. If the stored key is rejected as unusable
    /// (e.g. the App Attest environment changed between sandbox and production, or it's a stale
    /// leftover from earlier testing), discard it, re-register a fresh key, and retry once — so the
    /// app self-heals instead of requiring a reinstall.
    private func signedAssertion(clientDataHash: Data) async throws -> (keyId: String, assertion: Data) {
        let keyId = try await registeredKeyId()
        do {
            let assertion = try await service.generateAssertion(keyId, clientDataHash: clientDataHash)
            return (keyId, assertion)
        } catch where isKeyUnusable(error) {
            let freshKeyId = try await resetAndRegister()
            do {
                let assertion = try await service.generateAssertion(freshKeyId, clientDataHash: clientDataHash)
                return (freshKeyId, assertion)
            } catch {
                throw SDXProxyError.assertionFailed(error.localizedDescription)
            }
        } catch {
            throw SDXProxyError.assertionFailed(error.localizedDescription)
        }
    }

    /// Discards the stored key and registers a fresh one. Used to recover from an invalidated key
    /// (App Attest environment change, key rejection).
    private func resetAndRegister() async throws -> String {
        cachedKeyId = nil
        try? await keychain.delete(account: configuration.keychainAccount)
        let keyId = try await register()
        cachedKeyId = keyId
        return keyId
    }

    // MARK: - Registration

    private func registeredKeyId() async throws -> String {
        if let cachedKeyId { return cachedKeyId }
        if let stored = try? await keychain.load(account: configuration.keychainAccount),
           !stored.isEmpty {
            cachedKeyId = stored
            return stored
        }
        let keyId = try await register()
        cachedKeyId = keyId
        return keyId
    }

    private func register(retrying: Bool = false) async throws -> String {
        let keyId: String
        do {
            keyId = try await service.generateKey()
        } catch {
            throw SDXProxyError.registrationFailed(error.localizedDescription)
        }

        let challenge = try await fetchChallenge()
        // Attestation binds the key to a hash of the server challenge.
        let challengeHash = Data(SHA256.hash(data: Data(challenge.utf8)))

        let attestation: Data
        do {
            attestation = try await service.attestKey(keyId, clientDataHash: challengeHash)
        } catch where isKeyUnusable(error) && !retrying {
            // The freshly generated key was itself rejected (observed for stale App Attest state
            // left over from earlier testing) — one fresh key and one retry is enough; a repeat
            // failure surfaces normally.
            return try await register(retrying: true)
        } catch {
            // A rejected/failed key must be discarded; a fresh one is generated next attempt.
            throw SDXProxyError.registrationFailed(error.localizedDescription)
        }

        try await postRegistration(keyId: keyId, attestation: attestation, challenge: challenge)

        // Persist only after the Worker accepts the attestation.
        try? await keychain.save(keyId, account: configuration.keychainAccount)
        return keyId
    }

    // MARK: - Networking

    private struct ClientData: Encodable {
        let challenge: String
        let bodySHA256: String
    }

    private struct ChallengeResponse: Decodable {
        let challenge: String
    }

    private func fetchChallenge() async throws -> String {
        var request = URLRequest(url: configuration.proxyBaseURL.appending(path: configuration.challengePath))
        request.httpMethod = "POST"
        if useDevBypass, let devBypassToken = configuration.devBypassToken {
            request.setValue(devBypassToken, forHTTPHeaderField: "\(configuration.headerPrefix)-Dev-Token")
        }
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                throw SDXProxyError.challengeFailed
            }
            return try JSONDecoder().decode(ChallengeResponse.self, from: data).challenge
        } catch let error as SDXProxyError {
            throw error
        } catch {
            throw SDXProxyError.challengeFailed
        }
    }

    private func postRegistration(keyId: String, attestation: Data, challenge: String) async throws {
        struct RegistrationBody: Encodable {
            let keyId: String
            let attestation: String
            let challenge: String
        }
        var request = URLRequest(url: configuration.proxyBaseURL.appending(path: configuration.registerPath))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? encoder.encode(
            RegistrationBody(keyId: keyId, attestation: attestation.base64EncodedString(), challenge: challenge)
        )

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let message = String(data: data, encoding: .utf8) ?? "registration rejected"
            throw SDXProxyError.registrationFailed(message)
        }
    }

    // MARK: - Dev bypass

    /// True only for Simulator builds where App Attest is unavailable, and only when a build-time
    /// dev bypass token is actually configured.
    private nonisolated var useDevBypass: Bool {
        #if targetEnvironment(simulator)
        return configuration.devBypassToken != nil
        #else
        return false
        #endif
    }
}
