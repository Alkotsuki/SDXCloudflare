import Foundation

/// Something that can send an authenticated request to a Cloudflare Worker proxy and return its
/// response body. Exists mainly so callers can inject a fake implementation in tests.
public protocol SDXProxyClientProtocol: Sendable {
    /// The configuration this client was built with — exposed so extensions (like
    /// `responses(body:)`) can resolve configurable paths without duplicating them.
    var configuration: SDXProxyConfiguration { get }

    /// Whether the proxy can plausibly be reached from this build/device — App Attest is supported,
    /// or a dev bypass token is configured. Does not guarantee the network call itself will
    /// succeed; use this to gate UI, not to skip error handling.
    var isAvailable: Bool { get }

    /// POSTs `body` to `<proxyBaseURL>/<path>`, attaching App Attest (or dev-bypass) authorization,
    /// and returns the raw response body. Throws `SDXProxyError` on any non-2xx response or
    /// transport failure.
    func send(path: String, body: Data, contentType: String) async throws -> Data
}

/// The default `SDXProxyClientProtocol` implementation: a Cloudflare Worker client authorized via
/// Apple App Attest.
///
/// An actor because App Attest key registration must be serialized — concurrent first-launch calls
/// must not race two `generateKey`/`attestKey` attempts.
public actor SDXProxyClient: SDXProxyClientProtocol {
    public nonisolated let configuration: SDXProxyConfiguration
    private let session: URLSession
    private let authorizer: AppAttestAuthorizer

    public init(configuration: SDXProxyConfiguration, session: URLSession = .shared) {
        self.configuration = configuration
        self.session = session
        self.authorizer = AppAttestAuthorizer(
            configuration: configuration,
            keychain: KeychainStore(),
            session: session
        )
    }

    public nonisolated var isAvailable: Bool {
        authorizer.isAvailable
    }

    public func send(path: String, body: Data, contentType: String = "application/json") async throws -> Data {
        var request = URLRequest(url: configuration.proxyBaseURL.appending(path: path))
        request.httpMethod = "POST"
        request.timeoutInterval = configuration.requestTimeout
        request.setValue(contentType, forHTTPHeaderField: "Content-Type")
        request.httpBody = body

        try await authorizer.authorize(&request, body: body)

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch let error as URLError where error.code == .cancelled {
            throw SDXProxyError.cancelled
        } catch {
            throw SDXProxyError.transport(error)
        }

        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw SDXProxyError.requestFailed(status: http.statusCode, body: data)
        }
        return data
    }
}
