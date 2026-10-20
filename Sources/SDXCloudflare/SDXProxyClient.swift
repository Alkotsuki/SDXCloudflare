import Foundation

/// Something that can send an authenticated request to a Cloudflare Worker proxy and return its
/// response body. Exists mainly so callers can inject a fake implementation in tests.
public protocol SDXProxyClientProtocol: Sendable {
    /// The configuration this client was built with — exposed so extensions (like
    /// `responses(body:)`) can resolve configurable paths without duplicating them.
    var configuration: SDXProxyConfiguration { get }

    /// POSTs `body` to `<proxyBaseURL>/<path>`, attaching App Check (or dev-bypass) authorization,
    /// and returns the raw response body. Throws `SDXProxyError` on any non-2xx response or
    /// transport failure.
    func send(path: String, body: Data, contentType: String) async throws -> Data

    /// The same request, but delivered **line by line as it arrives** rather than buffered.
    ///
    /// Lines rather than parsed events, deliberately: line framing is an HTTP-level concern and
    /// belongs here, while what the lines *mean* — server-sent events, a particular vendor's event
    /// names, a JSON schema being filled in — belongs to the caller. This package knows nothing about
    /// its upstream and this method does not change that.
    ///
    /// Authorization happens before the stream is returned, exactly as in `send`.
    ///
    /// Note that `SDXProxyConfiguration.requestTimeout` becomes an **idle** timeout for a streamed
    /// request — `URLRequest.timeoutInterval` measures the gap between packets, not the total. An
    /// upstream that thinks for longer than the timeout before emitting its first byte will fail, so
    /// set the timeout against how long the *silence* can legitimately last, not the whole response.
    func sendStream(
        path: String,
        body: Data,
        contentType: String
    ) async throws -> AsyncThrowingStream<String, any Error>
}

public extension SDXProxyClientProtocol {
    /// Buffers, then hands the whole body over as lines.
    ///
    /// A default so that adding streaming did not break every conformance — a client that cannot
    /// stream, or a fake in a test, degrades to "one response, delivered at the end", which is the
    /// behaviour every caller had before this existed. Correct, just not incremental.
    func sendStream(
        path: String,
        body: Data,
        contentType: String = "application/json"
    ) async throws -> AsyncThrowingStream<String, any Error> {
        let data = try await send(path: path, body: body, contentType: contentType)
        let lines = String(decoding: data, as: UTF8.self)
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map(String.init)
        return AsyncThrowingStream { continuation in
            for line in lines { continuation.yield(line) }
            continuation.finish()
        }
    }
}

/// The default `SDXProxyClientProtocol` implementation: a Cloudflare Worker client authorized via
/// Firebase App Check.
public actor SDXProxyClient: SDXProxyClientProtocol {
    public nonisolated let configuration: SDXProxyConfiguration
    private let session: URLSession
    private let authorizer: AppCheckAuthorizer

    public init(configuration: SDXProxyConfiguration, session: URLSession = .shared) {
        self.configuration = configuration
        self.session = session
        self.authorizer = AppCheckAuthorizer(configuration: configuration, keychain: KeychainStore())
    }

    public func send(path: String, body: Data, contentType: String = "application/json") async throws -> Data {
        var request = URLRequest(url: configuration.proxyBaseURL.appending(path: path))
        request.httpMethod = "POST"
        request.timeoutInterval = configuration.requestTimeout
        request.setValue(contentType, forHTTPHeaderField: "Content-Type")
        request.httpBody = body

        try await authorizer.authorize(&request)

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

    public func sendStream(
        path: String,
        body: Data,
        contentType: String = "application/json"
    ) async throws -> AsyncThrowingStream<String, any Error> {
        var request = URLRequest(url: configuration.proxyBaseURL.appending(path: path))
        request.httpMethod = "POST"
        request.timeoutInterval = configuration.requestTimeout
        request.setValue(contentType, forHTTPHeaderField: "Content-Type")
        // HTTP-correct, though not load-bearing: what actually selects a streamed response is
        // whatever flag the upstream API defines in the body, and the reference Worker forwards only
        // `authorization` and `content-type` upstream. Sent anyway so a proxy that *does* forward
        // headers gets the right one.
        request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        request.httpBody = body

        try await authorizer.authorize(&request)

        let bytes: URLSession.AsyncBytes
        let response: URLResponse
        do {
            (bytes, response) = try await session.bytes(for: request)
        } catch let error as URLError where error.code == .cancelled {
            throw SDXProxyError.cancelled
        } catch {
            throw SDXProxyError.transport(error)
        }

        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            // Read the error body before giving up, so the caller gets the upstream's own message
            // rather than a bare status code. Bounded, because this is a failure path and an
            // unbounded read here would turn one bad response into a hang.
            throw SDXProxyError.requestFailed(
                status: http.statusCode,
                body: await Self.prefix(of: bytes)
            )
        }

        return Self.lines(of: bytes)
    }

    /// Bridges `URLSession.AsyncBytes` to a stream of lines.
    ///
    /// `static`, and capturing nothing but the byte sequence, **so the reading task is not isolated to
    /// this actor.** Holding the actor for the lifetime of a multi-second stream would serialise
    /// every concurrent request behind it. Authorization happens on the actor; reading does not.
    private static func lines(
        of bytes: URLSession.AsyncBytes
    ) -> AsyncThrowingStream<String, any Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    for try await line in bytes.lines {
                        continuation.yield(line)
                    }
                    continuation.finish()
                } catch is CancellationError {
                    continuation.finish(throwing: SDXProxyError.cancelled)
                } catch let error as URLError where error.code == .cancelled {
                    continuation.finish(throwing: SDXProxyError.cancelled)
                } catch {
                    continuation.finish(throwing: SDXProxyError.transport(error))
                }
            }
            // A consumer that stops early — a cancelled edit, a thrown error downstream — must not
            // leave the connection being drained in the background.
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    /// At most `limit` bytes of a response, for error reporting.
    private static func prefix(of bytes: URLSession.AsyncBytes, limit: Int = 8_192) async -> Data {
        var data = Data()
        do {
            for try await byte in bytes {
                data.append(byte)
                if data.count >= limit { break }
            }
        } catch {
            // Whatever we managed to read is still better than nothing in an error message.
        }
        return data
    }
}
