import Foundation

/// Convenience for proxies fronting an OpenAI-Responses-API-shaped upstream (the default
/// `SDXCloudflare/server` template forwards to `/v1/responses`).
public extension SDXProxyClientProtocol {
    /// POSTs `body` to the configured `responsesPath` and returns the raw response body.
    func responses(body: Data) async throws -> Data {
        try await send(path: configuration.responsesPath, body: body, contentType: "application/json")
    }

    /// The same, delivered line by line. The body still has to ask the upstream for a stream.
    func responsesStream(body: Data) async throws -> AsyncThrowingStream<String, any Error> {
        try await sendStream(
            path: configuration.responsesPath,
            body: body,
            contentType: "application/json"
        )
    }
}
