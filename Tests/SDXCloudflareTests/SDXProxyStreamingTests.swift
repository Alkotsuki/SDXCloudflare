import Foundation
import Testing
@testable import SDXCloudflare

/// The streaming seam, at the level that can be tested without a network or App Check.
///
/// `SDXProxyClient.sendStream` itself needs a real `URLSession` and a configured Firebase app, so what is
/// covered here is the part that has logic in it: the protocol default, which is what every fake and
/// every non-streaming transport falls back to. It has to behave like the buffered call it wraps, or a
/// caller that switched to streaming would quietly get different data in tests than in production.
struct SDXProxyStreamingTests {

    /// A client that returns a canned body and records what it was asked for.
    private struct StubClient: SDXProxyClientProtocol {
        let configuration = SDXProxyConfiguration(proxyBaseURL: URL(string: "https://example.invalid")!)
        let body: Data
        let recorder: Recorder

        final class Recorder: @unchecked Sendable {
            var paths: [String] = []
            var contentTypes: [String] = []
        }

        func send(path: String, body: Data, contentType: String) async throws -> Data {
            recorder.paths.append(path)
            recorder.contentTypes.append(contentType)
            return self.body
        }
    }

    private func collect(
        _ stream: AsyncThrowingStream<String, any Error>
    ) async throws -> [String] {
        var lines: [String] = []
        for try await line in stream { lines.append(line) }
        return lines
    }

    @Test func theDefaultDeliversTheWholeBodyAsLines() async throws {
        let payload = "event: one\ndata: {\"a\":1}\n\ndata: [DONE]"
        let client = StubClient(
            body: Data(payload.utf8),
            recorder: StubClient.Recorder()
        )

        let lines = try await collect(
            client.sendStream(path: "v1/responses", body: Data(), contentType: "application/json")
        )

        // Every line, in order, including the blank one that separates SSE frames — a caller parsing
        // events depends on that boundary existing.
        #expect(lines == ["event: one", "data: {\"a\":1}", "", "data: [DONE]"])
    }

    @Test func theDefaultRoutesThroughSendUnchanged() async throws {
        let recorder = StubClient.Recorder()
        let client = StubClient(body: Data("hello".utf8), recorder: recorder)

        _ = try await collect(
            client.sendStream(path: "v1/responses", body: Data("{}".utf8), contentType: "application/json")
        )

        #expect(recorder.paths == ["v1/responses"])
        #expect(recorder.contentTypes == ["application/json"])
    }

    @Test func anEmptyBodyYieldsOneEmptyLineRatherThanFailing() async throws {
        let client = StubClient(body: Data(), recorder: StubClient.Recorder())
        let lines = try await collect(
            client.sendStream(path: "p", body: Data(), contentType: "application/json")
        )
        #expect(lines == [""])
    }

    /// A trailing newline must not be swallowed, because a stream that ends mid-frame and one that ends
    /// cleanly are different situations for the caller.
    @Test func aTrailingNewlineIsPreserved() async throws {
        let client = StubClient(body: Data("data: x\n".utf8), recorder: StubClient.Recorder())
        let lines = try await collect(
            client.sendStream(path: "p", body: Data(), contentType: "application/json")
        )
        #expect(lines == ["data: x", ""])
    }

    /// The convenience wrapper must use the configured path, not a hardcoded one.
    @Test func theResponsesWrapperUsesTheConfiguredPath() async throws {
        let recorder = StubClient.Recorder()
        let client = StubClient(body: Data("{}".utf8), recorder: recorder)
        _ = try await collect(client.responsesStream(body: Data()))
        #expect(recorder.paths == [client.configuration.responsesPath])
    }
}
