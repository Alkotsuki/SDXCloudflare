import Testing
@testable import SDXCloudflare
import Foundation

@Suite("SDXProxyConfiguration")
struct SDXProxyConfigurationTests {
    @Test("default values match the shared client/server contract")
    func defaults() {
        let configuration = SDXProxyConfiguration(proxyBaseURL: URL(string: "https://example.workers.dev")!)

        #expect(configuration.devBypassToken == nil)
        #expect(configuration.keychainAccount == "SDXProxyInstallId")
        #expect(configuration.headerPrefix == "X-Proxy")
        #expect(configuration.responsesPath == "v1/responses")
        #expect(configuration.requestTimeout == 60)
    }

    @Test("every field is overridable")
    func overrides() {
        let configuration = SDXProxyConfiguration(
            proxyBaseURL: URL(string: "https://example.workers.dev")!,
            devBypassToken: "abc123",
            keychainAccount: "CustomAccount",
            headerPrefix: "X-Custom",
            responsesPath: "custom/responses",
            requestTimeout: 15
        )

        #expect(configuration.devBypassToken == "abc123")
        #expect(configuration.keychainAccount == "CustomAccount")
        #expect(configuration.headerPrefix == "X-Custom")
        #expect(configuration.responsesPath == "custom/responses")
        #expect(configuration.requestTimeout == 15)
    }
}
