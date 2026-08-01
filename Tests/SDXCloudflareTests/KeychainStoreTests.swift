import Testing
@testable import SDXCloudflare
import Foundation

@Suite("KeychainStore")
struct KeychainStoreTests {
    /// A distinct service name so these tests never collide with a host app's own Keychain items.
    private func makeStore() -> KeychainStore {
        KeychainStore(service: "com.sdx.SDXCloudflareTests.\(UUID().uuidString)")
    }

    @Test("save then load round-trips the value")
    func saveThenLoad() async throws {
        let store = makeStore()
        try await store.save("test-key-id", account: "account-a")
        let loaded = try await store.load(account: "account-a")
        #expect(loaded == "test-key-id")
    }

    @Test("loading a missing account returns nil")
    func loadMissing() async throws {
        let store = makeStore()
        let loaded = try await store.load(account: "never-written")
        #expect(loaded == nil)
    }

    @Test("save overwrites an existing value for the same account")
    func saveOverwrites() async throws {
        let store = makeStore()
        try await store.save("first", account: "account-b")
        try await store.save("second", account: "account-b")
        let loaded = try await store.load(account: "account-b")
        #expect(loaded == "second")
    }

    @Test("delete removes the value")
    func delete() async throws {
        let store = makeStore()
        try await store.save("to-delete", account: "account-c")
        try await store.delete(account: "account-c")
        let loaded = try await store.load(account: "account-c")
        #expect(loaded == nil)
    }

    @Test("deleting a missing account does not throw")
    func deleteMissing() async throws {
        let store = makeStore()
        try await store.delete(account: "never-written")
    }
}
