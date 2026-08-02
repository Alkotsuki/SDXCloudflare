@testable import SDXCloudflare
import Foundation
import Security

/// An in-memory stand-in for `SecurityFrameworkBacking`, so `KeychainStoreTests` exercise
/// `KeychainStore`'s own save/load/delete logic without any real OS Keychain call — which would
/// fail on iOS with `errSecMissingEntitlement` for a bare SPM test bundle (no host app, no
/// `keychain-access-groups` entitlement). Mirrors `SecItem*` status-code semantics closely enough
/// for `KeychainStore`'s branches (found / not-found / other).
final class InMemoryKeychainBacking: KeychainBacking, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String: Data] = [:]

    private func key(for query: [String: Any]) -> String {
        let service = query[kSecAttrService as String] as? String ?? ""
        let account = query[kSecAttrAccount as String] as? String ?? ""
        return "\(service)\u{0}\(account)"
    }

    func probe(_ query: [String: Any]) -> OSStatus {
        lock.lock(); defer { lock.unlock() }
        return storage[key(for: query)] != nil ? errSecSuccess : errSecItemNotFound
    }

    func copyData(_ query: [String: Any]) -> (status: OSStatus, data: Data?) {
        lock.lock(); defer { lock.unlock() }
        guard let data = storage[key(for: query)] else { return (errSecItemNotFound, nil) }
        return (errSecSuccess, data)
    }

    func add(_ query: [String: Any]) -> OSStatus {
        lock.lock(); defer { lock.unlock() }
        guard let data = query[kSecValueData as String] as? Data else { return errSecParam }
        storage[key(for: query)] = data
        return errSecSuccess
    }

    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        lock.lock(); defer { lock.unlock() }
        let k = key(for: query)
        guard storage[k] != nil else { return errSecItemNotFound }
        guard let data = attributes[kSecValueData as String] as? Data else { return errSecParam }
        storage[k] = data
        return errSecSuccess
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        lock.lock(); defer { lock.unlock() }
        guard storage.removeValue(forKey: key(for: query)) != nil else { return errSecItemNotFound }
        return errSecSuccess
    }
}
