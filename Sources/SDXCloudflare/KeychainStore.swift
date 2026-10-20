import Foundation
import Security

enum KeychainStoreError: LocalizedError {
    case unexpectedStatus(OSStatus)

    var errorDescription: String? {
        switch self {
        case .unexpectedStatus(let status):
            "Keychain operation failed with status \(status)."
        }
    }
}

/// The raw Keychain Services calls `KeychainStore` needs, abstracted so its query-building and
/// status-mapping logic can be unit-tested without touching the OS keychain.
///
/// A bare SPM test bundle has no host app, so on iOS it is signed with no `keychain-access-groups`
/// entitlement — every real Keychain call fails with `errSecMissingEntitlement` (-34018)
/// regardless of device vs. Simulator. Testing through this seam instead of the Security framework
/// directly sidesteps that entirely, so tests exercise `KeychainStore`'s own logic everywhere,
/// including on iOS.
protocol KeychainBacking: Sendable {
    func probe(_ query: [String: Any]) -> OSStatus
    func copyData(_ query: [String: Any]) -> (status: OSStatus, data: Data?)
    func add(_ query: [String: Any]) -> OSStatus
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus
    func delete(_ query: [String: Any]) -> OSStatus
}

/// The real backing, used in production: thin wrappers over `SecItem*`.
struct SecurityFrameworkBacking: KeychainBacking {
    func probe(_ query: [String: Any]) -> OSStatus {
        SecItemCopyMatching(query as CFDictionary, nil)
    }

    func copyData(_ query: [String: Any]) -> (status: OSStatus, data: Data?) {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        return (status, item as? Data)
    }

    func add(_ query: [String: Any]) -> OSStatus {
        SecItemAdd(query as CFDictionary, nil)
    }

    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        SecItemDelete(query as CFDictionary)
    }
}

/// Persists small device-local secrets (the per-install id) outside source control and
/// `UserDefaults`. Account-scoped so multiple values can live under one Keychain service.
actor KeychainStore {
    private let service: String
    private let backing: KeychainBacking

    init(service: String = Bundle.main.bundleIdentifier ?? "SDXCloudflare", backing: KeychainBacking = SecurityFrameworkBacking()) {
        self.service = service
        self.backing = backing
    }

    func save(_ value: String, account: String) throws {
        let data = Data(value.utf8)
        let query = baseQuery(account: account)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]

        let status = backing.probe(query)
        switch status {
        case errSecSuccess:
            let updateStatus = backing.update(query, attributes: attributes)
            guard updateStatus == errSecSuccess else { throw KeychainStoreError.unexpectedStatus(updateStatus) }
        case errSecItemNotFound:
            var addQuery = query
            attributes.forEach { addQuery[$0.key] = $0.value }
            let addStatus = backing.add(addQuery)
            guard addStatus == errSecSuccess else { throw KeychainStoreError.unexpectedStatus(addStatus) }
        default:
            throw KeychainStoreError.unexpectedStatus(status)
        }
    }

    func load(account: String) throws -> String? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        let (status, data) = backing.copyData(query)
        switch status {
        case errSecSuccess:
            guard let data, let value = String(data: data, encoding: .utf8) else { return nil }
            return value
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainStoreError.unexpectedStatus(status)
        }
    }

    func delete(account: String) throws {
        let status = backing.delete(baseQuery(account: account))
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainStoreError.unexpectedStatus(status)
        }
    }

    private func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}
