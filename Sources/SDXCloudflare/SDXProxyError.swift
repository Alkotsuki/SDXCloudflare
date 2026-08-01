import Foundation

/// Everything that can go wrong between deciding to call the proxy and getting a response body
/// back.
public enum SDXProxyError: Error, Sendable {
    /// App Attest is not available (e.g. an unsupported device) and no dev bypass applies, so the
    /// proxy cannot be reached securely.
    case appAttestUnsupported
    case challengeFailed
    case registrationFailed(String)
    case assertionFailed(String)
    /// The Worker responded outside the 2xx range.
    case requestFailed(status: Int, body: Data?)
    case transport(Error)
    case cancelled
}

extension SDXProxyError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .appAttestUnsupported:
            "This device can't be verified for cloud features."
        case .challengeFailed:
            "Couldn't reach the proxy. Check your connection and try again."
        case .registrationFailed(let detail):
            "Couldn't verify this device with the proxy: \(detail)"
        case .assertionFailed(let detail):
            "Couldn't authorize the request with the proxy: \(detail)"
        case .requestFailed(let status, _):
            "The proxy request failed (\(status))."
        case .transport:
            "Couldn't reach the network."
        case .cancelled:
            "Cancelled."
        }
    }
}
