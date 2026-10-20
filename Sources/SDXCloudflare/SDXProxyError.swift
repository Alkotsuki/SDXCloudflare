import Foundation

/// Everything that can go wrong between deciding to call the proxy and getting a response body
/// back.
public enum SDXProxyError: Error, Sendable {
    /// Firebase App Check could not produce a token (not configured, provider unsupported on this
    /// device, network failure, or throttled by Firebase).
    case appCheckFailed(String)
    /// The Worker responded outside the 2xx range.
    case requestFailed(status: Int, body: Data?)
    case transport(Error)
    case cancelled
}

extension SDXProxyError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .appCheckFailed(let detail):
            "Couldn't verify this app for cloud features: \(detail)"
        case .requestFailed(let status, _):
            "The proxy request failed (\(status))."
        case .transport:
            "Couldn't reach the network."
        case .cancelled:
            "Cancelled."
        }
    }
}
