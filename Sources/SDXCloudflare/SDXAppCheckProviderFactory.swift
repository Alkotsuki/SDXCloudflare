import FirebaseAppCheck
import FirebaseCore
import Foundation

/// The App Check provider setup `SDXProxyClient` expects: App Attest on devices, Firebase's debug
/// provider on the Simulator. Install it before configuring Firebase:
///
/// ```swift
/// #if DEBUG
/// let debugToken: String? = "<UUID registered in Firebase console → App Check → Manage debug tokens>"
/// #else
/// let debugToken: String? = nil
/// #endif
/// AppCheck.setAppCheckProviderFactory(SDXAppCheckProviderFactory(debugToken: debugToken))
/// FirebaseApp.configure()
/// ```
///
/// With one shared `debugToken`, every Simulator works without registering each one. Anyone holding
/// the debug token can mint valid App Check tokens, so keep it out of Release builds (`#if DEBUG`)
/// and revoke it in the Firebase console if it leaks.
public final class SDXAppCheckProviderFactory: NSObject, AppCheckProviderFactory {
    private let debugToken: String?

    /// - Parameter debugToken: Used only on the Simulator. `nil` falls back to Firebase's default:
    ///   a random token per install, printed to the console, that must be registered by hand.
    public init(debugToken: String? = nil) {
        self.debugToken = debugToken
    }

    public func createProvider(with app: FirebaseApp) -> AppCheckProvider? {
        #if targetEnvironment(simulator)
        // The debug provider reads this variable when it is created.
        if let debugToken { setenv("FIRAAppCheckDebugToken", debugToken, 1) }
        return AppCheckDebugProvider(app: app)
        #else
        return AppAttestProvider(app: app)
        #endif
    }
}
