import Foundation

/// Incomplete user redirect.
///
/// Returned in place of a ``Redirect`` when no default redirect URI was
/// configured via `RoutexClient.setRedirectURI(_:)`. A final redirect URI
/// must be registered, using ``handle``, via
/// `RoutexClient.registerRedirectURI` to receive the URL to send the
/// user to.
public struct RedirectHandle: Sendable, Hashable, Codable {
    /// Server-issued handle to identify the pending redirect.
    public let handle: String
    /// Continuation token for the per-service `confirm` method.
    public let context: ConfirmationContext

    /// Build a `RedirectHandle`.
    public init(handle: String, context: ConfirmationContext) {
        self.handle = handle
        self.context = context
    }
}
