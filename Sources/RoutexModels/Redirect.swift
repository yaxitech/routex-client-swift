import Foundation

/// User redirect.
///
/// Send the user to ``url``; once they return, resume the call by
/// passing ``context`` to the per-service `confirm` method.
///
/// A web application directs the user agent to ``url``; a desktop or
/// mobile application can open it in a browser or inside a `WebView`.
public struct Redirect: Sendable, Hashable, Codable {
    /// URL the user has to visit.
    public let url: URL
    /// Continuation token for the per-service `confirm` method.
    public let context: ConfirmationContext

    /// Build a `Redirect`.
    public init(url: URL, context: ConfirmationContext) {
        self.url = url
        self.context = context
    }
}
