import Foundation

/// Continuation token returned with a
/// ``DialogInput/confirmation(context:pollingDelay:)``, ``Redirect``,
/// or ``RedirectHandle``. Pass back to the per-service `confirm` method to
/// resume the service call.
public struct ConfirmationContext: Sendable, Hashable, Base64BytesCoding {
    /// Raw token bytes. On the wire encoded as base64.
    public let bytes: Data
    /// Wrap raw token bytes.
    public init(_ bytes: Data) { self.bytes = bytes }
}
