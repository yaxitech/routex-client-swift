import Foundation

/// Short-lived session token returned by the bank.
///
/// Pass back into subsequent calls in the same flow (via the `session:`
/// parameter on each service method) to avoid repeating authentication
/// steps. Treat as single-use; discard once a new one is returned.
public struct Session: Sendable, Hashable, Base64BytesCoding {
    /// Raw token bytes. On the wire encoded as base64.
    public let bytes: Data
    /// Wrap raw token bytes.
    public init(_ bytes: Data) { self.bytes = bytes }
}
