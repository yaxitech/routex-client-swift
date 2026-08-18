import Foundation

/// Continuation token returned with a
/// ``DialogInput/selection(options:context:)`` or a
/// ``DialogInput/field(type:secrecyLevel:minLength:maxLength:context:)``.
/// Pass back to the per-service `respond` method together with the user's
/// answer.
public struct InputContext: Sendable, Hashable, Base64BytesCoding {
    /// Raw token bytes. On the wire encoded as base64.
    public let bytes: Data
    /// Wrap raw token bytes.
    public init(_ bytes: Data) { self.bytes = bytes }
}
