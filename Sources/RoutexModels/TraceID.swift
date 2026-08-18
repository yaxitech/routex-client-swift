import Foundation

/// Identifier of a single request across the routex trace pipeline.
///
/// Read off `RoutexClient.traceID` after a request and pass back to
/// `RoutexClient.trace(...)` to retrieve the server-side diagnostic blob.
public struct TraceID: Sendable, Hashable, Base64BytesCoding {
    /// Raw bytes. On the wire encoded as base64.
    public let bytes: Data
    /// Wrap raw bytes.
    public init(_ bytes: Data) { self.bytes = bytes }
}
