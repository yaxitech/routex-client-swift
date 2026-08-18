import Foundation

/// Long-lived per-connection state.
///
/// Persist alongside the user's credentials and pass back via
/// ``Credentials/connectionData`` on a future call to skip prompts the
/// original consent already covers. Required for recurring-consent flows.
public struct ConnectionData: Sendable, Hashable, Base64BytesCoding {
    /// Raw bytes. On the wire encoded as base64.
    public let bytes: Data
    /// Wrap raw bytes.
    public init(_ bytes: Data) { self.bytes = bytes }
}
