import Foundation

/// Ed25519 signature attached to a ``SystemVersionEntry``.
public struct SystemVersionSignature: Sendable, Hashable, Codable {
    /// Identifier of the verifying key.
    public let keyID: String
    /// Base64-encoded raw 64-byte Ed25519 signature.
    public let value: String

    /// Build a `SystemVersionSignature`.
    public init(keyID: String, value: String) {
        self.keyID = keyID
        self.value = value
    }

    private enum CodingKeys: String, CodingKey {
        case keyID = "keyId"
        case value
    }
}
