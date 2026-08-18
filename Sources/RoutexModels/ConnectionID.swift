import Foundation

/// Identifier of a specific service connection.
///
/// Wire format is `"connection-{uuid}"`; bare UUIDs are also accepted on
/// input and normalized to the prefixed form when re-encoded.
public struct ConnectionID: Sendable, Hashable, Codable, CustomStringConvertible {
    /// The underlying UUID.
    public let uuid: UUID

    /// Build from a `UUID` directly.
    public init(_ uuid: UUID) { self.uuid = uuid }

    /// Parse `"connection-{uuid}"` or a bare UUID string.
    /// - Throws: ``ConnectionIDError/invalid(_:)`` if the input is not a
    ///   well-formed UUID, optionally prefixed with `connection-`.
    public init(_ string: String) throws {
        let prefix = "connection-"
        let raw = string.hasPrefix(prefix) ? String(string.dropFirst(prefix.count)) : string
        guard let uuid = UUID(uuidString: raw) else {
            throw ConnectionIDError.invalid(string)
        }
        self.uuid = uuid
    }

    public init(from decoder: any Decoder) throws {
        let s = try decoder.singleValueContainer().decode(String.self)
        try self.init(s)
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(description)
    }

    public var description: String { "connection-\(uuid.uuidString.lowercased())" }
}
