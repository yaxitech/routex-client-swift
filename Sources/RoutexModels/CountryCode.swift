import Foundation

/// ISO 3166-1 alpha-2 country code (e.g. `"DE"`, `"FR"`).
///
/// Stored as the bare two-letter string. Construction does not validate
/// against the ISO list, so values returned by older servers round-trip
/// transparently even if they are not currently registered.
public struct CountryCode: Sendable, Hashable, Codable, RawRepresentable, CustomStringConvertible {
    /// Raw two-letter code as it appears on the wire.
    public let rawValue: String

    /// Build a `CountryCode` from a two-letter code. Not validated.
    public init(_ rawValue: String) { self.rawValue = rawValue }
    /// `RawRepresentable` initializer mirroring ``init(_:)``.
    public init(rawValue: String) { self.rawValue = rawValue }

    public var description: String { rawValue }
}
