import Foundation

/// ISO 8601 calendar date (`yyyy-MM-dd`), as carried on the wire.
///
/// Foundation has no calendar-date type, so the wire string is stored
/// verbatim; parse ``rawValue`` with the precision the caller needs.
public struct ISODate: Sendable, Hashable, Codable, CustomStringConvertible {
    /// The `yyyy-MM-dd` string as it appears on the wire.
    public let rawValue: String

    /// Parse a `yyyy-MM-dd` string.
    /// - Throws: ``ISODateError/invalid(_:)`` when the input is not a
    ///   well-formed calendar date.
    public init(_ rawValue: String) throws {
        guard Self.components(rawValue) != nil else { throw ISODateError.invalid(rawValue) }
        self.rawValue = rawValue
    }

    public init(from decoder: any Decoder) throws {
        try self.init(decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(rawValue)
    }

    public var description: String { rawValue }

    /// The instant this date starts at in `timeZone`. A calendar date names no
    /// instant by itself, so the caller picks the zone.
    public func date(in timeZone: TimeZone) -> Date {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        return calendar.date(from: Self.components(rawValue)!)!
    }

    /// `yyyy-MM-dd` whose day exists in that month, or `nil`.
    private static func components(_ string: String) -> DateComponents? {
        let parts = string.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 3,
            parts[0].count == 4, parts[1].count == 2, parts[2].count == 2,
            parts.allSatisfy({ $0.allSatisfy { $0.isASCII && $0.isNumber } }),
            let year = Int(parts[0]), let month = Int(parts[1]), let day = Int(parts[2])
        else {
            return nil
        }
        var components = DateComponents()
        components.calendar = Calendar(identifier: .gregorian)
        components.year = year
        components.month = month
        components.day = day
        return components.isValidDate ? components : nil
    }
}

/// Errors thrown when parsing an ``ISODate`` from a string.
public enum ISODateError: Error, Sendable, Equatable {
    /// Input was not a well-formed `yyyy-MM-dd` calendar date. The associated
    /// value is the original string.
    case invalid(String)
}
