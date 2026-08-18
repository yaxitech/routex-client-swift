import Foundation

/// A calendar date or instant.
///
/// Carries one of three ISO 8601 representations:
/// - ``date(_:)`` for `"YYYY-MM-DD"`,
/// - ``naiveDateTime(_:)`` for `"YYYY-MM-DDTHH:MM:SS"` (no offset),
/// - ``offsetDateTime(_:)`` for `"YYYY-MM-DDTHH:MM:SS±HH:MM"` or `"...Z"`.
///
/// The original wire string is preserved verbatim through encode and
/// decode; clients that need a `Date` should parse ``rawValue`` themselves
/// with the precision they want.
public enum ISODateTimeOrDate: Sendable, Hashable, Codable {
    /// Bare calendar date (e.g. `"2024-03-15"`).
    case date(ISODate)
    /// Local date-time without a time-zone offset.
    case naiveDateTime(String)
    /// Date-time with an explicit UTC offset or `Z` suffix.
    case offsetDateTime(String)

    /// The original wire string, unchanged.
    public var rawValue: String {
        switch self {
        case .date(let d): return d.rawValue
        case .naiveDateTime(let s), .offsetDateTime(let s): return s
        }
    }

    public init(from decoder: any Decoder) throws {
        let string = try decoder.singleValueContainer().decode(String.self)
        if string.contains("+") || string.contains("Z") || Self.hasNegativeOffset(string) {
            self = .offsetDateTime(string)
        } else if string.contains("T") {
            self = .naiveDateTime(string)
        } else {
            self = .date(try ISODate(string))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(rawValue)
    }

    private static func hasNegativeOffset(_ string: String) -> Bool {
        // Negative timezone offset comes after a "T...". A leading `-` is
        // part of the date.
        guard let tIdx = string.firstIndex(of: "T") else { return false }
        return string[string.index(after: tIdx)...].contains("-")
    }
}
