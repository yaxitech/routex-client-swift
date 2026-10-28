import Foundation

/// Execution frequency of a ``StandingOrder``.
public enum Frequency: Sendable, Hashable, Codable {
    /// Frequency in days.
    case days(UInt32)
    /// Frequency in months.
    case months(UInt32)
    /// Specific months that the standing order is scheduled for.
    case variableMonths([Month])

    private enum Tag: String, CodingKey {
        case days
        case months
        case variableMonths
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: Tag.self)
        guard c.allKeys.count == 1, let tag = c.allKeys.first else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Expected one tag for Frequency"
                )
            )
        }
        switch tag {
        case .days: self = .days(try c.decode(UInt32.self, forKey: tag))
        case .months: self = .months(try c.decode(UInt32.self, forKey: tag))
        case .variableMonths: self = .variableMonths(try c.decode([Month].self, forKey: tag))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: Tag.self)
        switch self {
        case .days(let n): try c.encode(n, forKey: .days)
        case .months(let n): try c.encode(n, forKey: .months)
        case .variableMonths(let months): try c.encode(months, forKey: .variableMonths)
        }
    }
}
