import Foundation

/// Month of the year. Wire values are the month numbers, `1` (January)
/// through `12` (December).
public enum Month: UInt8, Sendable, Codable, Hashable, CaseIterable {
    case january = 1
    case february = 2
    case march = 3
    case april = 4
    case may = 5
    case june = 6
    case july = 7
    case august = 8
    case september = 9
    case october = 10
    case november = 11
    case december = 12
}
