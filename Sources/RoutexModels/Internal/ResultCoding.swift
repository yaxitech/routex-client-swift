// Shared `Codable` helpers for ``RoutexResult`` payload types
// (UUID + ISO 8601 timestamp encoding/decoding).

import Foundation

enum RoutexResultCoding {
    static func decodeUUID(_ s: String) throws -> UUID {
        guard let uuid = UUID(uuidString: s) else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: [], debugDescription: "ticketId is not a UUID: \(s)")
            )
        }
        return uuid
    }

    static func decodeISO8601(_ s: String, field: String = "timestamp") throws -> Date {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime]
        if let d = f.date(from: s) { return d }
        throw DecodingError.dataCorrupted(
            .init(codingPath: [], debugDescription: "\(field) is not ISO 8601: \(s)")
        )
    }

    static func encodeISO8601(_ d: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.string(from: d)
    }
}
