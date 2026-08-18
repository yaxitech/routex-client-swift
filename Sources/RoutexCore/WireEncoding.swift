import Foundation
import RoutexModels

/// Body of a `search` request.
struct SearchRequestBody: Encodable, Sendable {
    var filters: [SearchFilter]
    var ibanDetection: Bool
    var limit: Int?
    var details: [ConnectionDetails]
}

/// Encoder and decoder used for all wire payloads.
package enum WireEncoding {
    private static let encoder = JSONEncoder()
    private static let decoder = JSONDecoder()

    package static func encode<T: Encodable>(_ value: T) throws -> Data {
        try encoder.encode(value)
    }

    package static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try decoder.decode(type, from: data)
    }
}
