import Foundation
import JWTKit

/// Represents `null`  in JSON
struct Null: JWTPayload {
    func verify(using algorithm: some JWTKit.JWTAlgorithm) async throws {
    }
}

extension Null: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if !container.decodeNil() {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Expected nil, got value"))
        }
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encodeNil()
    }
}

struct AccountIdentifier: Codable {
    var iban: String
}

struct Amount: Codable {
    var currency: String
    var amount: String
}

struct CollectPaymentData: Codable {
    var amount: Amount
    var creditorAccount: AccountIdentifier
    var creditorName: String
    var remittance: String
}

struct ServiceData<T: Codable & Sendable>: Codable {
    var id: String
    var service: String
    var data: T?
}

struct Ticket<T: Codable & Sendable>: JWTPayload {
    var exp: ExpirationClaim
    var data: ServiceData<T>
    
    func verify(using algorithm: some JWTKit.JWTAlgorithm) async throws {
    }
}

func issueTicket<T: Codable & Sendable>(service: String, _ data: T = Null()) async throws -> (ticket: String, id: String) {
    let keys = JWTKeyCollection()
    let keyId = JWKIdentifier(string: ProcessInfo.processInfo.environment["KEY_ID"]!)
    let key = HMACKey(from: Data(base64Encoded: ProcessInfo.processInfo.environment["KEY"]!)!)
    await keys.add(hmac: key, digestAlgorithm: .sha256, kid: keyId)
    // Throw away decimals
    let expDateEpoch = Date(timeIntervalSinceNow: 10 * 60).timeIntervalSince1970.rounded(.towardZero)
    let id = UUID().uuidString
    let ticket = Ticket(exp: ExpirationClaim(value: Date(timeIntervalSince1970: expDateEpoch)),
                        data: ServiceData(id: id, service: service, data: data))
    return (ticket: try await keys.sign(ticket, kid: keyId), id: id)
}
