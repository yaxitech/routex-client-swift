import Foundation

/// A value returned by a YAXI Open Banking service.
///
/// Besides the value itself, it carries a timestamp and a ticket
/// identifier (bound to the input parameters of the originating call and
/// to the service type). Each service has its own concrete result type
/// whose ``Payload`` payload differs (e.g. `[Account]`, ``Balances``,
/// ``Transfer``).
public protocol RoutexResult: Sendable, Codable, Hashable {
    /// Concrete payload type for this service.
    associatedtype Payload: Sendable, Codable, Hashable
    /// The service-specific payload.
    var data: Payload { get }
    /// Identifier of the originating ``RoutexTicket``.
    var ticketID: UUID { get }
    /// Server-side timestamp at which the result was produced.
    var timestamp: Date { get }
    /// Memberwise initializer required by the default `Codable` glue.
    init(data: Payload, ticketID: UUID, timestamp: Date)
}

extension RoutexResult {
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: RoutexResultCodingKeys.self)
        let data = try c.decode(Payload.self, forKey: .data)
        let ticketID = try RoutexResultCoding.decodeUUID(
            c.decode(String.self, forKey: .ticketID)
        )
        let timestamp = try RoutexResultCoding.decodeISO8601(
            c.decode(String.self, forKey: .timestamp)
        )
        self.init(data: data, ticketID: ticketID, timestamp: timestamp)
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: RoutexResultCodingKeys.self)
        try c.encode(data, forKey: .data)
        try c.encode(ticketID.uuidString.lowercased(), forKey: .ticketID)
        try c.encode(RoutexResultCoding.encodeISO8601(timestamp), forKey: .timestamp)
    }
}

enum RoutexResultCodingKeys: String, CodingKey {
    case data
    case ticketID = "ticketId"
    case timestamp
}
