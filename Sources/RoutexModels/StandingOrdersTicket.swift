import Foundation

/// Ticket authorizing a single `RoutexClient.standingOrders(...)` call.
public struct StandingOrdersTicket: RoutexTicket {
    public typealias ResultData = StandingOrdersResult
    public let raw: String
    public let id: UUID

    /// Parse a backend-issued JWT for the standing orders service.
    public init(_ raw: String) throws {
        self.raw = raw
        self.id = try TicketDecoder.parse(raw, expectingService: "StandingOrders")
    }
}

extension StandingOrdersTicket: ServiceTicket {
    package static let servicePath = "standing-orders"
}
