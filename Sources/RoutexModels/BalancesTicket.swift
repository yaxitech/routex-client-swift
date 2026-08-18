import Foundation

/// Ticket authorizing a single `RoutexClient.balances(...)` call.
public struct BalancesTicket: RoutexTicket {
    public typealias ResultData = BalancesResult
    public let raw: String
    public let id: UUID

    /// Parse a backend-issued JWT for the balances service.
    public init(_ raw: String) throws {
        self.raw = raw
        self.id = try TicketDecoder.parse(raw, expectingService: "Balances")
    }
}

extension BalancesTicket: ServiceTicket {
    package static let servicePath = "balances"
}
