import Foundation

/// Ticket authorizing a single `RoutexClient.transactions(...)` call.
public struct TransactionsTicket: RoutexTicket {
    public typealias ResultData = TransactionsResult
    public let raw: String
    public let id: UUID

    /// Parse a backend-issued JWT for the transactions service.
    public init(_ raw: String) throws {
        self.raw = raw
        self.id = try TicketDecoder.parse(raw, expectingService: "Transactions")
    }
}

extension TransactionsTicket: ServiceTicket {
    package static let servicePath = "transactions"
}
