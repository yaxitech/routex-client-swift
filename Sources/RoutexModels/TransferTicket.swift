import Foundation

/// Ticket authorizing a single `RoutexClient.transfer(...)` call.
public struct TransferTicket: RoutexTicket {
    public typealias ResultData = TransferResult
    public let raw: String
    public let id: UUID

    /// Parse a backend-issued JWT for the transfer service.
    public init(_ raw: String) throws {
        self.raw = raw
        self.id = try TicketDecoder.parse(raw, expectingService: "Transfer")
    }
}

extension TransferTicket: ServiceTicket {
    package static let servicePath = "transfer"
}
