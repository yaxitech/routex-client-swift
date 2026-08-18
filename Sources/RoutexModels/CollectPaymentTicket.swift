import Foundation

/// Ticket authorizing a single `RoutexClient.collectPayment(...)` call.
public struct CollectPaymentTicket: RoutexTicket {
    public typealias ResultData = CollectPaymentResult
    public let raw: String
    public let id: UUID

    /// Parse a backend-issued JWT for the collect-payment service.
    public init(_ raw: String) throws {
        self.raw = raw
        self.id = try TicketDecoder.parse(raw, expectingService: "CollectPayment")
    }
}

extension CollectPaymentTicket: ServiceTicket {
    package static let servicePath = "collect-payment"
}
