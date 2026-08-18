import Foundation

/// Result returned by `RoutexClient.collectPayment(...)`.
public struct CollectPaymentResult: RoutexResult {
    /// The ``PaymentInitiation`` payload.
    public let data: PaymentInitiation
    /// Identifier of the originating ``CollectPaymentTicket``.
    public let ticketID: UUID
    /// Server-side timestamp at which the result was produced.
    public let timestamp: Date

    /// Build a `CollectPaymentResult`.
    public init(data: PaymentInitiation, ticketID: UUID, timestamp: Date) {
        self.data = data
        self.ticketID = ticketID
        self.timestamp = timestamp
    }
}
