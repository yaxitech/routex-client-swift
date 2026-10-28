import Foundation

/// Result returned by `RoutexClient.standingOrders(...)`.
public struct StandingOrdersResult: RoutexResult {
    /// List of the account's ``StandingOrder``s.
    public let data: [StandingOrder]
    /// Identifier of the originating ``StandingOrdersTicket``.
    public let ticketID: UUID
    /// Server-side timestamp at which the result was produced.
    public let timestamp: Date

    /// Build a `StandingOrdersResult`.
    public init(data: [StandingOrder], ticketID: UUID, timestamp: Date) {
        self.data = data
        self.ticketID = ticketID
        self.timestamp = timestamp
    }
}
