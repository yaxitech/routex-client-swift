import Foundation

/// Result returned by `RoutexClient.balances(...)`.
public struct BalancesResult: RoutexResult {
    /// Per-account ``Balance`` lists.
    public let data: Balances
    /// Identifier of the originating ``BalancesTicket``.
    public let ticketID: UUID
    /// Server-side timestamp at which the result was produced.
    public let timestamp: Date

    /// Build a `BalancesResult`.
    public init(data: Balances, ticketID: UUID, timestamp: Date) {
        self.data = data
        self.ticketID = ticketID
        self.timestamp = timestamp
    }
}
