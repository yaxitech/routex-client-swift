import Foundation

/// Result returned by `RoutexClient.transfer(...)`.
public struct TransferResult: RoutexResult {
    /// The ``Transfer`` payload.
    public let data: Transfer
    /// Identifier of the originating ``TransferTicket``.
    public let ticketID: UUID
    /// Server-side timestamp at which the result was produced.
    public let timestamp: Date

    /// Build a `TransferResult`.
    public init(data: Transfer, ticketID: UUID, timestamp: Date) {
        self.data = data
        self.ticketID = ticketID
        self.timestamp = timestamp
    }
}
