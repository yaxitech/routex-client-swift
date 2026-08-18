import Foundation

/// Result returned by `RoutexClient.accounts(...)`.
public struct AccountsResult: RoutexResult {
    /// List of accounts populated according to the request's
    /// ``AccountField`` set and ``AccountFilter``.
    public let data: [Account]
    /// Identifier of the originating ``AccountsTicket``.
    public let ticketID: UUID
    /// Server-side timestamp at which the result was produced.
    public let timestamp: Date

    /// Build an `AccountsResult`.
    public init(data: [Account], ticketID: UUID, timestamp: Date) {
        self.data = data
        self.ticketID = ticketID
        self.timestamp = timestamp
    }
}
