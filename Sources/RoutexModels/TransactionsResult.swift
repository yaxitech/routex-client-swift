import Foundation

/// Result returned by `RoutexClient.transactions(...)`.
///
/// ``data`` is `nil` when the bank returned no transaction list at all
/// (e.g. an asynchronous webhook delivery), and an empty array when the
/// bank returned an empty list. The wire form always carries `data` (with
/// the value `null` in the no-list case).
public struct TransactionsResult: RoutexResult {
    /// Optional list of ``Transaction``s. See type-level discussion for
    /// `nil` vs empty-array semantics.
    public let data: [Transaction]?
    /// Identifier of the originating ``TransactionsTicket``.
    public let ticketID: UUID
    /// Server-side timestamp at which the result was produced.
    public let timestamp: Date

    /// Build a `TransactionsResult`.
    public init(data: [Transaction]?, ticketID: UUID, timestamp: Date) {
        self.data = data
        self.ticketID = ticketID
        self.timestamp = timestamp
    }
}
