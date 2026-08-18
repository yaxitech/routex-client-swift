import Foundation

/// Settlement state of a ``Transaction``.
public enum TransactionStatus: String, Sendable, Codable, Hashable, CaseIterable {
    /// The transaction is expected / planned.
    case pending = "Pending"
    /// The transaction is booked to the account. This is typically the
    /// final state for most accounts.
    case booked = "Booked"
    /// The credit card transaction is booked and invoiced but not yet paid.
    case invoiced = "Invoiced"
    /// The credit card transaction is paid. This is typically the final
    /// state for card accounts.
    case paid = "Paid"
    /// The transaction has been canceled in some way.
    case canceled = "Canceled"
}
