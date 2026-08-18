import Foundation

/// Categories of a ``Balance`` reading at a point in time.
public enum BalanceType: String, Sendable, Codable, Hashable, CaseIterable {
    /// Balance from booked transactions.
    case booked = "Booked"
    /// Available balance from booked transactions.
    ///
    /// Depending on the bank, a credit line may or may not be included
    /// (see ``Balance/creditLimitIncluded``). For the most current balance
    /// without credit, prefer ``booked`` and judge recency by
    /// ``Balance/dateTime``.
    case available = "Available"
    /// Expected balance from booked and pending transactions.
    case expected = "Expected"
}
