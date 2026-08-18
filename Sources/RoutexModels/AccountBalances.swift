import Foundation

/// Group of balances (of different ``BalanceType``s) belonging to a single
/// account.
public struct AccountBalances: Sendable, Hashable, Codable {
    /// The account these balances belong to.
    public let account: AccountReference
    /// Balances of different types for the account.
    public let balances: [Balance]

    /// Build an `AccountBalances`.
    public init(account: AccountReference, balances: [Balance]) {
        self.account = account
        self.balances = balances
    }
}
