import Foundation

/// Result payload returned by `RoutexClient.balances(...)`.
public struct Balances: Sendable, Hashable, Codable {
    /// Per-account balance lists.
    public let balances: [AccountBalances]

    /// Build a `Balances` payload.
    public init(balances: [AccountBalances]) {
        self.balances = balances
    }
}
