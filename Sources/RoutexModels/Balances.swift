import Foundation

/// Result payload returned by `RoutexClient.balances(...)`.
public struct Balances: Sendable, Hashable, Codable {
    /// Per-account balance lists.
    public let balances: [AccountBalances]
    /// Accounts that were requested but not found.
    public let missingAccounts: [AccountReference]

    /// Build a `Balances` payload.
    public init(balances: [AccountBalances], missingAccounts: [AccountReference] = []) {
        self.balances = balances
        self.missingAccounts = missingAccounts
    }

    private enum CodingKeys: String, CodingKey { case balances, missingAccounts }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.balances = try c.decode([AccountBalances].self, forKey: .balances)
        self.missingAccounts =
            try c.decodeIfPresent([AccountReference].self, forKey: .missingAccounts) ?? []
    }
}
