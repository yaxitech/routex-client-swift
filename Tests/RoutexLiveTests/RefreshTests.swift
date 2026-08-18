import Foundation
import RoutexClient
import RoutexModels
import RoutexRefresh
import RoutexTickets
import Testing

/// Capture `connectionData` from an interactive flow, then replay it through
/// `RoutexRefreshClient` to reach accounts, balances, and transactions
/// without any further interaction.
@Suite("Live: refresh", .enabled(if: LiveEnvironment.isAvailable))
struct RefreshTests {
    private static let demoAccount = AccountReference(
        id: .iban(DemoData.demoAccountIBAN),
        currency: "EUR"
    )

    /// Non-interactive transactions trigger SCA for windows of 90 days or
    /// more, so stay just under that.
    private static let recentRange: TransactionsRange = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.timeZone = TimeZone(identifier: "UTC")
        return .period(
            from: try! ISODate(formatter.string(from: Date(timeIntervalSinceNow: -89 * 86_400))),
            to: nil
        )
    }()

    /// Drive an interactive balances flow (`userID: "result"` skips dialogs)
    /// with recurring consent and return its `connectionData`.
    private func capturedConnectionData(_ env: LiveEnvironment) async throws -> ConnectionData {
        let response = try await env.makeClient().balances(
            ticket: env.issuer.balances(),
            credentials: Credentials(connectionID: DemoData.demoConnection, userID: "result"),
            accounts: [Self.demoAccount],
            recurringConsents: true
        )
        guard case .result(let result) = response else {
            throw RefreshTestError.unexpected("expected .result, got \(response)")
        }
        return try #require(
            result.connectionData,
            "interactive flow should yield connectionData"
        )
    }

    @Test func refreshesAccountsBalancesAndTransactions() async throws {
        let env = try #require(LiveEnvironment.load())
        let connectionData = try await capturedConnectionData(env)
        let client = env.makeRefreshClient()

        let accounts = try await client.accounts(
            ticket: env.issuer.accounts(),
            connectionData: connectionData,
            fields: AccountField.allCases
        )
        #expect(!accounts.result.isEmpty)

        let balances = try await client.balances(
            ticket: env.issuer.balances(),
            connectionData: connectionData,
            accounts: [Self.demoAccount]
        )
        #expect(!balances.result.balances.isEmpty)
        let balance = try #require(balances.result.balances.first?.balances.first)
        #expect(balance.dateTime != nil)

        let transactions = try await client.transactions(
            ticket: env.issuer.transactions(account: Self.demoAccount, range: Self.recentRange),
            connectionData: connectionData
        )
        #expect(transactions.result != nil)
    }
}

private enum RefreshTestError: Error { case unexpected(String) }
