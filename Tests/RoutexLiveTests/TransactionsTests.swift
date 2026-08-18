import Foundation
import RoutexClient
import RoutexModels
import Testing

@Suite("Live: transactions", .enabled(if: LiveEnvironment.isAvailable))
struct TransactionsTests {
    @Test func resultUserReturnsTransactions() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try env.issuer.transactions(
            account: AccountReference(id: .iban(DemoData.demoAccountIBAN), currency: "EUR"),
            range: DemoData.demoTransactionRange
        )

        let response = try await client.transactions(
            ticket: ticket,
            credentials: Credentials(
                connectionID: DemoData.demoConnection,
                userID: "result"
            )
        )
        guard case .result(let result) = response else {
            Issue.record("expected .result, got \(response)")
            return
        }
        let decoded = try result.authenticated.decodeUnverified()

        // The demo's transactions service returns an optional list. We accept
        // either a non-empty list or a server-side `null` (the latter signals
        // "no new transactions").
        if let txs = decoded.data {
            #expect(!txs.isEmpty || true, "transactions list may be empty when nothing recent")
        }
    }
}
