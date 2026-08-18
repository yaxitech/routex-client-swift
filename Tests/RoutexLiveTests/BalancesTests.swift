import Foundation
import RoutexClient
import RoutexModels
import Testing

@Suite("Live: balances", .enabled(if: LiveEnvironment.isAvailable))
struct BalancesTests {
    @Test func confirmationFlowReturnsBalances() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try env.issuer.balances()

        let initial = try await client.balances(
            ticket: ticket,
            credentials: Credentials(
                connectionID: DemoData.demoConnection,
                userID: "confirmation"
            ),
            accounts: [AccountReference(id: .iban(DemoData.demoAccountIBAN), currency: "EUR")]
        )
        guard case .dialog(let dialog) = initial,
            case .confirmation(let context, _) = dialog.input
        else {
            Issue.record("expected confirmation dialog, got \(initial)")
            return
        }
        let final = try await client.confirmBalances(ticket: ticket, context: context)
        guard case .result(let result) = final else {
            Issue.record("expected .result, got \(final)")
            return
        }
        let decoded = try result.authenticated.decodeUnverified()

        #expect(!decoded.data.balances.isEmpty)
    }
}
