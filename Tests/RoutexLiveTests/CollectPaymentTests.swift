import Foundation
import RoutexClient
import RoutexModels
import Testing

@Suite("Live: collectPayment (debtor identification)", .enabled(if: LiveEnvironment.isAvailable))
struct CollectPaymentTests {
    @Test func resultUserReturnsDebtorIdentification() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try DemoData.collectPaymentTicket(env.issuer)

        let response = try await client.collectPayment(
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

        #expect(decoded.data.debtorIBAN != nil, "expected debtorIBAN populated")
        #expect(decoded.data.debtorName != nil, "expected debtorName populated")
    }
}
