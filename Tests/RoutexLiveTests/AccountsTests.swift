import Foundation
import RoutexClient
import RoutexModels
import Testing

@Suite("Live: accounts", .enabled(if: LiveEnvironment.isAvailable))
struct AccountsTests {
    @Test func resultUserReachesResult() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try env.issuer.accounts()

        let response = try await client.accounts(
            ticket: ticket,
            credentials: Credentials(connectionID: DemoData.demoConnection, userID: "result"),
            fields: AccountField.allCases
        )
        guard case .result(let result) = response else {
            Issue.record("expected .result, got \(response)")
            return
        }
        let decoded = try result.authenticated.decodeUnverified()

        #expect(!decoded.data.isEmpty, "expected at least one account in result")
    }
}
