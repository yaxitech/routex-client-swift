import Foundation
import RoutexClient
import RoutexModels
import Testing

/// First call walks a `Field` dialog and captures the result's
/// `connectionData`. The second call carries that connection data and the
/// same userID; the bank skips authentication and reaches a `Result`
/// without re-prompting.
@Suite("Live: connection-data replay", .enabled(if: LiveEnvironment.isAvailable))
struct ConnectionDataReplayTests {
    @Test func replayedConnectionDataSkipsDialog() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()

        // First call: full interactive flow, capture connectionData.
        let firstTicket = try env.issuer.accounts()
        let initial = try await client.accounts(
            ticket: firstTicket,
            credentials: Credentials(
                connectionID: DemoData.demoConnection,
                userID: "input"
            ),
            fields: AccountField.allCases,
            recurringConsents: true
        )
        guard case .dialog(let dialog) = initial,
            case .field(_, _, _, _, let context) = dialog.input
        else {
            Issue.record("expected field dialog, got \(initial)")
            return
        }
        let resolved = try await client.respondAccounts(
            ticket: firstTicket,
            context: context,
            response: "133742"
        )
        guard case .result(let result) = resolved else {
            Issue.record("expected .result, got \(resolved)")
            return
        }
        let connectionData = try #require(
            result.connectionData,
            "first call should yield connectionData"
        )

        // Second call: replay connectionData, expect no dialog.
        let secondTicket = try env.issuer.accounts()
        let response = try await client.accounts(
            ticket: secondTicket,
            credentials: Credentials(
                connectionID: DemoData.demoConnection,
                userID: "input",
                connectionData: connectionData
            ),
            fields: AccountField.allCases,
            recurringConsents: true
        )
        guard case .result(let result) = response else {
            Issue.record("expected .result, got \(response)")
            return
        }
        let decoded = try result.authenticated.decodeUnverified()
        #expect(!decoded.data.isEmpty)
    }
}
