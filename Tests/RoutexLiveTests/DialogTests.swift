import Foundation
import RoutexClient
import RoutexModels
import Testing

@Suite("Live: dialog interrupts", .enabled(if: LiveEnvironment.isAvailable))
struct DialogTests {
    @Test func confirmationDialogResolvesViaConfirm() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try env.issuer.accounts()

        let initial = try await client.accounts(
            ticket: ticket,
            credentials: Credentials(
                connectionID: DemoData.demoConnection,
                userID: "confirmation"
            ),
            fields: AccountField.allCases
        )
        guard case .dialog(let dialog) = initial,
            case .confirmation(let context, _) = dialog.input
        else {
            Issue.record("expected confirmation dialog, got \(initial)")
            return
        }
        let final = try await client.confirmAccounts(ticket: ticket, context: context)
        guard case .result(let result) = final else {
            Issue.record("expected .result, got \(final)")
            return
        }
        let decoded = try result.authenticated.decodeUnverified()

        #expect(!decoded.data.isEmpty)
    }

    @Test func fieldDialogResolvesViaRespond() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try env.issuer.accounts()

        let initial = try await client.accounts(
            ticket: ticket,
            credentials: Credentials(
                connectionID: DemoData.demoConnection,
                userID: "input"
            ),
            fields: AccountField.allCases
        )
        guard case .dialog(let dialog) = initial,
            case .field(_, _, _, _, let context) = dialog.input
        else {
            Issue.record("expected field dialog, got \(initial)")
            return
        }
        let final = try await client.respondAccounts(
            ticket: ticket,
            context: context,
            response: "133742"
        )
        guard case .result(let result) = final else {
            Issue.record("expected .result, got \(final)")
            return
        }
        let decoded = try result.authenticated.decodeUnverified()

        #expect(!decoded.data.isEmpty)
    }
}
