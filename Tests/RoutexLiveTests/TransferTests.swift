import Foundation
import RoutexClient
import RoutexModels
import Testing

@Suite("Live: transfer", .enabled(if: LiveEnvironment.isAvailable))
struct TransferTests {
    @Test func sepaCreditTransferReachesResult() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try env.issuer.transfer()

        let initial = try await client.transfer(
            ticket: ticket,
            credentials: Credentials(
                connectionID: DemoData.demoConnection,
                userID: "confirmation"
            ),
            product: .sepaCreditTransfer,
            details: DemoData.transferDetails,
            debtorAccount: DebtorAccountReference(id: .iban(DemoData.demoAccountIBAN))
        )
        guard case .dialog(let dialog) = initial,
            case .confirmation(let context, _) = dialog.input
        else {
            Issue.record("expected confirmation dialog, got \(initial)")
            return
        }
        let final = try await client.confirmTransfer(ticket: ticket, context: context)
        guard case .result(let result) = final else {
            Issue.record("expected .result, got \(final)")
            return
        }
        _ = try result.authenticated.decodeUnverified()
    }
}
