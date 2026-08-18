import Foundation
import RoutexClient
import RoutexModels
import RoutexSettlement
import Testing

@Suite("Live: settlement", .enabled(if: LiveEnvironment.isAvailable))
struct SettlementTests {
    @Test func settleYieldsSessionAndSystemVersion() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()

        // The first request triggers settlement; afterwards
        // `systemVersion(for:)` must be populated for that ticket.
        let ticket = try env.issuer.accounts()
        _ = try? await client.info(ticket: ticket, connectionID: DemoData.demoConnection)
        let entry = await client.systemVersion(for: ticket)
        let sv = try #require(entry, "settlement should publish a systemVersion entry")
        #expect(!sv.kind.isEmpty)
        #expect(sv.generation > 0)
        #expect(!sv.signature.keyID.isEmpty)
    }
}
