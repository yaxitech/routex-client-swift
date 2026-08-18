import Foundation
import RoutexClient
import RoutexModels
import Testing

@Suite("Live: discovery", .enabled(if: LiveEnvironment.isAvailable))
struct DiscoveryTests {
    @Test func infoOnDemoReturnsExpectedShape() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try env.issuer.accounts()

        let info = try await client.info(
            ticket: ticket,
            connectionID: DemoData.demoConnection
        )

        #expect(info.id == DemoData.demoConnection)
        #expect(!info.displayName.isEmpty)
        #expect(!info.logoID.isEmpty)
        // Demo only requires `userID`.
        #expect(info.credentials.userID)
        #expect(!info.credentials.full)
    }

    @Test func searchByTermReturnsMatches() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try env.issuer.accounts()

        let results = try await client.search(
            ticket: ticket,
            filters: [.term("sparkasse")],
            details: [.bics, .bankCodes]
        )

        #expect(!results.isEmpty)
        for r in results {
            #expect(!r.displayName.isEmpty)
        }
    }

    @Test func traceIdMutatesAcrossCalls() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try env.issuer.accounts()

        _ = try await client.info(
            ticket: ticket,
            connectionID: DemoData.demoConnection
        )
        let first = await client.traceID

        _ = try await client.search(
            ticket: ticket,
            filters: [.term("sparkasse")]
        )
        let second = await client.traceID

        #expect(first != nil)
        #expect(second != nil)
        #expect(first != second)
    }

    @Test func traceFetchReturnsNonEmptyBlob() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try env.issuer.accounts()

        _ = try await client.info(
            ticket: ticket,
            connectionID: DemoData.demoConnection
        )
        let traceID = try #require(await client.traceID)

        let blob = try await client.trace(ticket: ticket, traceID: traceID)
        #expect(!blob.isEmpty)
    }
}
