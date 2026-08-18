import Foundation
import RoutexClient
import RoutexModels
import Testing

@Suite("Live: errors", .enabled(if: LiveEnvironment.isAvailable))
struct ErrorTests {
    @Test func expiredTicketSurfacesTicketError() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try env.expiredAccountsTicket()

        do {
            _ = try await client.info(
                ticket: ticket,
                connectionID: DemoData.demoConnection
            )
            Issue.record("expected ticketError(.expired) but call succeeded")
        } catch let e as RoutexError {
            guard case .ticketError(_, let code) = e else {
                Issue.record("expected ticketError, got \(e)")
                return
            }
            #expect(code == .expired, "expected .expired, got \(code)")
        }
    }

    @Test func unknownAPIKeySurfacesTicketError() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try env.unknownKeyAccountsTicket()

        do {
            _ = try await client.info(
                ticket: ticket,
                connectionID: DemoData.demoConnection
            )
            Issue.record("expected ticketError(.unknownKey) but call succeeded")
        } catch let e as RoutexError {
            guard case .ticketError(_, let code) = e else {
                Issue.record("expected ticketError, got \(e)")
                return
            }
            #expect(code == .unknownKey, "expected .unknownKey, got \(code)")
        }
    }

    @Test func unknownConnectionSurfacesNotFound() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try env.issuer.accounts()
        let unknown = ConnectionID(UUID())

        do {
            _ = try await client.info(ticket: ticket, connectionID: unknown)
            Issue.record("expected notFound but call succeeded")
        } catch let e as RoutexError {
            guard case .notFound = e else {
                Issue.record("expected .notFound, got \(e)")
                return
            }
        }
    }
}
