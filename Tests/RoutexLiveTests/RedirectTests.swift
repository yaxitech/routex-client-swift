import Foundation
import RoutexClient
import RoutexModels
import Testing

@Suite("Live: redirect interrupts", .enabled(if: LiveEnvironment.isAvailable))
struct RedirectTests {
    @Test func redirectViaSetRedirectUri() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        await client.setRedirectURI(DemoData.callbackURI)
        let ticket = try env.issuer.accounts()
        let follower = RedirectFollower()

        let initial = try await client.accounts(
            ticket: ticket,
            credentials: Credentials(
                connectionID: DemoData.demoConnection,
                userID: "redirect"
            ),
            fields: AccountField.allCases
        )
        guard case .redirect(let redirect) = initial else {
            Issue.record("expected redirect, got \(initial)")
            return
        }
        _ = try await follower.follow(redirect.url, terminate: "smoketest")
        let final = try await client.confirmAccounts(ticket: ticket, context: redirect.context)
        guard case .result(let result) = final else {
            Issue.record("expected .result, got \(final)")
            return
        }
        let decoded = try result.authenticated.decodeUnverified()

        #expect(!decoded.data.isEmpty)
    }

    @Test func redirectViaRegisterRedirectUri() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        // Note: no setRedirectURI here; the server responds with a
        // RedirectHandle that we resolve to a URL via registerRedirectURI.
        let ticket = try env.issuer.accounts()
        let follower = RedirectFollower()

        let initial = try await client.accounts(
            ticket: ticket,
            credentials: Credentials(
                connectionID: DemoData.demoConnection,
                userID: "redirect"
            ),
            fields: AccountField.allCases
        )
        guard case .redirectHandle(let handle) = initial else {
            Issue.record("expected redirectHandle, got \(initial)")
            return
        }
        let url = try await client.registerRedirectURI(
            ticket: ticket,
            handle: handle.handle,
            redirectURI: DemoData.callbackURI
        )
        _ = try await follower.follow(url, terminate: "smoketest")
        let final = try await client.confirmAccounts(ticket: ticket, context: handle.context)
        guard case .result(let result) = final else {
            Issue.record("expected .result, got \(final)")
            return
        }
        let decoded = try result.authenticated.decodeUnverified()

        #expect(!decoded.data.isEmpty)
    }
}
