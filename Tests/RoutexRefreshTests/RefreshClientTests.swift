import Foundation
import RoutexCore
import RoutexModels
import RoutexTransport
import Testing

@testable import RoutexRefresh

@Suite("Refresh client: request/response shapes")
struct RefreshClientTests {
    private func makeClient(
        _ responses: [HTTPResponse],
        userInSession: UserInSession? = nil
    ) -> (RoutexRefreshClient, StubTransport) {
        let transport = StubTransport(responses)
        let core = RoutexClientCore(
            baseURL: URL(string: "https://example")!,
            transport: transport,
            settlementFactory: { _ in PassthroughSettlement() }
        )
        return (RoutexRefreshClient(core: core, userInSession: userInSession), transport)
    }

    @Test("accounts() posts connectionData to /non-interactive and decodes the envelope")
    func accountsRoundTrip() async throws {
        let ticket = try AccountsTicket(sampleTicket(service: "Accounts"))
        let body = Data(
            #"{"result":[{"iban":"DE89370400440532013000","currency":"EUR"}],"session":"AQID","connectionData":"BAUG"}"#
                .utf8
        )
        let (client, transport) = makeClient([HTTPResponse(status: 200, headers: [:], body: body)])

        let response = try await client.accounts(
            ticket: ticket,
            connectionData: ConnectionData(Data([9, 9])),
            fields: [.iban, .currency]
        )

        #expect(response.result.first?.iban == "DE89370400440532013000")
        #expect(response.session == Session(Data([1, 2, 3])))
        #expect(response.connectionData == ConnectionData(Data([4, 5, 6])))

        let request = try #require(await transport.recorded().first)
        #expect(request.url.path.hasSuffix("accounts/non-interactive"))
        let sent = try #require(request.body)
        #expect(String(decoding: sent, as: UTF8.self).contains("\"connectionData\":\"CQk=\""))
    }

    @Test("balances() posts to /non-interactive and decodes a Balances envelope")
    func balancesRoundTrip() async throws {
        let ticket = try BalancesTicket(sampleTicket(service: "Balances"))
        let body = Data(
            #"""
            {"result":{"balances":[{"account":{"iban":"DE89370400440532013000","currency":"EUR"},
            "balances":[{"amount":"3.14","currency":"EUR","balanceType":"Booked",
            "dateTime":"1970-01-01T00:00:01.500Z"}]}],"missingAccounts":[]},"session":"AQID"}
            """#.utf8
        )
        let (client, transport) = makeClient([HTTPResponse(status: 200, headers: [:], body: body)])

        let response = try await client.balances(
            ticket: ticket,
            connectionData: ConnectionData(Data([7])),
            accounts: [AccountReference(id: .iban("DE89370400440532013000"), currency: "EUR")]
        )

        #expect(response.result.missingAccounts.isEmpty)
        #expect(response.session == Session(Data([1, 2, 3])))
        let balance = try #require(response.result.balances.first?.balances.first)
        #expect(balance.dateTime == Date(timeIntervalSince1970: 1.5))

        let request = try #require(await transport.recorded().first)
        #expect(request.url.path.hasSuffix("balances/non-interactive"))
    }

    @Test("transactions() decodes a null result as nil")
    func transactionsNullResult() async throws {
        let ticket = try TransactionsTicket(sampleTicket(service: "Transactions"))
        let body = Data(#"{"result":null}"#.utf8)
        let (client, transport) = makeClient([HTTPResponse(status: 200, headers: [:], body: body)])

        let response = try await client.transactions(
            ticket: ticket,
            connectionData: ConnectionData(Data([1]))
        )

        #expect(response.result == nil)
        #expect(response.session == nil)

        // Without a user in session (the default), the field stays off the wire.
        let sent = try #require(await transport.recorded().first?.body)
        #expect(!String(decoding: sent, as: UTF8.self).contains("userInSession"))
    }

    @Test(
        "userInSession rides along in every request body",
        arguments: [
            (UserInSession.onThisConnection, "connection"),
            (.at("203.0.113.7"), "203.0.113.7"),
        ]
    )
    func userInSessionOnTheWire(userInSession: UserInSession, wire: String) async throws {
        let ticket = try TransactionsTicket(sampleTicket(service: "Transactions"))
        let body = Data(#"{"result":null}"#.utf8)
        let (client, transport) = makeClient(
            [HTTPResponse(status: 200, headers: [:], body: body)],
            userInSession: userInSession
        )

        _ = try await client.transactions(
            ticket: ticket,
            connectionData: ConnectionData(Data([1]))
        )

        let sent = try #require(await transport.recorded().first?.body)
        #expect(String(decoding: sent, as: UTF8.self).contains(#""userInSession":"\#(wire)""#))
    }
}
