import Foundation
import RoutexClient
import RoutexModels
import Testing

@Suite("Live: standing orders", .enabled(if: LiveEnvironment.isAvailable))
struct StandingOrdersTests {
    @Test func resultUserReturnsStandingOrders() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticketID = UUID()
        let ticket = try env.issuer.standingOrders(
            account: AccountReference(id: .iban(DemoData.demoAccountIBAN), currency: "EUR"),
            ticketID: ticketID
        )

        let response = try await client.standingOrders(
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
        #expect(decoded.ticketID == ticketID)
        #expect(abs(decoded.timestamp.timeIntervalSinceNow) < 60)

        let orders = decoded.data
        try #require(orders.count == 2, "unexpected standing orders: \(orders)")
        let rent = orders[0]
        let broadcasting = orders[1]

        #expect(rent.startDate == (try ISODate("2023-02-01")))
        #expect(rent.frequency == .months(1))
        #expect(rent.executionRule == .following)
        #expect(rent.day == 1)
        #expect(rent.amount == Amount(amount: 1000, currency: "EUR"))
        #expect(rent.creditor?.iban == "DE89370400440532013000")

        #expect(broadcasting.frequency == .variableMonths([.january, .april, .july, .october]))
        #expect(broadcasting.amount == Amount(amount: Decimal(string: "55.08")!, currency: "EUR"))
    }

    @Test func unknownAccountIsNotFound() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try env.issuer.standingOrders(
            account: AccountReference(id: .iban("NL31YAXI1234567891"), currency: "EUR")
        )

        await #expect(throws: RoutexError.notFound) {
            _ = try await client.standingOrders(
                ticket: ticket,
                credentials: Credentials(
                    connectionID: DemoData.demoConnection,
                    userID: "result"
                )
            )
        }
    }
}
