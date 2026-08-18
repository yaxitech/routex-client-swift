import Foundation
import RoutexClient
import RoutexModels
import RoutexTickets
import Testing

/// Establish a consent with the demo `refresh` user, then replay its
/// `connectionData` through the interactive services in place of credentials.
@Suite("Live: services without credentials", .enabled(if: LiveEnvironment.isAvailable))
struct WithoutCredentialsTests {
    private static let demoAccount = AccountReference(
        id: .iban(DemoData.demoAccountIBAN),
        currency: "EUR"
    )

    /// Windows of 90 days or more cost the demo bank its SCA exemption, so
    /// stay just under that.
    private static let recentRange: TransactionsRange = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.timeZone = TimeZone(identifier: "UTC")
        return .period(
            from: try! ISODate(formatter.string(from: Date(timeIntervalSinceNow: -89 * 86_400))),
            to: nil
        )
    }()

    /// The demo `refresh` user answers the first call with a result, so its
    /// `connectionData` is reusable right away.
    private func establishedConnectionData(_ env: LiveEnvironment) async throws -> ConnectionData {
        let response = try await env.makeClient().accounts(
            ticket: try env.issuer.accounts(),
            credentials: Credentials(connectionID: DemoData.demoConnection, userID: "refresh"),
            fields: []
        )
        guard case .result(let result) = response else {
            throw WithoutCredentialsTestError.unexpected("expected .result, got \(response)")
        }
        return try #require(result.connectionData, "the demo refresh user should yield one")
    }

    @Test func runsAccountsBalancesAndTransactions() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let connectionData = try await establishedConnectionData(env)

        let accountsTicket = try env.issuer.accounts()
        let accounts = try await client.accounts(
            ticket: accountsTicket,
            connectionData: connectionData,
            fields: [.iban, .ownerName]
        )
        guard case .result(let accountsResult) = accounts else {
            throw WithoutCredentialsTestError.unexpected("expected .result, got \(accounts)")
        }
        let decoded = try accountsResult.authenticated.decodeUnverified()
        #expect(decoded.ticketID == accountsTicket.id)
        #expect(decoded.data.compactMap(\.iban) == [DemoData.demoAccountIBAN])

        let balances = try await client.balances(
            ticket: try env.issuer.balances(),
            connectionData: connectionData,
            accounts: [Self.demoAccount]
        )
        guard case .result(let balancesResult) = balances else {
            throw WithoutCredentialsTestError.unexpected("expected .result, got \(balances)")
        }
        #expect(!(try balancesResult.authenticated.decodeUnverified().data.balances.isEmpty))

        let transactions = try await client.transactions(
            ticket: try env.issuer.transactions(
                account: Self.demoAccount,
                range: Self.recentRange
            ),
            connectionData: connectionData
        )
        guard case .result(let transactionsResult) = transactions else {
            throw WithoutCredentialsTestError.unexpected("expected .result, got \(transactions)")
        }
        #expect(try transactionsResult.authenticated.decodeUnverified().data != nil)
    }

    /// A window the demo bank will not serve under an SCA exemption needs the
    /// user, which a call without credentials cannot bring.
    @Test func failsWithoutAnSCAExemption() async throws {
        let env = try #require(LiveEnvironment.load())
        let connectionData = try await establishedConnectionData(env)

        await #expect(throws: RoutexError.interruptError) {
            _ = try await env.makeClient().transactions(
                ticket: try env.issuer.transactions(
                    account: Self.demoAccount,
                    range: DemoData.demoTransactionRange
                ),
                connectionData: connectionData
            )
        }
    }
}

private enum WithoutCredentialsTestError: Error { case unexpected(String) }
