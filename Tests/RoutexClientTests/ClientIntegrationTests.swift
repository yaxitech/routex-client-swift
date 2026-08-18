import Foundation
import RoutexCore
import RoutexModels
import RoutexTransport
import Testing

@testable import RoutexClient

@Suite("Routex client: request/response shapes")
struct ClientIntegrationTests {

    /// Builds a known-valid AccountsTicket fixture for use in tests. The
    /// signature is not verified; only the payload structure is checked.
    static func sampleTicket(service: String = "Accounts", id: UUID = UUID()) -> String {
        let header = #"{"alg":"HS256","typ":"JWT","kid":"test"}"#
        let payload = """
            {"data":{"service":"\(service)","id":"\(id.uuidString)"},"exp":99999999999}
            """
        let h = Data(header.utf8).base64URLEncodedString
        let p = Data(payload.utf8).base64URLEncodedString
        return "\(h).\(p).fakesig"
    }

    /// Build a Result envelope: an OBResponse JSON wrapping an AccountsResult JWT.
    static func resultEnvelope(accounts: [Account]) throws -> Data {
        let result = AccountsResult(
            data: accounts,
            ticketID: UUID(uuidString: "00000000-0000-0000-0000-000000000000")!,
            timestamp: Date(timeIntervalSince1970: 1_704_067_200)  // 2024-01-01
        )
        struct Envelope: Encodable {
            let data: AccountsResult
            let exp: Int
        }
        let payload = try JSONEncoder().encode(Envelope(data: result, exp: 2_540_808_000))
        let header = Data(#"{"alg":"HS256","typ":"JWT","kid":"test"}"#.utf8)
        let jwt = "\(header.base64URLEncodedString).\(payload.base64URLEncodedString).fakesig"
        let response = #"{"Result":["\#(jwt)",null,null]}"#
        return Data(response.utf8)
    }

    @Test("accounts() decodes a Result envelope")
    func accountsResultRoundTrip() async throws {
        let raw = Self.sampleTicket(service: "Accounts")
        let ticket = try AccountsTicket(raw)

        let payload = try Self.resultEnvelope(accounts: [
            Account(
                iban: "DE89370400440532013000",
                currency: "EUR",
                status: .available,
                type: .current
            )
        ])
        let transport = StubTransport([
            HTTPResponse(status: 200, headers: ["yaxi-trace-id": "AQID"], body: payload)
        ])
        let core = RoutexClientCore(
            baseURL: URL(string: "https://example")!,
            transport: transport,
            settlementFactory: { _ in PassthroughSettlement() }
        )
        let client = RoutexClient(core: core)

        let response = try await client.accounts(
            ticket: ticket,
            credentials: Credentials(connectionID: .demo, userID: "result"),
            fields: [.iban, .currency, .status, .type]
        )

        guard case .result(let result) = response else {
            Issue.record("expected .result, got \(response)")
            return
        }
        let decoded = try result.authenticated.decodeUnverified()
        #expect(decoded.data.first?.iban == "DE89370400440532013000")

        // The trace id from the response header should be captured.
        let traceID = await client.traceID
        #expect(traceID != nil)
    }

    @Test("error responses dispatch to RoutexError")
    func errorDispatch() async throws {
        let raw = Self.sampleTicket(service: "Accounts")
        let ticket = try AccountsTicket(raw)

        let body = Data(#"{"InvalidCredentials":{"userMessage":"bad password"}}"#.utf8)
        let transport = StubTransport([
            HTTPResponse(status: 401, headers: [:], body: body)
        ])
        let core = RoutexClientCore(
            baseURL: URL(string: "https://example")!,
            transport: transport,
            settlementFactory: { _ in PassthroughSettlement() }
        )
        let client = RoutexClient(core: core)

        await #expect(throws: RoutexError.self) {
            _ = try await client.accounts(
                ticket: ticket,
                credentials: Credentials(connectionID: .demo, userID: "test"),
                fields: [.iban]
            )
        }
    }

    @Test("unknown error bodies stay in the RoutexError family")
    func unknownErrorDispatch() async throws {
        let raw = Self.sampleTicket(service: "Accounts")
        let ticket = try AccountsTicket(raw)

        let body = #"{"NotARoutexError":{}}"#
        let transport = StubTransport([
            HTTPResponse(status: 500, headers: [:], body: Data(body.utf8))
        ])
        let core = RoutexClientCore(
            baseURL: URL(string: "https://example")!,
            transport: transport,
            settlementFactory: { _ in PassthroughSettlement() }
        )
        let client = RoutexClient(core: core)

        await #expect(throws: RoutexError.unrecognizedResponse(status: 500, text: body)) {
            _ = try await client.accounts(
                ticket: ticket,
                credentials: Credentials(connectionID: .demo, userID: "test"),
                fields: [.iban]
            )
        }
    }

    @Test("accounts() without credentials sends connection data to the same endpoint")
    func accountsWithoutCredentials() async throws {
        let raw = Self.sampleTicket(service: "Accounts")
        let ticket = try AccountsTicket(raw)

        let payload = try Self.resultEnvelope(accounts: [Account(iban: "DE12")])
        let transport = StubTransport([
            HTTPResponse(status: 200, headers: [:], body: payload)
        ])
        let core = RoutexClientCore(
            baseURL: URL(string: "https://example")!,
            transport: transport,
            settlementFactory: { _ in PassthroughSettlement() }
        )
        let client = RoutexClient(core: core)

        let response = try await client.accounts(
            ticket: ticket,
            connectionData: ConnectionData(Data([1, 2, 3])),
            fields: [.iban]
        )
        guard case .result = response else {
            Issue.record("expected .result, got \(response)")
            return
        }

        let recorded = await transport.recorded()
        #expect(recorded.first?.url.path.hasSuffix("accounts/service") == true)
        let sent = try #require(recorded.first?.body)
        let json = String(decoding: sent, as: UTF8.self)
        #expect(json.contains(#""connectionData":"AQID""#))
        #expect(!json.contains("credentials"))
        #expect(!json.contains("recurringConsents"))
    }

    @Test("an InterruptError body dispatches to RoutexError.interruptError")
    func interruptErrorDispatch() async throws {
        let raw = Self.sampleTicket(service: "Transactions")
        let ticket = try TransactionsTicket(raw)

        let body = Data(#"{"InterruptError":{}}"#.utf8)
        let transport = StubTransport([
            HTTPResponse(status: 400, headers: [:], body: body)
        ])
        let core = RoutexClientCore(
            baseURL: URL(string: "https://example")!,
            transport: transport,
            settlementFactory: { _ in PassthroughSettlement() }
        )
        let client = RoutexClient(core: core)

        await #expect(throws: RoutexError.interruptError) {
            _ = try await client.transactions(
                ticket: ticket,
                connectionData: ConnectionData(Data([1, 2, 3]))
            )
        }
    }

    @Test("Field dialog: respond(...) routes to /response and returns the result")
    func respondToFieldDialog() async throws {
        let raw = Self.sampleTicket(service: "Accounts")
        let ticket = try AccountsTicket(raw)

        // First response: dialog asking for a 6-digit number
        let dialogJSON = #"""
            {"Dialog":{"context":"Sca","input":{"Field":{"context":"AQID","maxLength":6,"minLength":6,"secrecyLevel":"Otp","type":"Number"}},"message":"Enter TAN"}}
            """#
        // Second response: result
        let resultEnv = try Self.resultEnvelope(accounts: [
            Account(iban: "DE12", currency: "EUR")
        ])

        let transport = StubTransport([
            HTTPResponse(status: 200, headers: [:], body: Data(dialogJSON.utf8)),
            HTTPResponse(status: 200, headers: [:], body: resultEnv),
        ])
        let core = RoutexClientCore(
            baseURL: URL(string: "https://example")!,
            transport: transport,
            settlementFactory: { _ in PassthroughSettlement() }
        )
        let client = RoutexClient(core: core)

        let first = try await client.accounts(
            ticket: ticket,
            credentials: Credentials(connectionID: .demo, userID: "input"),
            fields: [.iban]
        )
        guard case .dialog(let dialog) = first,
            case .field(_, _, _, _, let context) = dialog.input
        else {
            Issue.record("expected Field dialog, got \(first)")
            return
        }
        let second = try await client.respondAccounts(
            ticket: ticket,
            context: context,
            response: "133742"
        )
        guard case .result(let result) = second else {
            Issue.record("expected .result, got \(second)")
            return
        }
        let decoded = try result.authenticated.decodeUnverified()
        #expect(decoded.data.first?.iban == "DE12")

        let recorded = await transport.recorded()
        #expect(recorded.count == 2)
        // The second request should have hit the /response endpoint.
        #expect(recorded[1].url.path.hasSuffix("/response"))
    }

    @Test("confirmTransactions routes to transactions/confirmation")
    func confirmTransactionsRouting() async throws {
        let raw = Self.sampleTicket(service: "Transactions")
        let ticket = try TransactionsTicket(raw)

        let body = Data(#"{"InvalidCredentials":{"userMessage":"x"}}"#.utf8)
        let transport = StubTransport([
            HTTPResponse(status: 401, headers: [:], body: body)
        ])
        let core = RoutexClientCore(
            baseURL: URL(string: "https://example")!,
            transport: transport,
            settlementFactory: { _ in PassthroughSettlement() }
        )
        let client = RoutexClient(core: core)

        await #expect(throws: RoutexError.self) {
            _ = try await client.confirmTransactions(
                ticket: ticket,
                context: ConfirmationContext(Data([1]))
            )
        }
        let recorded = await transport.recorded()
        #expect(recorded.first?.url.path.hasSuffix("transactions/confirmation") == true)
    }

    @Test("collectPayment sends the debtor account on the wire")
    func collectPaymentSendsDebtorAccount() async throws {
        let raw = Self.sampleTicket(service: "CollectPayment")
        let ticket = try CollectPaymentTicket(raw)

        let body = Data(#"{"InvalidCredentials":{"userMessage":"x"}}"#.utf8)
        let transport = StubTransport([
            HTTPResponse(status: 401, headers: [:], body: body)
        ])
        let core = RoutexClientCore(
            baseURL: URL(string: "https://example")!,
            transport: transport,
            settlementFactory: { _ in PassthroughSettlement() }
        )
        let client = RoutexClient(core: core)

        let account = DebtorAccountReference(id: .iban("DE89370400440532013000"), currency: "EUR")
        await #expect(throws: RoutexError.self) {
            _ = try await client.collectPayment(
                ticket: ticket,
                credentials: Credentials(connectionID: .demo, userID: "test"),
                account: account
            )
        }
        let recorded = await transport.recorded()
        #expect(recorded.first?.url.path.hasSuffix("collect-payment/service") == true)
        let sent = try #require(recorded.first?.body)
        let json = String(decoding: sent, as: UTF8.self)
        #expect(json.contains("DE89370400440532013000"))
        #expect(json.contains("EUR"))
    }

    @Test("AccountReference round-trips a non-IBAN number identifier")
    func accountReferenceNumberRoundTrip() throws {
        let ref = AccountReference(id: .number("1234567890"), currency: "EUR")
        let data = try JSONEncoder().encode(ref)
        #expect(String(decoding: data, as: UTF8.self).contains(#""number":"1234567890""#))
        #expect(try JSONDecoder().decode(AccountReference.self, from: data) == ref)
    }

    @Test("User-Agent header carries client version and platform")
    func userAgentHeaderShape() async throws {
        let raw = Self.sampleTicket(service: "Accounts")
        let ticket = try AccountsTicket(raw)
        let payload = try Self.resultEnvelope(accounts: [])
        let transport = StubTransport([
            HTTPResponse(status: 200, headers: [:], body: payload)
        ])
        let core = RoutexClientCore(
            baseURL: URL(string: "https://example")!,
            transport: transport,
            settlementFactory: { _ in PassthroughSettlement() }
        )
        let client = RoutexClient(core: core)
        _ = try await client.accounts(
            ticket: ticket,
            credentials: Credentials(connectionID: .demo, userID: "result"),
            fields: [.iban]
        )
        let recorded = await transport.recorded()
        let ua = try #require(recorded.first?.headers["User-Agent"])
        // `RoutexClient/{version} (swift; {os}; {arch})` - mirrors the Rust
        // client (`routex-client-common::for_distribution`).
        // Foundation's matcher, not `Regex`: the latter needs iOS 16 and the
        // package supports iOS 15, so `Regex` builds only because SwiftPM
        // raises test targets to macOS 14 and breaks on an iOS destination.
        let pattern = #"^RoutexClient/\d+\.\d+\.\d+ \(swift(; [a-z0-9_]+){0,2}\)$"#
        #expect(
            ua.range(of: pattern, options: .regularExpression) == ua.startIndex..<ua.endIndex,
            "unexpected User-Agent: \(ua)"
        )
    }

    @Test("search() rejects a negative limit before sending anything")
    func searchRejectsNegativeLimit() async throws {
        let ticket = try AccountsTicket(Self.sampleTicket(service: "Accounts"))
        let transport = StubTransport([])
        let core = RoutexClientCore(
            baseURL: URL(string: "https://example")!,
            transport: transport,
            settlementFactory: { _ in PassthroughSettlement() }
        )
        let client = RoutexClient(core: core)

        await #expect(throws: SearchError.negativeLimit(-1)) {
            _ = try await client.search(ticket: ticket, filters: [.term("yaxi")], limit: -1)
        }
        #expect(await transport.recorded().isEmpty)
    }
}

// MARK: - test fixtures

extension ConnectionID {
    fileprivate static let demo = ConnectionID(
        UUID(uuidString: "96386142-60E5-4CA9-ABCF-944EFCE5BC1E")!
    )
}

// MARK: - base64url

extension Data {
    fileprivate var base64URLEncodedString: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
