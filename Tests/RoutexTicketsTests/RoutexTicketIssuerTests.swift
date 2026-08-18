import Crypto
import Foundation
import RoutexModels
import Testing

@testable import RoutexTickets

@Suite("RoutexTicketIssuer")
struct RoutexTicketIssuerTests {
    private static let apiKeyID = "test-key-id"
    private static let secret = Data("test-secret-bytes-with-enough-entropy".utf8)

    private func issuer() throws -> RoutexTicketIssuer {
        try RoutexTicketIssuer(apiKeyID: Self.apiKeyID, apiKeySecret: Self.secret)
    }

    // MARK: - Header + no-data services

    @Test("no-data services produce the expected header and a null data claim")
    func noDataServices() throws {
        let issuer = try issuer()
        let cases: [(String, String)] = [
            ("Accounts", try issuer.accounts().raw),
            ("Balances", try issuer.balances().raw),
            ("Transfer", try issuer.transfer().raw),
        ]
        for (service, raw) in cases {
            let (header, payload) = Self.decode(raw)
            #expect(header["alg"] as? String == "HS256")
            #expect(header["typ"] as? String == "JWT")
            #expect(header["kid"] as? String == Self.apiKeyID)

            let data = try #require(payload["data"] as? [String: Any])
            #expect(data["service"] as? String == service)
            #expect(UUID(uuidString: try #require(data["id"] as? String)) != nil)
            #expect(data["data"] is NSNull, "no-data services emit data:null")
        }
    }

    // MARK: - transactions

    @Test("transactions ticket encodes a period range and omits an absent webhook")
    func transactionsPeriodRange() throws {
        let raw = try issuer().transactions(
            account: AccountReference(id: .iban("DE02120300000000202051"), currency: "EUR"),
            range: .period(from: try ISODate("2026-01-01"))
        ).raw
        let data = Self.ticketData(raw)
        #expect((data["account"] as? [String: Any])?["iban"] as? String == "DE02120300000000202051")
        #expect(data["webhook"] == nil, "an absent webhook is omitted")
        let range = try #require(data["range"] as? [String: Any])
        #expect(range["from"] as? String == "2026-01-01")
        #expect(range["to"] == nil, "an open-ended period omits `to`")
    }

    @Test("transactions ticket encodes a reference range and an explicit webhook")
    func transactionsReferenceRange() throws {
        let raw = try issuer().transactions(
            account: AccountReference(id: .iban("DE02120300000000202051")),
            range: .reference("abc"),
            webhook: URL(string: "https://example.invalid/hook")!
        ).raw
        let data = Self.ticketData(raw)
        #expect(data["webhook"] as? String == "https://example.invalid/hook")
        #expect((data["range"] as? [String: Any])?["reference"] as? String == "abc")
    }

    // MARK: - collectPayment

    @Test("collectPayment omits optionals by default")
    func collectPaymentDefaults() throws {
        let raw = try issuer().collectPayment(
            amount: Amount(amount: Decimal(string: "100.00")!, currency: "EUR"),
            creditorAccount: .iban("DE79430609671288143100"),
            creditorName: "YAXI GmbH",
            remittance: "Sign-up fee routex 123456789"
        ).raw
        let data = Self.ticketData(raw)
        let amount = try #require(data["amount"] as? [String: Any])
        // `Amount` normalizes the decimal on the wire (trailing zeros dropped).
        #expect(amount["amount"] as? String == "100")
        #expect(amount["currency"] as? String == "EUR")
        #expect(
            (data["creditorAccount"] as? [String: Any])?["iban"] as? String
                == "DE79430609671288143100"
        )
        #expect(data["creditorName"] as? String == "YAXI GmbH")
        #expect(data["remittance"] as? String == "Sign-up fee routex 123456789")
        #expect(data["instant"] == nil, "instant is omitted when nil")
        #expect(data["fields"] == nil, "fields is omitted when nil")
    }

    @Test("collectPayment emits optionals when provided")
    func collectPaymentWithOptionals() throws {
        let raw = try issuer().collectPayment(
            amount: Amount(amount: Decimal(string: "1.00")!, currency: "EUR"),
            creditorAccount: .iban("DE79430609671288143100"),
            creditorName: "YAXI GmbH",
            remittance: "fee",
            instant: false,
            fields: [.debtorIBAN, .debtorName]
        ).raw
        let data = Self.ticketData(raw)
        #expect(data["instant"] as? Bool == false)
        #expect(
            data["fields"] as? [String] == ["debtorIban", "debtorName"],
            "fields serialize as camelCase"
        )
    }

    // MARK: - exp / ttl / id

    @Test("exp reflects the clock, the default ttl, and a per-call override")
    func expReflectsClockAndTTL() throws {
        let fixed = Date(timeIntervalSince1970: 1_800_000_000)
        let issuer = try RoutexTicketIssuer(
            apiKeyID: Self.apiKeyID,
            apiKeySecret: Self.secret,
            ttl: 420,
            now: { fixed }
        )

        let defaultExp = try Self.exp(issuer.accounts().raw)
        #expect(defaultExp == Int(fixed.timeIntervalSince1970) + 420)
        let overrideExp = try Self.exp(issuer.accounts(ttl: 30).raw)
        #expect(overrideExp == Int(fixed.timeIntervalSince1970) + 30)
    }

    @Test("each call mints a fresh ticket id, and a caller-supplied id is honored")
    func ticketIDs() throws {
        let issuer = try issuer()
        let first = try issuer.accounts().id
        let second = try issuer.accounts().id
        #expect(first != second)
        let explicit = UUID()
        let assigned = try issuer.accounts(ticketID: explicit).id
        #expect(assigned == explicit)
    }

    // MARK: - Signature

    @Test("signature is HMAC-SHA256 over header.payload")
    func signatureMatchesHMAC() throws {
        let parts = try issuer().accounts().raw.split(separator: ".").map(String.init)
        let signingInput = "\(parts[0]).\(parts[1])"
        let expected = HMAC<SHA256>.authenticationCode(
            for: Data(signingInput.utf8),
            using: SymmetricKey(data: Self.secret)
        )
        #expect(Self.base64URL(Data(expected)) == parts[2])
    }

    @Test("the base64-secret initializer decodes to the same signing key")
    func base64SecretInitializer() throws {
        let rawBytes = Data([1, 2, 3, 4, 5, 6, 7, 8])
        let raw = try RoutexTicketIssuer(
            apiKeyID: Self.apiKeyID,
            base64Secret: rawBytes.base64EncodedString()
        )
        .accounts().raw
        let parts = raw.split(separator: ".").map(String.init)
        let expected = HMAC<SHA256>.authenticationCode(
            for: Data("\(parts[0]).\(parts[1])".utf8),
            using: SymmetricKey(data: rawBytes)
        )
        #expect(Self.base64URL(Data(expected)) == parts[2])
    }

    // MARK: - Validation

    @Test("the initializer rejects invalid inputs")
    func rejectsInvalidConstructorInputs() {
        #expect(throws: RoutexTicketIssuerError.blankAPIKeyID) {
            try RoutexTicketIssuer(apiKeyID: " ", apiKeySecret: Self.secret)
        }
        #expect(throws: RoutexTicketIssuerError.emptySecret) {
            try RoutexTicketIssuer(apiKeyID: Self.apiKeyID, apiKeySecret: Data())
        }
        #expect(throws: RoutexTicketIssuerError.nonPositiveTTL(0)) {
            try RoutexTicketIssuer(apiKeyID: Self.apiKeyID, apiKeySecret: Self.secret, ttl: 0)
        }
        #expect(throws: RoutexTicketIssuerError.invalidBase64Secret) {
            try RoutexTicketIssuer(apiKeyID: Self.apiKeyID, base64Secret: "not base64!!")
        }
    }

    @Test("service methods reject blank inputs and non-positive ttl overrides")
    func rejectsInvalidServiceInputs() throws {
        let issuer = try issuer()
        let creditor = CreditorAccountIdentifier.iban("DE79430609671288143100")
        let amount = Amount(amount: 1, currency: "EUR")
        #expect(throws: RoutexTicketIssuerError.blankField("creditorName")) {
            try issuer.collectPayment(
                amount: amount,
                creditorAccount: creditor,
                creditorName: " ",
                remittance: "fee"
            )
        }
        #expect(throws: RoutexTicketIssuerError.blankField("remittance")) {
            try issuer.collectPayment(
                amount: amount,
                creditorAccount: creditor,
                creditorName: "YAXI",
                remittance: " "
            )
        }
        #expect(throws: RoutexTicketIssuerError.nonPositiveTTL(-1)) {
            try issuer.accounts(ttl: -1)
        }
    }

    // MARK: - Helpers

    private static func base64URLDecode(_ s: String) -> Data {
        var str = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(
            of: "_",
            with: "/"
        )
        while str.count % 4 != 0 { str += "=" }
        return Data(base64Encoded: str)!
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func decode(_ jwt: String) -> (header: [String: Any], payload: [String: Any]) {
        let parts = jwt.split(separator: ".").map(String.init)
        let header =
            try! JSONSerialization.jsonObject(with: base64URLDecode(parts[0])) as! [String: Any]
        let payload =
            try! JSONSerialization.jsonObject(with: base64URLDecode(parts[1])) as! [String: Any]
        return (header, payload)
    }

    /// The inner `data.data` object (the service-specific ticket data).
    private static func ticketData(_ jwt: String) -> [String: Any] {
        let data = decode(jwt).payload["data"] as! [String: Any]
        return data["data"] as! [String: Any]
    }

    private static func exp(_ jwt: String) -> Int {
        decode(jwt).payload["exp"] as! Int
    }
}
