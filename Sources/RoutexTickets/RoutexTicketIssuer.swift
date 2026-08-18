import Crypto
import Foundation
import RoutexModels

/// Issues signed JWT tickets for the YAXI Open Banking services.
///
/// One method per service, each returning the matching typed ticket. Instances
/// are immutable value types and safe to share across tasks.
///
/// ```swift
/// let issuer = try RoutexTicketIssuer(
///     apiKeyID: "api-key-2eeba71f-...",
///     base64Secret: ProcessInfo.processInfo.environment["YAXI_API_KEY_SECRET"]!)
/// let ticket = try issuer.accounts()
/// ```
///
/// Issuing a ticket requires the API key secret, so the issuer belongs in a
/// trusted backend in the vast majority of deployments. Frontend issuance is
/// possible and a handful of legitimate use cases exist, but only consider it if
/// you understand the security implications of co-locating the API key secret
/// with untrusted code; a leaked secret lets third parties issue tickets at your
/// cost.
public struct RoutexTicketIssuer: Sendable {
    private let apiKeyID: String
    private let secret: SymmetricKey
    private let ttl: TimeInterval
    private let now: @Sendable () -> Date

    /// Default time-to-live applied to every issued ticket unless the call site
    /// supplies its own override.
    public static let defaultTTL: TimeInterval = 600

    /// - Parameters:
    ///   - apiKeyID: Identifier of the API key, set as the JWT `kid` header so the
    ///     routex backend can pick the correct verifying key.
    ///   - apiKeySecret: HMAC-SHA256 key bytes; the issuer never logs or otherwise
    ///     exposes them.
    ///   - ttl: Default time-to-live for issued tickets.
    public init(apiKeyID: String, apiKeySecret: Data, ttl: TimeInterval = defaultTTL) throws {
        try self.init(apiKeyID: apiKeyID, apiKeySecret: apiKeySecret, ttl: ttl, now: { Date() })
    }

    /// Convenience initializer that decodes `base64Secret` as standard Base64.
    ///
    /// - Throws: ``RoutexTicketIssuerError/invalidBase64Secret`` if `base64Secret`
    ///   is not valid standard Base64.
    public init(apiKeyID: String, base64Secret: String, ttl: TimeInterval = defaultTTL) throws {
        guard let secret = Data(base64Encoded: base64Secret) else {
            throw RoutexTicketIssuerError.invalidBase64Secret
        }
        try self.init(apiKeyID: apiKeyID, apiKeySecret: secret, ttl: ttl)
    }

    /// Designated initializer with an injectable clock, for tests.
    init(
        apiKeyID: String,
        apiKeySecret: Data,
        ttl: TimeInterval = defaultTTL,
        now: @escaping @Sendable () -> Date
    ) throws {
        guard !apiKeyID.isBlank else { throw RoutexTicketIssuerError.blankAPIKeyID }
        guard !apiKeySecret.isEmpty else { throw RoutexTicketIssuerError.emptySecret }
        guard ttl > 0 else { throw RoutexTicketIssuerError.nonPositiveTTL(ttl) }
        self.apiKeyID = apiKeyID
        self.secret = SymmetricKey(data: apiKeySecret)
        self.ttl = ttl
        self.now = now
    }

    /// Issue a ticket for the accounts service.
    public func accounts(ticketID: UUID = UUID(), ttl: TimeInterval? = nil) throws -> AccountsTicket {
        try AccountsTicket(sign(service: "Accounts", ticketID: ticketID, ttl: ttl))
    }

    /// Issue a ticket for the balances service.
    public func balances(ticketID: UUID = UUID(), ttl: TimeInterval? = nil) throws -> BalancesTicket {
        try BalancesTicket(sign(service: "Balances", ticketID: ticketID, ttl: ttl))
    }

    /// Issue a ticket for the transfer service.
    public func transfer(ticketID: UUID = UUID(), ttl: TimeInterval? = nil) throws -> TransferTicket {
        try TransferTicket(sign(service: "Transfer", ticketID: ticketID, ttl: ttl))
    }

    /// Issue a ticket for the transactions service against `account`.
    public func transactions(
        account: AccountReference,
        range: TransactionsRange,
        webhook: URL? = nil,
        ticketID: UUID = UUID(),
        ttl: TimeInterval? = nil
    ) throws -> TransactionsTicket {
        let data = TransactionsTicketData(account: account, range: range, webhook: webhook)
        return try TransactionsTicket(
            sign(service: "Transactions", data: data, ticketID: ticketID, ttl: ttl)
        )
    }

    /// Issue a ticket for the collect-payment service.
    ///
    /// - Parameters:
    ///   - amount: Amount to collect from the debtor.
    ///   - creditorAccount: Account the payment is collected to.
    ///   - creditorName: Name of the holder of `creditorAccount`.
    ///   - remittance: Remittance information shown to the debtor.
    ///   - instant: Force instant (`true`) or non-instant (`false`). Leave `nil`
    ///     to request an instant payment when supported and fall back to
    ///     non-instant otherwise; forcing `true` makes the service return an
    ///     `UnsupportedProduct` error when the bank cannot offer an instant payment.
    ///   - fields: Debtor-side fields to populate on the result. `nil` returns no
    ///     debtor data.
    ///   - ticketID: Unique ticket identifier embedded in the signed claims;
    ///     defaults to a fresh UUID.
    ///   - ttl: Seconds the ticket stays valid; `nil` uses the issuer's default.
    public func collectPayment(
        amount: Amount,
        creditorAccount: CreditorAccountIdentifier,
        creditorName: String,
        remittance: String,
        instant: Bool? = nil,
        fields: [CollectPaymentField]? = nil,
        ticketID: UUID = UUID(),
        ttl: TimeInterval? = nil
    ) throws -> CollectPaymentTicket {
        guard !creditorName.isBlank else {
            throw RoutexTicketIssuerError.blankField("creditorName")
        }
        guard !remittance.isBlank else { throw RoutexTicketIssuerError.blankField("remittance") }
        let data = CollectPaymentTicketData(
            amount: amount,
            creditorAccount: creditorAccount,
            creditorName: creditorName,
            remittance: remittance,
            instant: instant,
            fields: fields
        )
        return try CollectPaymentTicket(
            sign(service: "CollectPayment", data: data, ticketID: ticketID, ttl: ttl)
        )
    }

    // MARK: - JWT issuance

    private func sign(service: String, ticketID: UUID, ttl: TimeInterval?) throws -> String {
        try sign(service: service, data: Optional<NoTicketData>.none, ticketID: ticketID, ttl: ttl)
    }

    private func sign<Payload: Encodable>(
        service: String,
        data: Payload?,
        ticketID: UUID,
        ttl perCallTTL: TimeInterval?
    ) throws -> String {
        if let perCallTTL, perCallTTL <= 0 {
            throw RoutexTicketIssuerError.nonPositiveTTL(perCallTTL)
        }
        let expiresAt = now().addingTimeInterval(perCallTTL ?? ttl).timeIntervalSince1970
        let claims = Claims(
            service: service,
            id: ticketID.uuidString.lowercased(),
            data: data,
            exp: Int(expiresAt)
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let header = try encoder.encode(Header(kid: apiKeyID))
        let payload = try encoder.encode(claims)

        let signingInput = "\(header.base64URLEncodedString()).\(payload.base64URLEncodedString())"
        let signature = HMAC<SHA256>.authenticationCode(for: Data(signingInput.utf8), using: secret)
        return "\(signingInput).\(Data(signature).base64URLEncodedString())"
    }
}

/// Reason a ticket could not be issued.
public enum RoutexTicketIssuerError: Error, Sendable, Equatable {
    /// `apiKeyID` was empty or whitespace-only.
    case blankAPIKeyID
    /// `apiKeySecret` was empty.
    case emptySecret
    /// `base64Secret` was not valid standard Base64.
    case invalidBase64Secret
    /// A ticket lifetime was zero or negative. The associated value is the
    /// given TTL.
    case nonPositiveTTL(TimeInterval)
    /// A required string argument was blank. The associated value names it.
    case blankField(String)
}

// MARK: - JWT wire shapes

private struct Header: Encodable {
    let alg = "HS256"
    let typ = "JWT"
    let kid: String
}

/// `{ "data": { "service", "id", "data" }, "exp" }`. `data.data` is emitted as
/// `null` for services that take no ticket data, keeping the shape stable.
private struct Claims<Body: Encodable>: Encodable {
    let service: String
    let id: String
    let data: Body?
    let exp: Int

    private enum TopKey: String, CodingKey { case data, exp }
    private enum BodyKey: String, CodingKey { case service, id, data }

    func encode(to encoder: any Encoder) throws {
        var top = encoder.container(keyedBy: TopKey.self)
        var body = top.nestedContainer(keyedBy: BodyKey.self, forKey: .data)
        try body.encode(service, forKey: .service)
        try body.encode(id, forKey: .id)
        if let data {
            try body.encode(data, forKey: .data)
        } else {
            try body.encodeNil(forKey: .data)
        }
        try top.encode(exp, forKey: .exp)
    }
}

/// Placeholder element type for the no-ticket-data services; never encoded.
private struct NoTicketData: Encodable {}

extension Data {
    fileprivate func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

extension String {
    fileprivate var isBlank: Bool {
        trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}
