import Foundation
import RoutexModels

/// Time-range selector for a transactions ticket. Pass it as the `range`
/// argument to ``RoutexTicketIssuer/transactions(account:range:webhook:ticketID:ttl:)``.
public enum TransactionsRange: Sendable, Hashable {
    /// Delta cursor resuming the stream after a prior call. `reference` is the
    /// `entryReference` of a transaction returned by an earlier call; the service
    /// then yields all newer transactions.
    case reference(String)

    /// Absolute date range. `from` is inclusive; `to` is inclusive when present
    /// and `nil` leaves the upper bound open.
    case period(from: ISODate, to: ISODate? = nil)
}

extension TransactionsRange: Encodable {
    private enum ReferenceKey: String, CodingKey { case reference }
    private enum PeriodKey: String, CodingKey { case from, to }

    public func encode(to encoder: any Encoder) throws {
        switch self {
        case .reference(let reference):
            var container = encoder.container(keyedBy: ReferenceKey.self)
            try container.encode(reference, forKey: .reference)
        case .period(let from, let to):
            var container = encoder.container(keyedBy: PeriodKey.self)
            try container.encode(from, forKey: .from)
            try container.encodeIfPresent(to, forKey: .to)
        }
    }
}

/// Debtor-side fields that the collect-payment service can include in its result.
/// Pass these as the `fields` argument to
/// ``RoutexTicketIssuer/collectPayment(amount:creditorAccount:creditorName:remittance:instant:fields:ticketID:ttl:)``;
/// omitting them returns no debtor data.
public enum CollectPaymentField: String, Sendable, Hashable, Encodable {
    /// Plain-text IBAN of the debtor account.
    case debtorIBAN = "debtorIban"
    /// Account-owner name on the debtor account.
    case debtorName
    /// Encrypted IBAN of the debtor account, suitable for an opaque handoff back
    /// to the caller's backend. See [Opaque Data](https://docs.yaxi.tech/opaque-data.html).
    case encryptedDebtorIBAN = "encryptedDebtorIban"
    /// Encrypted name on the debtor account, suitable for an opaque handoff back
    /// to the caller's backend. See [Opaque Data](https://docs.yaxi.tech/opaque-data.html).
    case encryptedDebtorName
}

// MARK: - Wire payloads

struct TransactionsTicketData: Encodable {
    let account: AccountReference
    let range: TransactionsRange
    let webhook: URL?
}

struct CollectPaymentTicketData: Encodable {
    let amount: Amount
    let creditorAccount: CreditorAccountIdentifier
    let creditorName: String
    let remittance: String
    let instant: Bool?
    let fields: [CollectPaymentField]?
}
