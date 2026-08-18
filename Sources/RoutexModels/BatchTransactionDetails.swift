import Foundation

/// Details of the transactions inside a ``BatchData``.
///
/// Every field is optional: a batch entry may carry details common to all
/// its transactions, a single representative transaction, or nothing.
public struct BatchTransactionDetails: Sendable, Hashable, Codable {
    /// Unique reference assigned by the account servicer.
    public let accountServicerReference: String?
    /// Unique identifier assigned by the sending party.
    public let paymentID: String?
    /// Unique identifier assigned by the first instructing agent.
    public let transactionID: String?
    /// Unique end-to-end identifier assigned by the initiating party.
    public let endToEndID: String?
    /// Mandate identifier.
    public let mandateID: String?
    /// SEPA creditor identifier.
    public let creditorID: String?
    /// Transaction amount as billed to the account.
    public let amount: Amount?
    /// Indicator for reversals.
    public let reversal: Bool
    /// Original amount of the transaction.
    public let originalAmount: Amount?
    /// Exchange rates applied to the transaction.
    public let exchanges: [ExchangeRate]
    /// Any fees related to the transaction.
    public let fees: [Fee]
    /// Creditor data. In case of reversals this refers to the initial
    /// transaction.
    public let creditor: Party?
    /// Debtor data. In case of reversals this refers to the initial
    /// transaction.
    public let debtor: Party?
    /// Remittance (purpose).
    public let remittanceInformation: [String]
    /// ISO 20022 `ExternalPurpose1Code`.
    public let purposeCode: String?
    /// Bank transaction codes.
    public let bankTransactionCodes: [BankTransactionCode]
    /// Additional information attached to the transaction.
    public let additionalInformation: String?

    private enum CodingKeys: String, CodingKey {
        case accountServicerReference
        case paymentID = "paymentId"
        case transactionID = "transactionId"
        case endToEndID = "endToEndId"
        case mandateID = "mandateId"
        case creditorID = "creditorId"
        case amount, reversal, originalAmount, exchanges, fees, creditor, debtor
        case remittanceInformation, purposeCode, bankTransactionCodes, additionalInformation
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.accountServicerReference = try c.decodeIfPresent(
            String.self,
            forKey: .accountServicerReference
        )
        self.paymentID = try c.decodeIfPresent(String.self, forKey: .paymentID)
        self.transactionID = try c.decodeIfPresent(String.self, forKey: .transactionID)
        self.endToEndID = try c.decodeIfPresent(String.self, forKey: .endToEndID)
        self.mandateID = try c.decodeIfPresent(String.self, forKey: .mandateID)
        self.creditorID = try c.decodeIfPresent(String.self, forKey: .creditorID)
        self.amount = try c.decodeIfPresent(Amount.self, forKey: .amount)
        self.reversal = try c.decodeIfPresent(Bool.self, forKey: .reversal) ?? false
        self.originalAmount = try c.decodeIfPresent(Amount.self, forKey: .originalAmount)
        self.exchanges = try c.decodeIfPresent([ExchangeRate].self, forKey: .exchanges) ?? []
        self.fees = try c.decodeIfPresent([Fee].self, forKey: .fees) ?? []
        self.creditor = try c.decodeIfPresent(Party.self, forKey: .creditor)
        self.debtor = try c.decodeIfPresent(Party.self, forKey: .debtor)
        self.remittanceInformation =
            try c.decodeIfPresent([String].self, forKey: .remittanceInformation) ?? []
        self.purposeCode = try c.decodeIfPresent(String.self, forKey: .purposeCode)
        self.bankTransactionCodes =
            try c.decodeIfPresent([BankTransactionCode].self, forKey: .bankTransactionCodes) ?? []
        self.additionalInformation =
            try c.decodeIfPresent(String.self, forKey: .additionalInformation)
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(accountServicerReference, forKey: .accountServicerReference)
        try c.encodeIfPresent(paymentID, forKey: .paymentID)
        try c.encodeIfPresent(transactionID, forKey: .transactionID)
        try c.encodeIfPresent(endToEndID, forKey: .endToEndID)
        try c.encodeIfPresent(mandateID, forKey: .mandateID)
        try c.encodeIfPresent(creditorID, forKey: .creditorID)
        try c.encodeIfPresent(amount, forKey: .amount)
        if reversal { try c.encode(true, forKey: .reversal) }
        try c.encodeIfPresent(originalAmount, forKey: .originalAmount)
        if !exchanges.isEmpty { try c.encode(exchanges, forKey: .exchanges) }
        if !fees.isEmpty { try c.encode(fees, forKey: .fees) }
        try c.encodeIfPresent(creditor, forKey: .creditor)
        try c.encodeIfPresent(debtor, forKey: .debtor)
        if !remittanceInformation.isEmpty {
            try c.encode(remittanceInformation, forKey: .remittanceInformation)
        }
        try c.encodeIfPresent(purposeCode, forKey: .purposeCode)
        if !bankTransactionCodes.isEmpty {
            try c.encode(bankTransactionCodes, forKey: .bankTransactionCodes)
        }
        try c.encodeIfPresent(additionalInformation, forKey: .additionalInformation)
    }
}
