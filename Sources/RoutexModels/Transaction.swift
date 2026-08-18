import Foundation

/// A single account transaction.
public struct Transaction: Sendable, Hashable, Codable {
    /// Identifier used for delta requests.
    public let entryReference: String?
    /// Structure of any batch this transaction stands in for.
    public let batch: BatchData?
    /// Booking date (ASPSP's books) as ISO `YYYY-MM-DD`.
    public let bookingDate: ISODate?
    /// Value date as ISO `YYYY-MM-DD`. Expected / requested value date in
    /// case of pending entries.
    public let valueDate: ISODate?
    /// Date of the actual transaction (e.g. card payment) as ISO
    /// `YYYY-MM-DD`.
    public let transactionDate: ISODate?
    /// Settlement state.
    public let status: TransactionStatus
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
    public let amount: Amount
    /// Indicator for reversals.
    public let reversal: Bool
    /// Original amount of the transaction (before any conversion).
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
    ///
    /// May be a proprietary, localized, human-readable long text
    /// corresponding to some machine-readable bank transaction code that is
    /// not directly provided by the bank.
    public let additionalInformation: String?

    /// Build a `Transaction`.
    public init(
        entryReference: String? = nil,
        batch: BatchData? = nil,
        bookingDate: ISODate? = nil,
        valueDate: ISODate? = nil,
        transactionDate: ISODate? = nil,
        status: TransactionStatus,
        accountServicerReference: String? = nil,
        paymentID: String? = nil,
        transactionID: String? = nil,
        endToEndID: String? = nil,
        mandateID: String? = nil,
        creditorID: String? = nil,
        amount: Amount,
        reversal: Bool = false,
        originalAmount: Amount? = nil,
        exchanges: [ExchangeRate] = [],
        fees: [Fee] = [],
        creditor: Party? = nil,
        debtor: Party? = nil,
        remittanceInformation: [String] = [],
        purposeCode: String? = nil,
        bankTransactionCodes: [BankTransactionCode] = [],
        additionalInformation: String? = nil
    ) {
        self.entryReference = entryReference
        self.batch = batch
        self.bookingDate = bookingDate
        self.valueDate = valueDate
        self.transactionDate = transactionDate
        self.status = status
        self.accountServicerReference = accountServicerReference
        self.paymentID = paymentID
        self.transactionID = transactionID
        self.endToEndID = endToEndID
        self.mandateID = mandateID
        self.creditorID = creditorID
        self.amount = amount
        self.reversal = reversal
        self.originalAmount = originalAmount
        self.exchanges = exchanges
        self.fees = fees
        self.creditor = creditor
        self.debtor = debtor
        self.remittanceInformation = remittanceInformation
        self.purposeCode = purposeCode
        self.bankTransactionCodes = bankTransactionCodes
        self.additionalInformation = additionalInformation
    }

    private enum CodingKeys: String, CodingKey {
        case entryReference, batch, bookingDate, valueDate, transactionDate, status
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
        self.entryReference = try c.decodeIfPresent(String.self, forKey: .entryReference)
        self.batch = try c.decodeIfPresent(BatchData.self, forKey: .batch)
        self.bookingDate = try c.decodeIfPresent(ISODate.self, forKey: .bookingDate)
        self.valueDate = try c.decodeIfPresent(ISODate.self, forKey: .valueDate)
        self.transactionDate = try c.decodeIfPresent(ISODate.self, forKey: .transactionDate)
        self.status = try c.decode(TransactionStatus.self, forKey: .status)
        self.accountServicerReference = try c.decodeIfPresent(
            String.self,
            forKey: .accountServicerReference
        )
        self.paymentID = try c.decodeIfPresent(String.self, forKey: .paymentID)
        self.transactionID = try c.decodeIfPresent(String.self, forKey: .transactionID)
        self.endToEndID = try c.decodeIfPresent(String.self, forKey: .endToEndID)
        self.mandateID = try c.decodeIfPresent(String.self, forKey: .mandateID)
        self.creditorID = try c.decodeIfPresent(String.self, forKey: .creditorID)
        self.amount = try c.decode(Amount.self, forKey: .amount)
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
        try c.encodeIfPresent(entryReference, forKey: .entryReference)
        try c.encodeIfPresent(batch, forKey: .batch)
        try c.encodeIfPresent(bookingDate, forKey: .bookingDate)
        try c.encodeIfPresent(valueDate, forKey: .valueDate)
        try c.encodeIfPresent(transactionDate, forKey: .transactionDate)
        try c.encode(status, forKey: .status)
        try c.encodeIfPresent(accountServicerReference, forKey: .accountServicerReference)
        try c.encodeIfPresent(paymentID, forKey: .paymentID)
        try c.encodeIfPresent(transactionID, forKey: .transactionID)
        try c.encodeIfPresent(endToEndID, forKey: .endToEndID)
        try c.encodeIfPresent(mandateID, forKey: .mandateID)
        try c.encodeIfPresent(creditorID, forKey: .creditorID)
        try c.encode(amount, forKey: .amount)
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
