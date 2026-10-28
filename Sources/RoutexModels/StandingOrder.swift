import Foundation

/// A standing order set up on an account.
public struct StandingOrder: Sendable, Hashable, Codable {
    /// Date of the first execution as ISO `YYYY-MM-DD`.
    public let startDate: ISODate
    /// Date of the last execution as ISO `YYYY-MM-DD`.
    public let endDate: ISODate?
    /// Rule to follow if the execution falls on a weekend or bank holiday.
    public let executionRule: ExecutionRule?
    /// Execution frequency.
    public let frequency: Frequency?
    /// Day of month on which the order shall get executed.
    public let day: UInt8?
    /// Amount limit for fund skimming, i.e. funds exceeding this value get
    /// transferred instead of a fixed amount.
    public let skimmingLimit: Amount?
    /// Unique end-to-end identifier assigned by the initiating party.
    public let endToEndID: String?
    /// Amount of each execution.
    public let amount: Amount
    /// Creditor data.
    public let creditor: Party?
    /// Debtor data.
    public let debtor: Party?
    /// Remittance (purpose).
    public let remittanceInformation: [String]
    /// ISO 20022 `ExternalPurpose1Code`.
    public let purposeCode: String?
    /// Additional information attached to the standing order.
    public let additionalInformation: String?

    /// Build a `StandingOrder`.
    public init(
        startDate: ISODate,
        endDate: ISODate? = nil,
        executionRule: ExecutionRule? = nil,
        frequency: Frequency? = nil,
        day: UInt8? = nil,
        skimmingLimit: Amount? = nil,
        endToEndID: String? = nil,
        amount: Amount,
        creditor: Party? = nil,
        debtor: Party? = nil,
        remittanceInformation: [String] = [],
        purposeCode: String? = nil,
        additionalInformation: String? = nil
    ) {
        self.startDate = startDate
        self.endDate = endDate
        self.executionRule = executionRule
        self.frequency = frequency
        self.day = day
        self.skimmingLimit = skimmingLimit
        self.endToEndID = endToEndID
        self.amount = amount
        self.creditor = creditor
        self.debtor = debtor
        self.remittanceInformation = remittanceInformation
        self.purposeCode = purposeCode
        self.additionalInformation = additionalInformation
    }

    private enum CodingKeys: String, CodingKey {
        case startDate, endDate, executionRule, frequency, day, skimmingLimit
        case endToEndID = "endToEndId"
        case amount, creditor, debtor, remittanceInformation, purposeCode, additionalInformation
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.startDate = try c.decode(ISODate.self, forKey: .startDate)
        self.endDate = try c.decodeIfPresent(ISODate.self, forKey: .endDate)
        self.executionRule = try c.decodeIfPresent(ExecutionRule.self, forKey: .executionRule)
        self.frequency = try c.decodeIfPresent(Frequency.self, forKey: .frequency)
        self.day = try c.decodeIfPresent(UInt8.self, forKey: .day)
        self.skimmingLimit = try c.decodeIfPresent(Amount.self, forKey: .skimmingLimit)
        self.endToEndID = try c.decodeIfPresent(String.self, forKey: .endToEndID)
        self.amount = try c.decode(Amount.self, forKey: .amount)
        self.creditor = try c.decodeIfPresent(Party.self, forKey: .creditor)
        self.debtor = try c.decodeIfPresent(Party.self, forKey: .debtor)
        self.remittanceInformation =
            try c.decodeIfPresent([String].self, forKey: .remittanceInformation) ?? []
        self.purposeCode = try c.decodeIfPresent(String.self, forKey: .purposeCode)
        self.additionalInformation =
            try c.decodeIfPresent(String.self, forKey: .additionalInformation)
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(startDate, forKey: .startDate)
        try c.encodeIfPresent(endDate, forKey: .endDate)
        try c.encodeIfPresent(executionRule, forKey: .executionRule)
        try c.encodeIfPresent(frequency, forKey: .frequency)
        try c.encodeIfPresent(day, forKey: .day)
        try c.encodeIfPresent(skimmingLimit, forKey: .skimmingLimit)
        try c.encodeIfPresent(endToEndID, forKey: .endToEndID)
        try c.encode(amount, forKey: .amount)
        try c.encodeIfPresent(creditor, forKey: .creditor)
        try c.encodeIfPresent(debtor, forKey: .debtor)
        if !remittanceInformation.isEmpty {
            try c.encode(remittanceInformation, forKey: .remittanceInformation)
        }
        try c.encodeIfPresent(purposeCode, forKey: .purposeCode)
        try c.encodeIfPresent(additionalInformation, forKey: .additionalInformation)
    }
}
