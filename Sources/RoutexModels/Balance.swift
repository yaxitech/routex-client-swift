import Foundation

/// One balance reading for an account, of a specific ``BalanceType``.
public struct Balance: Sendable, Hashable, Codable {
    /// Numeric amount.
    public let amount: Decimal
    /// ISO 4217 Alpha 3 currency code.
    public let currency: String
    /// Kind of reading: booked, available, or expected.
    public let balanceType: BalanceType
    /// `true` if a credit limit is folded into ``amount``.
    public let creditLimitIncluded: Bool?
    /// The moment the balance is valid, when known.
    public let dateTime: Date?

    /// Build a `Balance`.
    public init(
        amount: Decimal,
        currency: String,
        balanceType: BalanceType,
        creditLimitIncluded: Bool? = nil,
        dateTime: Date? = nil
    ) {
        self.amount = amount
        self.currency = currency
        self.balanceType = balanceType
        self.creditLimitIncluded = creditLimitIncluded
        self.dateTime = dateTime
    }

    private enum CodingKeys: String, CodingKey {
        case amount, currency, balanceType, creditLimitIncluded, dateTime
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let s = try c.decode(String.self, forKey: .amount)
        guard let d = Decimal(string: s, locale: Locale(identifier: "en_US_POSIX")) else {
            throw DecodingError.dataCorruptedError(
                forKey: .amount,
                in: c,
                debugDescription: "Balance.amount is not a valid decimal: \(s)"
            )
        }
        self.amount = d
        self.currency = try c.decode(String.self, forKey: .currency)
        self.balanceType = try c.decode(BalanceType.self, forKey: .balanceType)
        self.creditLimitIncluded = try c.decodeIfPresent(Bool.self, forKey: .creditLimitIncluded)
        self.dateTime = try c.decodeIfPresent(String.self, forKey: .dateTime)
            .map { try RoutexResultCoding.decodeISO8601($0, field: "dateTime") }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        var v = amount
        try c.encode(NSDecimalString(&v, Locale(identifier: "en_US_POSIX")), forKey: .amount)
        try c.encode(currency, forKey: .currency)
        try c.encode(balanceType, forKey: .balanceType)
        try c.encodeIfPresent(creditLimitIncluded, forKey: .creditLimitIncluded)
        try c.encodeIfPresent(dateTime.map(RoutexResultCoding.encodeISO8601), forKey: .dateTime)
    }
}
