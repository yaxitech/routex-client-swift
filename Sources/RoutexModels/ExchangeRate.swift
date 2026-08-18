import Foundation

/// Exchange rate metadata that may be attached to a foreign-currency
/// transaction.
public struct ExchangeRate: Sendable, Hashable, Codable {
    /// ISO 4217 Alpha 3 code of the source currency that gets converted.
    public let sourceCurrency: String
    /// ISO 4217 Alpha 3 code of the target currency that the source currency
    /// gets converted into.
    public let targetCurrency: String?
    /// ISO 4217 Alpha 3 code of the unit currency for the exchange rate.
    public let unitCurrency: String?
    /// The exchange rate itself.
    public let exchangeRate: Decimal

    /// Build an `ExchangeRate`.
    public init(
        sourceCurrency: String,
        targetCurrency: String? = nil,
        unitCurrency: String? = nil,
        exchangeRate: Decimal
    ) {
        self.sourceCurrency = sourceCurrency
        self.targetCurrency = targetCurrency
        self.unitCurrency = unitCurrency
        self.exchangeRate = exchangeRate
    }

    private enum CodingKeys: String, CodingKey {
        case sourceCurrency, targetCurrency, unitCurrency, exchangeRate
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.sourceCurrency = try c.decode(String.self, forKey: .sourceCurrency)
        self.targetCurrency = try c.decodeIfPresent(String.self, forKey: .targetCurrency)
        self.unitCurrency = try c.decodeIfPresent(String.self, forKey: .unitCurrency)
        let s = try c.decode(String.self, forKey: .exchangeRate)
        guard let d = Decimal(string: s, locale: Locale(identifier: "en_US_POSIX")) else {
            throw DecodingError.dataCorruptedError(
                forKey: .exchangeRate,
                in: c,
                debugDescription: "ExchangeRate.exchangeRate is not a valid decimal: \(s)"
            )
        }
        self.exchangeRate = d
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(sourceCurrency, forKey: .sourceCurrency)
        try c.encodeIfPresent(targetCurrency, forKey: .targetCurrency)
        try c.encodeIfPresent(unitCurrency, forKey: .unitCurrency)
        try c.encode(exchangeRate.routexWireString, forKey: .exchangeRate)
    }
}
