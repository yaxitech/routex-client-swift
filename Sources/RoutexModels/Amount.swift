import Foundation

/// Monetary amount with an ISO 4217 currency code.
public struct Amount: Sendable, Hashable, Codable {
    /// The numeric amount. Sign carries debit (negative) vs credit (positive).
    public let amount: Decimal
    /// ISO 4217 Alpha 3 currency code.
    public let currency: String

    /// Build an `Amount`.
    public init(amount: Decimal, currency: String) {
        self.amount = amount
        self.currency = currency
    }

    private enum CodingKeys: String, CodingKey { case amount, currency }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let s = try c.decode(String.self, forKey: .amount)
        guard let d = Decimal(string: s, locale: Locale(identifier: "en_US_POSIX")) else {
            throw DecodingError.dataCorruptedError(
                forKey: .amount,
                in: c,
                debugDescription: "Amount.amount is not a valid decimal: \(s)"
            )
        }
        self.amount = d
        self.currency = try c.decode(String.self, forKey: .currency)
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(amount.routexWireString, forKey: .amount)
        try c.encode(currency, forKey: .currency)
    }
}

extension Decimal {
    /// Locale-independent string representation. `Decimal` normalizes its
    /// internal exponent so trailing zeros from the wire (e.g. `"10.00"`)
    /// are not preserved on round-trip; both representations decode to the
    /// same numeric value.
    var routexWireString: String {
        var v = self
        return NSDecimalString(&v, Locale(identifier: "en_US_POSIX"))
    }
}
