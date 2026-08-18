import Foundation

/// Reference to an account by IBAN or non-IBAN account number, used by the
/// account-information services. Carries an optional currency to disambiguate
/// multi-currency accounts.
public struct AccountReference: Sendable, Hashable, Codable {
    /// Account identifier: an IBAN or a non-IBAN account number.
    public var id: AccountIdentifier
    /// ISO 4217 Alpha 3 currency code. `nil` means "any currency".
    public var currency: String?

    /// Build a reference. Pass `currency` only when the bank exposes multiple
    /// currencies on the same account.
    public init(id: AccountIdentifier, currency: String? = nil) {
        self.id = id
        self.currency = currency
    }

    /// The wire format flattens `id` into the parent object, e.g.
    /// `{"iban": "...", "currency": "..."}` or `{"number": "..."}`.
    private enum CodingKeys: String, CodingKey { case iban, number, currency }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let iban = try c.decodeIfPresent(String.self, forKey: .iban) {
            self.id = .iban(iban)
        } else if let number = try c.decodeIfPresent(String.self, forKey: .number) {
            self.id = .number(number)
        } else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "AccountReference missing 'iban' or 'number'"
                )
            )
        }
        self.currency = try c.decodeIfPresent(String.self, forKey: .currency)
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch id {
        case .iban(let v): try c.encode(v, forKey: .iban)
        case .number(let v): try c.encode(v, forKey: .number)
        }
        try c.encodeIfPresent(currency, forKey: .currency)
    }
}
