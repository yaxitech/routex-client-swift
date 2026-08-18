import Foundation

/// Debtor account reference for `collectPayment` calls. Same shape as
/// ``AccountReference`` but allows carrying an opaque encrypted IBAN.
public struct DebtorAccountReference: Sendable, Hashable, Codable {
    /// Debtor account identifier (plaintext or encrypted).
    public var id: DebtorAccountIdentifier
    /// ISO 4217 Alpha 3 currency code. `nil` means "any currency".
    public var currency: String?

    /// Build a debtor reference.
    public init(id: DebtorAccountIdentifier, currency: String? = nil) {
        self.id = id
        self.currency = currency
    }

    private enum CodingKeys: String, CodingKey {
        case iban
        case encryptedIBAN = "encryptedIban"
        case currency
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let iban = try c.decodeIfPresent(String.self, forKey: .iban) {
            self.id = .iban(iban)
        } else if let s = try c.decodeIfPresent(String.self, forKey: .encryptedIBAN) {
            guard let d = Data(base64Encoded: s) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .encryptedIBAN,
                    in: c,
                    debugDescription: "encryptedIban must be base64"
                )
            }
            self.id = .encryptedIBAN(d)
        } else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "DebtorAccountReference missing 'iban' or 'encryptedIban'"
                )
            )
        }
        self.currency = try c.decodeIfPresent(String.self, forKey: .currency)
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch id {
        case .iban(let v): try c.encode(v, forKey: .iban)
        case .encryptedIBAN(let d): try c.encode(d.base64EncodedString(), forKey: .encryptedIBAN)
        }
        try c.encodeIfPresent(currency, forKey: .currency)
    }
}
