import Foundation

/// Identifier of a debtor account on a `collectPayment` call. Either a
/// plaintext IBAN or an opaque ciphertext that the backend produced under
/// the [Opaque Data](https://docs.yaxi.tech/opaque-data.html) protocol so
/// the frontend never sees the underlying IBAN.
public enum DebtorAccountIdentifier: Sendable, Hashable, Codable {
    /// ISO 20022 IBAN2007Identifier.
    case iban(String)
    /// Backend-encrypted IBAN ciphertext.
    case encryptedIBAN(Data)

    private enum CodingKeys: String, CodingKey {
        case iban
        case encryptedIBAN = "encryptedIban"
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let v = try c.decodeIfPresent(String.self, forKey: .iban) {
            self = .iban(v)
            return
        }
        if let s = try c.decodeIfPresent(String.self, forKey: .encryptedIBAN) {
            guard let d = Data(base64Encoded: s) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .encryptedIBAN,
                    in: c,
                    debugDescription: "encryptedIban must be base64"
                )
            }
            self = .encryptedIBAN(d)
            return
        }
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "DebtorAccountIdentifier missing 'iban' or 'encryptedIban'"
            )
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .iban(let v): try c.encode(v, forKey: .iban)
        case .encryptedIBAN(let d): try c.encode(d.base64EncodedString(), forKey: .encryptedIBAN)
        }
    }
}
