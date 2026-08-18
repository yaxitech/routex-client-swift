import Foundation

/// One filter used by `RoutexClient.search(...)`.
///
/// String filters look for the value anywhere in the related field,
/// case-insensitive. Multiple filters in the same request are combined with
/// AND.
public enum SearchFilter: Sendable, Hashable, Codable {
    /// Restrict to the given ISO 3166-1 ALPHA-2 country codes.
    case countries([CountryCode])
    /// String match on the provider/product name or any alias.
    case name(String)
    /// String match on the BIC.
    case bic(String)
    /// String match on the (national) bank code.
    case bankCode(String)
    /// String match on any of the searchable name/code fields.
    case term(String)
    /// Backend-encrypted IBAN ciphertext; matched server-side by bank code.
    case encryptedIBAN(Data)

    private enum Tag: String, CodingKey {
        case countries
        case name
        case bic
        case bankCode
        case term
        case encryptedIBAN = "encryptedIban"
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: Tag.self)
        guard c.allKeys.count == 1, let tag = c.allKeys.first else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Expected one tag for SearchFilter"
                )
            )
        }
        switch tag {
        case .countries: self = .countries(try c.decode([CountryCode].self, forKey: tag))
        case .name: self = .name(try c.decode(String.self, forKey: tag))
        case .bic: self = .bic(try c.decode(String.self, forKey: tag))
        case .bankCode: self = .bankCode(try c.decode(String.self, forKey: tag))
        case .term: self = .term(try c.decode(String.self, forKey: tag))
        case .encryptedIBAN:
            // Wire form: base64 string.
            let base64 = try c.decode(String.self, forKey: tag)
            guard let data = Data(base64Encoded: base64) else {
                throw DecodingError.dataCorrupted(
                    .init(
                        codingPath: decoder.codingPath,
                        debugDescription: "encryptedIban is not valid base64"
                    )
                )
            }
            self = .encryptedIBAN(data)
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: Tag.self)
        switch self {
        case .countries(let v): try c.encode(v, forKey: .countries)
        case .name(let v): try c.encode(v, forKey: .name)
        case .bic(let v): try c.encode(v, forKey: .bic)
        case .bankCode(let v): try c.encode(v, forKey: .bankCode)
        case .term(let v): try c.encode(v, forKey: .term)
        case .encryptedIBAN(let d): try c.encode(d.base64EncodedString(), forKey: .encryptedIBAN)
        }
    }
}
