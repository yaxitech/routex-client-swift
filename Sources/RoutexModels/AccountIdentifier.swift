import Foundation

/// Identifier of an account referenced by the account-information services.
public enum AccountIdentifier: Sendable, Hashable, Codable {
    /// ISO 20022 IBAN2007Identifier.
    case iban(String)
    /// Account number that is not an IBAN, e.g. ISO 20022 BBANIdentifier.
    case number(String)
    /// Masked payment card number.
    case maskedPan(String)

    private enum CodingKeys: String, CodingKey { case iban, number, maskedPan }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let v = try c.decodeIfPresent(String.self, forKey: .iban) {
            self = .iban(v)
            return
        }
        if let v = try c.decodeIfPresent(String.self, forKey: .number) {
            self = .number(v)
            return
        }
        if let v = try c.decodeIfPresent(String.self, forKey: .maskedPan) {
            self = .maskedPan(v)
            return
        }
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "AccountIdentifier missing 'iban', 'number' or 'maskedPan' key"
            )
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .iban(let v): try c.encode(v, forKey: .iban)
        case .number(let v): try c.encode(v, forKey: .number)
        case .maskedPan(let v): try c.encode(v, forKey: .maskedPan)
        }
    }
}
