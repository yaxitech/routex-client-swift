import Foundation

/// Identifier of a creditor account in the payment services. IBAN only.
public enum CreditorAccountIdentifier: Sendable, Hashable, Codable {
    /// ISO 20022 IBAN2007Identifier.
    case iban(String)

    private enum CodingKeys: String, CodingKey { case iban }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let v = try c.decodeIfPresent(String.self, forKey: .iban) {
            self = .iban(v)
            return
        }
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "CreditorAccountIdentifier missing 'iban' key"
            )
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .iban(let v): try c.encode(v, forKey: .iban)
        }
    }
}
