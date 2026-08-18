import Foundation

/// Bank transaction code annotation. The same transaction can carry
/// several of these in different code spaces.
public enum BankTransactionCode: Sendable, Hashable, Codable {
    /// ISO 20022 Bank Transaction Code.
    /// - Parameters:
    ///   - domain: ISO 20022 `ExternalBankTransactionDomain1Code`.
    ///   - family: ISO 20022 `ExternalBankTransactionFamily1Code`.
    ///   - subFamily: ISO 20022 `ExternalBankTransactionSubFamily1Code`.
    case iso(domain: String, family: String, subFamily: String)
    /// SWIFT transaction code.
    case swift(String)
    /// BAI2 transaction code.
    case bai(String)
    /// National transaction code, e.g. German GVC.
    case national(code: String, country: CountryCode)
    /// Unspecified transaction code, with optional issuer information.
    case other(code: String, issuer: String?)

    private enum Tag: String, CodingKey {
        case iso
        case swift
        case bai
        case national
        case other
    }
    private struct ISO: Codable, Sendable { var domain, family, subFamily: String }
    private struct National: Codable, Sendable {
        var code: String
        var country: CountryCode
    }
    private struct Other: Codable, Sendable {
        var code: String
        var issuer: String?
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: Tag.self)
        guard c.allKeys.count == 1, let tag = c.allKeys.first else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Expected one tag for BankTransactionCode"
                )
            )
        }
        switch tag {
        case .iso:
            let v = try c.decode(ISO.self, forKey: tag)
            self = .iso(domain: v.domain, family: v.family, subFamily: v.subFamily)
        case .swift: self = .swift(try c.decode(String.self, forKey: tag))
        case .bai: self = .bai(try c.decode(String.self, forKey: tag))
        case .national:
            let v = try c.decode(National.self, forKey: tag)
            self = .national(code: v.code, country: v.country)
        case .other:
            let v = try c.decode(Other.self, forKey: tag)
            self = .other(code: v.code, issuer: v.issuer)
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: Tag.self)
        switch self {
        case .iso(let d, let f, let s):
            try c.encode(ISO(domain: d, family: f, subFamily: s), forKey: .iso)
        case .swift(let s): try c.encode(s, forKey: .swift)
        case .bai(let s): try c.encode(s, forKey: .bai)
        case .national(let code, let country):
            try c.encode(National(code: code, country: country), forKey: .national)
        case .other(let code, let issuer):
            try c.encode(Other(code: code, issuer: issuer), forKey: .other)
        }
    }
}
