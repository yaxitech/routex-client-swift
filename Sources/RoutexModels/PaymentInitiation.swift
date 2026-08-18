import Foundation

/// Result payload returned by
/// `RoutexClient.collectPayment(...)`.
///
/// Shape depends on the requested fields and on whether the bank had to
/// run a debtor-identification step.
public struct PaymentInitiation: Sendable, Hashable, Codable {
    /// Status of the payment, if the call reached one.
    public let status: PaymentStatus?
    /// Debtor's name as the bank reports it.
    public let debtorName: String?
    /// Plaintext debtor IBAN (only when the call asked for it).
    public let debtorIBAN: String?
    /// Backend-encrypted debtor IBAN ciphertext, suitable for round-tripping
    /// to the backend without exposing the IBAN to the frontend.
    public let encryptedDebtorIBAN: Data?
    /// Backend-encrypted debtor name ciphertext, suitable for round-tripping
    /// to the backend without exposing the name to the frontend.
    public let encryptedDebtorName: Data?

    /// Build a `PaymentInitiation`.
    public init(
        status: PaymentStatus? = nil,
        debtorName: String? = nil,
        debtorIBAN: String? = nil,
        encryptedDebtorIBAN: Data? = nil,
        encryptedDebtorName: Data? = nil
    ) {
        self.status = status
        self.debtorName = debtorName
        self.debtorIBAN = debtorIBAN
        self.encryptedDebtorIBAN = encryptedDebtorIBAN
        self.encryptedDebtorName = encryptedDebtorName
    }

    private enum CodingKeys: String, CodingKey {
        case status, debtorName
        case debtorIBAN = "debtorIban"
        case encryptedDebtorIBAN = "encryptedDebtorIban"
        case encryptedDebtorName
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.status = try c.decodeIfPresent(PaymentStatus.self, forKey: .status)
        self.debtorName = try c.decodeIfPresent(String.self, forKey: .debtorName)
        self.debtorIBAN = try c.decodeIfPresent(String.self, forKey: .debtorIBAN)
        self.encryptedDebtorIBAN = try Self.decodeBase64(c, forKey: .encryptedDebtorIBAN)
        self.encryptedDebtorName = try Self.decodeBase64(c, forKey: .encryptedDebtorName)
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(status, forKey: .status)
        try c.encodeIfPresent(debtorName, forKey: .debtorName)
        try c.encodeIfPresent(debtorIBAN, forKey: .debtorIBAN)
        if let d = encryptedDebtorIBAN {
            try c.encode(d.base64EncodedString(), forKey: .encryptedDebtorIBAN)
        }
        if let d = encryptedDebtorName {
            try c.encode(d.base64EncodedString(), forKey: .encryptedDebtorName)
        }
    }

    /// Decode a base64 string field into raw bytes, or `nil` when absent.
    private static func decodeBase64(
        _ c: KeyedDecodingContainer<CodingKeys>,
        forKey key: CodingKeys
    ) throws -> Data? {
        guard let s = try c.decodeIfPresent(String.self, forKey: key) else { return nil }
        guard let d = Data(base64Encoded: s) else {
            throw DecodingError.dataCorruptedError(
                forKey: key,
                in: c,
                debugDescription: "\(key.stringValue) must be base64"
            )
        }
        return d
    }
}
