import Foundation

/// Address of a creditor, used by cross-border SEPA payments.
public struct CreditorAddress: Sendable, Hashable, Codable {
    /// Town name.
    public var townName: String
    /// ISO 3166-1 alpha-2 country code.
    public var country: CountryCode

    /// Build a `CreditorAddress`.
    public init(townName: String, country: CountryCode) {
        self.townName = townName
        self.country = country
    }
}
