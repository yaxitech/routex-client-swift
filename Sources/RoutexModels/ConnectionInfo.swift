import Foundation

/// Service connection metadata returned by
/// `RoutexClient.info(...)` and
/// `RoutexClient.search(...)`.
public struct ConnectionInfo: Sendable, Hashable, Codable {
    /// Unique identifier.
    public let id: ConnectionID
    /// ISO 3166-1 ALPHA-2 country codes.
    public let countries: [CountryCode]
    /// Display name.
    public let displayName: String
    /// What credentials the user has to provide; see ``CredentialsModel``.
    public let credentials: CredentialsModel
    /// Display label the bank uses for the user-identifier credential
    /// field, if relevant.
    public let userIDLabel: String?
    /// Display label the bank uses for the PIN / password credential
    /// field, if relevant.
    public let passwordLabel: String?
    /// Advice for the credentials to be displayed.
    public let advice: String?
    /// Logo identifier.
    public let logoID: String
    /// ISO 20022 BICFIIdentifiers. Only included in search results when
    /// ``ConnectionDetails/bics`` was requested.
    public let bics: [String]?
    /// National bank codes (as used in IBANs). Only included in search
    /// results when ``ConnectionDetails/bankCodes`` was requested.
    public let bankCodes: [String]?
    /// Labels categorizing the connection (e.g. `"beta"`, `"fints"`).
    public let labels: [String]

    /// Build a `ConnectionInfo`.
    public init(
        id: ConnectionID,
        countries: [CountryCode],
        displayName: String,
        credentials: CredentialsModel,
        userIDLabel: String? = nil,
        passwordLabel: String? = nil,
        advice: String? = nil,
        logoID: String,
        bics: [String]? = nil,
        bankCodes: [String]? = nil,
        labels: [String] = []
    ) {
        self.id = id
        self.countries = countries
        self.displayName = displayName
        self.credentials = credentials
        self.userIDLabel = userIDLabel
        self.passwordLabel = passwordLabel
        self.advice = advice
        self.logoID = logoID
        self.bics = bics
        self.bankCodes = bankCodes
        self.labels = labels
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case countries
        case displayName
        case credentials
        case userIDLabel = "userId"
        case passwordLabel = "password"
        case advice
        case logoID = "logoId"
        case bics
        case bankCodes
        case labels
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(ConnectionID.self, forKey: .id)
        self.countries = try c.decode([CountryCode].self, forKey: .countries)
        self.displayName = try c.decode(String.self, forKey: .displayName)
        self.credentials = try c.decode(CredentialsModel.self, forKey: .credentials)
        self.userIDLabel = try c.decodeIfPresent(String.self, forKey: .userIDLabel)
        self.passwordLabel = try c.decodeIfPresent(String.self, forKey: .passwordLabel)
        self.advice = try c.decodeIfPresent(String.self, forKey: .advice)
        self.logoID = try c.decode(String.self, forKey: .logoID)
        self.bics = try c.decodeIfPresent([String].self, forKey: .bics)
        self.bankCodes = try c.decodeIfPresent([String].self, forKey: .bankCodes)
        self.labels = try c.decodeIfPresent([String].self, forKey: .labels) ?? []
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(countries, forKey: .countries)
        try c.encode(displayName, forKey: .displayName)
        try c.encode(credentials, forKey: .credentials)
        try c.encodeIfPresent(userIDLabel, forKey: .userIDLabel)
        try c.encodeIfPresent(passwordLabel, forKey: .passwordLabel)
        try c.encodeIfPresent(advice, forKey: .advice)
        try c.encode(logoID, forKey: .logoID)
        try c.encodeIfPresent(bics, forKey: .bics)
        try c.encodeIfPresent(bankCodes, forKey: .bankCodes)
        if !labels.isEmpty { try c.encode(labels, forKey: .labels) }
    }
}
