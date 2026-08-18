import Foundation

/// A party (creditor or debtor) attached to a ``Transaction``. In case of
/// reversals this refers to the initial transaction.
public struct Party: Sendable, Hashable, Codable {
    /// Creditor / debtor name.
    public let name: String?
    /// ISO 20022 IBAN2007Identifier for the creditor / debtor account.
    public let iban: String?
    /// ISO 20022 BICFIIdentifier for the creditor / debtor agent.
    public let bic: String?
    /// Ultimate creditor / debtor (name).
    public let ultimate: String?

    /// Build a `Party`.
    public init(
        name: String? = nil,
        iban: String? = nil,
        bic: String? = nil,
        ultimate: String? = nil
    ) {
        self.name = name
        self.iban = iban
        self.bic = bic
        self.ultimate = ultimate
    }
}
