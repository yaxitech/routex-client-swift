import Foundation

/// Who pays the fees of a SEPA transfer. Wire values are the corresponding
/// ISO 20022 four-letter codes.
public enum ChargeBearer: String, Sendable, Codable, Hashable, CaseIterable {
    /// `DEBT`: charges borne by the debtor.
    case borneByDebtor = "DEBT"
    /// `CRED`: charges borne by the creditor.
    case borneByCreditor = "CRED"
    /// `SHAR`: charges shared between debtor and creditor.
    case shared = "SHAR"
    /// `SLEV`: charges follow the agreed service level.
    case followingServiceLevel = "SLEV"
}
