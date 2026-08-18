import Foundation

/// A fee applied by a bank or intermediary to a transaction.
public struct Fee: Sendable, Hashable, Codable {
    /// Amount of the fee.
    public let amount: Amount
    /// ISO 20022 `ExternalChargeType1Code` for the fee.
    public let kind: String?
    /// ISO 20022 `BICFIIdentifier` of the agent to whom the charges are due.
    public let bic: String?

    /// Build a `Fee`.
    public init(amount: Amount, kind: String? = nil, bic: String? = nil) {
        self.amount = amount
        self.kind = kind
        self.bic = bic
    }
}
