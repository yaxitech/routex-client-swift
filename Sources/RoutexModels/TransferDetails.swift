import Foundation

/// One leg of a transfer: either a single transfer or one item of a bulk
/// transfer.
public struct TransferDetails: Sendable, Hashable, Codable {
    /// End-to-end identification assigned by the initiating party.
    public var endToEndIdentification: String?
    /// Amount to credit to the creditor.
    public var amount: Amount
    /// Creditor account.
    public var creditorAccount: CreditorAccountIdentifier
    /// ISO 20022 BICFIIdentifier of the creditor's agent.
    public var creditorAgentBIC: String?
    /// Creditor name.
    public var creditorName: String
    /// Creditor address, required by some cross-border products.
    public var creditorAddress: CreditorAddress?
    /// Remittance information (purpose) on the transfer.
    public var remittance: String?
    /// Who pays the fees.
    public var chargeBearer: ChargeBearer?

    /// Build a `TransferDetails`.
    public init(
        endToEndIdentification: String? = nil,
        amount: Amount,
        creditorAccount: CreditorAccountIdentifier,
        creditorAgentBIC: String? = nil,
        creditorName: String,
        creditorAddress: CreditorAddress? = nil,
        remittance: String? = nil,
        chargeBearer: ChargeBearer? = nil
    ) {
        self.endToEndIdentification = endToEndIdentification
        self.amount = amount
        self.creditorAccount = creditorAccount
        self.creditorAgentBIC = creditorAgentBIC
        self.creditorName = creditorName
        self.creditorAddress = creditorAddress
        self.remittance = remittance
        self.chargeBearer = chargeBearer
    }

    private enum CodingKeys: String, CodingKey {
        case endToEndIdentification, amount, creditorAccount
        case creditorAgentBIC = "creditorAgentBic"
        case creditorName, creditorAddress, remittance, chargeBearer
    }
}
