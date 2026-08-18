import Foundation

/// Payment products supported by `RoutexClient.transfer(...)`.
public enum PaymentProduct: String, Sendable, Codable, Hashable, CaseIterable {
    /// SEPA Credit Transfer (SCT) in EUR.
    case sepaCreditTransfer = "SepaCreditTransfer"
    /// SEPA Instant Credit Transfer (SCT Inst) in EUR.
    case sepaInstantCreditTransfer = "SepaInstantCreditTransfer"
    /// Default SEPA Credit Transfer in EUR.
    ///
    /// Tries SCT Inst with a fallback to SCT if the instant variant is
    /// supported. Otherwise, plain SCT is used.
    case defaultSEPACreditTransfer = "DefaultSepaCreditTransfer"
    /// International credit transfer outside of SEPA (typically SWIFT).
    case crossBorderCreditTransfer = "CrossBorderCreditTransfer"
    /// Domestic credit transfer in the domestic, non-EUR currency.
    case domesticCreditTransfer = "DomesticCreditTransfer"
    /// Instant domestic credit transfer in the domestic, non-EUR currency.
    case domesticInstantCreditTransfer = "DomesticInstantCreditTransfer"
}
