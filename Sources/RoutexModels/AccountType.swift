import Foundation

/// Bank-side classification of an ``Account``.
public enum AccountType: String, Sendable, Codable, Hashable, CaseIterable {
    /// Account used to post debits and credits. ISO 20022
    /// `ExternalCashAccountType1Code` `CACC`.
    case current = "Current"
    /// Account used for credit-card payments. ISO 20022
    /// `ExternalCashAccountType1Code` `CARD`.
    case card = "Card"
    /// Account used for savings. ISO 20022
    /// `ExternalCashAccountType1Code` `SVGS`.
    case savings = "Savings"
    /// Account used for call money. No dedicated ISO 20022 code (falls into
    /// `SVGS`).
    case callMoney = "CallMoney"
    /// Account used for time deposits. No dedicated ISO 20022 code (falls
    /// into `SVGS`).
    case timeDeposit = "TimeDeposit"
    /// Account used for loans. ISO 20022 `ExternalCashAccountType1Code`
    /// `LOAN`.
    case loan = "Loan"
    /// Securities portfolio account.
    case securities = "Securities"
    /// Insurance product account.
    case insurance = "Insurance"
    /// Commerce account.
    case commerce = "Commerce"
    /// Loyalty / rewards account.
    case rewards = "Rewards"
}
