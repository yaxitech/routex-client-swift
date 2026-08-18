import Foundation

/// Specific code accompanying a ``RoutexError/paymentFailed(code:userMessage:)``.
public enum PaymentErrorCode: String, Sendable, Codable, Hashable, CaseIterable {
    case limitExceeded = "LimitExceeded"
    case insufficientFunds = "InsufficientFunds"
}
