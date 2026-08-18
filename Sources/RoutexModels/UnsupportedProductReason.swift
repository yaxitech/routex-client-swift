import Foundation

/// Reason a ``RoutexError/unsupportedProduct(reason:userMessage:)`` was
/// returned.
public enum UnsupportedProductReason: String, Sendable, Codable, Hashable, CaseIterable {
    /// The amount is not allowed for the payment product.
    case limit = "Limit"
    /// The recipient is not capable to receive the payment product.
    case recipient = "Recipient"
    /// Scheduled payments are not supported.
    case scheduled = "Scheduled"
}
