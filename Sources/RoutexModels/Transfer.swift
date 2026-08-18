import Foundation

/// Result payload returned by `RoutexClient.transfer(...)`.
public struct Transfer: Sendable, Hashable, Codable {
    /// Payment status, when the bank reported one.
    public let status: PaymentStatus?

    /// Build a `Transfer`.
    public init(status: PaymentStatus? = nil) {
        self.status = status
    }
}
