import Foundation

/// YAXI Open Banking services that an ``Account`` can be filtered by, via
/// ``AccountFilter/supports(_:)``.
public enum SupportedService: String, Sendable, Codable, Hashable, CaseIterable {
    case collectPayment = "CollectPayment"
}
