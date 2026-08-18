import Foundation

/// Lifecycle state of an ``Account``.
public enum AccountStatus: String, Sendable, Codable, Hashable, CaseIterable {
    case available = "Available"
    case terminated = "Terminated"
    case blocked = "Blocked"
}
