import Foundation

/// Rule to follow if the execution of a ``StandingOrder`` falls on a weekend
/// or bank holiday.
public enum ExecutionRule: String, Sendable, Codable, Hashable, CaseIterable {
    /// Following working day.
    case following = "Following"
    /// Following working day unless it would fall into the next month.
    case followingWithinAMonth = "FollowingWithinAMonth"
    /// Preceding working day.
    case preceding = "Preceding"
    /// Preceding working day unless it would fall into the previous month.
    case precedingWithinAMonth = "PrecedingWithinAMonth"
}
