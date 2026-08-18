import Foundation

/// Specific code accompanying a ``RoutexError/serviceBlocked(code:userMessage:)``.
public enum ServiceBlockedCode: String, Sendable, Codable, Hashable, CaseIterable {
    /// Something is not set up for the user, e.g. there are no TAN
    /// methods.
    case missingSetup = "MissingSetup"
    /// User attention is required via another channel. Typically the user
    /// needs to log into the Online Banking.
    case actionRequired = "ActionRequired"
}
