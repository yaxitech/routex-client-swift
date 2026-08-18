import Foundation

/// Specific code accompanying a ``RoutexError/providerError(code:userMessage:)``.
public enum ProviderErrorCode: String, Sendable, Codable, Hashable, CaseIterable {
    case maintenance = "Maintenance"
}
