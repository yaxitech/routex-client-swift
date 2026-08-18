import Foundation

/// Level of secrecy for an input field.
public enum SecrecyLevel: String, Sendable, Codable, Hashable, CaseIterable {
    /// The data is not a secret.
    case plain = "Plain"
    /// The data is a one-time password. This can usually be treated as no
    /// secret but the implementer might still choose to mask the input.
    case otp = "Otp"
    /// The data is a secret password. Input must be masked.
    case password = "Password"
}
