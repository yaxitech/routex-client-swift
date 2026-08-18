import Foundation

/// Requirements for user identifier and password.
///
/// Exactly one of ``full``, ``userID``, or ``none`` is true.
public struct CredentialsModel: Sendable, Hashable, Codable {
    /// A full set of credentials may be provided to support fully embedded
    /// authentication (including scraped redirects).
    public let full: Bool
    /// Only a user identifier without a password may be provided.
    ///
    /// This is typically the case for decoupled authentication where the
    /// user e.g. authorizes access in a mobile application. If
    /// password-less authentication fails (e.g. no device for decoupled
    /// authentication is set up for the user and a redirect is not
    /// supported), an error is returned and the transaction has to be
    /// restarted with a full set of credentials.
    public let userID: Bool
    /// Credentials are not required. The user will provide them to the
    /// service provider during a redirect.
    public let none: Bool

    /// Build a `CredentialsModel`.
    public init(full: Bool, userID: Bool, none: Bool) {
        self.full = full
        self.userID = userID
        self.none = none
    }

    private enum CodingKeys: String, CodingKey {
        case full
        case userID = "userId"
        case none
    }
}
