import Foundation

/// User-supplied credentials for a service call.
///
/// ``connectionID`` identifies the bank; the other fields are optional and
/// what the bank actually consumes is described by the connection's
/// ``CredentialsModel`` (returned by
/// `RoutexClient.info(...)`).
public struct Credentials: Sendable, Hashable, Codable {
    /// The connection (bank) the credentials belong to.
    public var connectionID: ConnectionID
    /// User identifier (PSU id, login name). Required when the connection's
    /// model has either ``CredentialsModel/userID`` or
    /// ``CredentialsModel/full`` set.
    public var userID: String?
    /// PIN or password. Required when the connection's model has
    /// ``CredentialsModel/full`` set.
    public var password: String?
    /// Long-lived state from a previous successful call. Pass back to skip
    /// authentication and authorization steps and (when used together with
    /// `recurringConsents: true`) to drive recurring-consent flows.
    public var connectionData: ConnectionData?

    /// Build a `Credentials` envelope.
    public init(
        connectionID: ConnectionID,
        userID: String? = nil,
        password: String? = nil,
        connectionData: ConnectionData? = nil
    ) {
        self.connectionID = connectionID
        self.userID = userID
        self.password = password
        self.connectionData = connectionData
    }

    private enum CodingKeys: String, CodingKey {
        case connectionID = "connectionId"
        case userID = "userId"
        case password
        case connectionData
    }
}
