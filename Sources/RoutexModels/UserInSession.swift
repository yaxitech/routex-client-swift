import Foundation

/// Indicates that a user is in session for a non-interactive service call.
///
/// When a user is in session, YAXI forwards the user's IP address to their
/// bank. That address is either this connection's own source IP
/// (``onThisConnection``) or an IP address the caller provides (``at(_:)``).
///
/// Without a user in session, banks limit how many requests a caller may
/// make and reject excess requests with an
/// ``RoutexError/accessExceeded(userMessage:)`` error. A user in session
/// lifts that limit.
public enum UserInSession: Sendable, Hashable, Codable {
    /// The user's IP is this connection's own source IP.
    case onThisConnection
    /// The user is at the given IP address.
    case at(String)

    // Wire form: a bare string, "connection" or the IP address.

    public init(from decoder: any Decoder) throws {
        let wire = try decoder.singleValueContainer().decode(String.self)
        self = wire == "connection" ? .onThisConnection : .at(wire)
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .onThisConnection: try c.encode("connection")
        case .at(let ipAddress): try c.encode(ipAddress)
        }
    }
}
