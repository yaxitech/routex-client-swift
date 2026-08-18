import Foundation

/// Specific code accompanying a ``RoutexError/ticketError(error:code:)``.
public enum TicketErrorCode: String, Sendable, Codable, Hashable, CaseIterable {
    /// Missing `yaxi-ticket` header.
    case missing = "Missing"
    /// Invalid ticket.
    case invalid = "Invalid"
    /// Ticket token lacks `kid`.
    case missingKey = "MissingKey"
    /// Unknown key.
    case unknownKey = "UnknownKey"
    /// Ticket does not match the service that was called.
    case mismatch = "Mismatch"
    /// Ticket is expired.
    case expired = "Expired"
    /// Ticket lifetime is too long.
    case invalidLifetime = "InvalidLifetime"
    /// Expired key.
    case expiredKey = "ExpiredKey"
    /// Environment mismatch between key and routex.
    case keyEnvironmentMismatch = "KeyEnvironmentMismatch"
}
