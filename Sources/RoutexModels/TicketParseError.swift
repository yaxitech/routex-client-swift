import Foundation

/// Errors raised when parsing a concrete ticket type from a raw JWT
/// string.
public enum TicketParseError: Error, Sendable, Equatable {
    /// Input has fewer than two segments separated by `.`, or the payload
    /// segment is not valid base64url.
    case malformedJWT
    /// JWT body had no recognizable `data` claim (or the claim was missing
    /// the required `id` / `service` fields).
    case missingDataClaim
    /// `data.service` did not match the ticket type's service tag.
    case wrongService(expected: String, actual: String)
}
