import Foundation

/// Errors raised by ``Authenticated/decodeUnverified()`` when the JWT
/// segments cannot be parsed.
public enum AuthenticatedDecodeError: Error, Sendable, Equatable {
    /// The string does not contain at least two base64url segments separated
    /// by `.`, or a segment is not valid base64url.
    case malformedJWT
}
