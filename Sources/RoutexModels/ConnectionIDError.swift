import Foundation

/// Errors thrown when parsing a ``ConnectionID`` from a string.
public enum ConnectionIDError: Error, Sendable, Equatable {
    /// Input was not a well-formed UUID, optionally prefixed with
    /// `connection-`. The associated value is the original string.
    case invalid(String)
}
