import Foundation

/// Errors raised for invalid `search` arguments, before a request goes out.
public enum SearchError: Error, Sendable, Equatable {
    /// `limit` was negative. The associated value is the given limit.
    case negativeLimit(Int)
}
