import Foundation

/// HTTP method used by `HTTPRequest`.
public enum HTTPMethod: String, Sendable, Hashable {
    case get = "GET"
    case post = "POST"
}

/// A request to be executed by an `HTTPTransport`.
public struct HTTPRequest: Sendable, Hashable {
    /// HTTP method.
    public var method: HTTPMethod
    /// Absolute request URL.
    public var url: URL
    /// Header fields to send. Single-valued per field name.
    public var headers: [String: String]
    /// Request body, or `nil` for bodyless requests.
    public var body: Data?

    /// Build a request.
    public init(method: HTTPMethod, url: URL, headers: [String: String] = [:], body: Data? = nil) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    }
}

/// A response returned by an `HTTPTransport`.
public struct HTTPResponse: Sendable, Hashable {
    /// HTTP status code.
    public var status: Int
    /// Header fields as returned by the server.
    public var headers: [String: String]
    /// Raw response body.
    public var body: Data

    /// Build a response.
    public init(status: Int, headers: [String: String], body: Data) {
        self.status = status
        self.headers = headers
        self.body = body
    }

    /// Case-insensitive header lookup. HTTP header field names are not
    /// case-sensitive; this method honors that.
    public func header(_ name: String) -> String? {
        headers.first(where: { $0.key.caseInsensitiveCompare(name) == .orderedSame })?.value
    }
}

/// Errors raised by an `HTTPTransport` itself (network failures, malformed
/// responses) - distinct from service-level errors carried in the response body.
public enum HTTPError: Error, Sendable {
    /// The transport produced no response at all (e.g. a network failure);
    /// `underlying` is the transport's own error.
    case transportFailure(underlying: any Error)
    /// The transport returned something other than an HTTP response.
    case noResponse
}

extension HTTPError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .transportFailure(let e): return "HTTP transport failure: \(e)"
        case .noResponse: return "HTTP transport returned no response"
        }
    }
}

extension HTTPError: LocalizedError {
    public var errorDescription: String? { description }
}
