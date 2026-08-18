import Foundation

/// Adapter that executes an `HTTPRequest` and returns an `HTTPResponse`.
///
/// `RoutexClient` uses an `URLSessionTransport` by default. Provide a custom
/// implementation to integrate with a different HTTP stack, to record traffic
/// in tests, or to inject middleware.
public protocol HTTPTransport: Sendable {
    /// Execute `request` and return the server's response, whatever its
    /// status. Throw `HTTPError` when no HTTP response was produced.
    func execute(_ request: HTTPRequest) async throws -> HTTPResponse
}
