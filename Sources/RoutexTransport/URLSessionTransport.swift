import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Default `HTTPTransport` backed by a `URLSession`. Available on Darwin and
/// on Linux via `swift-corelibs-foundation`'s `FoundationNetworking`.
public struct URLSessionTransport: HTTPTransport {
    /// The session requests are executed on.
    public let session: URLSession

    /// Build a transport backed by `session`.
    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func execute(_ request: HTTPRequest) async throws -> HTTPResponse {
        var urlRequest = URLRequest(url: request.url)
        urlRequest.httpMethod = request.method.rawValue
        for (k, v) in request.headers { urlRequest.setValue(v, forHTTPHeaderField: k) }
        if let body = request.body { urlRequest.httpBody = body }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.dataResponse(for: urlRequest)
        } catch {
            throw HTTPError.transportFailure(underlying: error)
        }
        guard let http = response as? HTTPURLResponse else {
            throw HTTPError.noResponse
        }

        var headers: [String: String] = [:]
        for (k, v) in http.allHeaderFields {
            if let kk = k as? String, let vv = v as? String { headers[kk] = vv }
        }
        return HTTPResponse(status: http.statusCode, headers: headers, body: data)
    }
}

extension URLSession {
    /// Cross-platform shim: macOS/iOS expose `data(for:)` directly; Linux's
    /// swift-corelibs-foundation exposes the same selector but the platform
    /// availability is gated. Both sides land on the same call.
    fileprivate func dataResponse(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await self.data(for: request)
    }
}
