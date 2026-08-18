import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Walks a routex redirect chain to its user-visible terminus. The demo
/// connection uses two patterns:
///   - `redirect.yaxi.tech` carries the next URL in a form-urlencoded query
///     POSTed to `https://remux.yaxi.tech/redirect`; the response is `200`
///     with the next URL in the body.
///   - Any other host returns `303` with the next URL in `Location`.
struct RedirectFollower: Sendable {
    let session: URLSession

    init() {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.httpCookieStorage = .none
        cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        self.session = URLSession(
            configuration: cfg,
            delegate: NoFollowDelegate(),
            delegateQueue: nil
        )
    }

    /// Follow `url` until the resulting URL's scheme matches `terminate` (or
    /// the chain naturally ends in a non-redirect response). Returns the
    /// terminal URL.
    func follow(_ start: URL, terminate: String? = nil, maxHops: Int = 10) async throws -> URL {
        var current = start
        for _ in 0..<maxHops {
            if let terminate, current.scheme?.lowercased() == terminate.lowercased() {
                return current
            }
            current = try await step(current)
        }
        throw RedirectFollowerError.tooManyHops(maxHops)
    }

    private func step(_ url: URL) async throws -> URL {
        if url.host == "redirect.yaxi.tech" {
            return try await followRemux(url)
        }
        return try await follow303(url)
    }

    private func followRemux(_ url: URL) async throws -> URL {
        guard let target = URL(string: "https://remux.yaxi.tech/redirect") else {
            throw RedirectFollowerError.malformedURL("remux endpoint")
        }
        let body = Data((url.query ?? "").utf8)
        var request = URLRequest(url: target)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = body

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw RedirectFollowerError.unexpectedStatus(0, url: url)
        }
        guard http.statusCode == 200 else {
            throw RedirectFollowerError.unexpectedStatus(http.statusCode, url: url)
        }
        let s =
            String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !s.isEmpty, let next = URL(string: s) else {
            throw RedirectFollowerError.malformedURL("remux body: \"\(s)\"")
        }
        return next
    }

    private func follow303(_ url: URL) async throws -> URL {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw RedirectFollowerError.unexpectedStatus(0, url: url)
        }
        guard http.statusCode == 303 else {
            throw RedirectFollowerError.unexpectedStatus(http.statusCode, url: url)
        }
        guard
            let loc =
                (http.value(forHTTPHeaderField: "Location")
                    ?? http.value(forHTTPHeaderField: "location")),
            let next = URL(string: loc, relativeTo: url)
        else {
            throw RedirectFollowerError.missingLocation(url: url)
        }
        return next.absoluteURL
    }
}

enum RedirectFollowerError: Error, CustomStringConvertible {
    case unexpectedStatus(Int, url: URL)
    case missingLocation(url: URL)
    case malformedURL(String)
    case tooManyHops(Int)

    var description: String {
        switch self {
        case .unexpectedStatus(let s, let u): return "unexpected HTTP \(s) at \(u)"
        case .missingLocation(let u): return "missing Location header at \(u)"
        case .malformedURL(let s): return "malformed URL: \(s)"
        case .tooManyHops(let n): return "redirect chain exceeded \(n) hops"
        }
    }
}

/// `URLSession` delegate that disables 3xx auto-following so we can inspect
/// `Location` headers ourselves.
private final class NoFollowDelegate: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}
