// Shared nucleus consumed by `RoutexClient` and `RoutexRefreshClient`. Owns the
// per-ticket settlement cache, the transport, and request-execution plumbing.

import Foundation
import RoutexModels
import RoutexSettlement
import RoutexTransport

package actor RoutexClientCore {
    let baseURL: URL
    let transport: any HTTPTransport
    private let settlementFactory: SettlementCoreFactory

    private var settlements: [UUID: any SettlementCore] = [:]
    private var lastTraceID: TraceID?
    private var redirectURI: String?

    package init(
        baseURL: URL,
        transport: any HTTPTransport,
        settlementFactory: @escaping SettlementCoreFactory
    ) {
        self.baseURL = baseURL
        self.transport = transport
        self.settlementFactory = settlementFactory
    }

    package var traceID: TraceID? { lastTraceID }

    package func setRedirectURI(_ uri: String?) { self.redirectURI = uri }

    package func systemVersion(for ticket: any RoutexTicket) async -> SystemVersionEntry? {
        await settlements[ticket.id]?.systemVersion
    }

    /// Request the settlement context for a given ticket. Created lazily on
    /// first use and reused across the lifetime of the ticket.
    private func settlement(for ticketID: UUID) -> any SettlementCore {
        if let s = settlements[ticketID] { return s }
        let s = settlementFactory(ticketID)
        settlements[ticketID] = s
        return s
    }

    /// Settle (idempotent) the ticket's session and seal `plaintext` against
    /// it. Used by callers that need to embed sealed bytes in a URL path
    /// (e.g. the `traces/{sealed}` endpoint).
    package func seal(ticket: any RoutexTicket, plaintext: Data) async throws -> Data {
        let s = settlement(for: ticket.id)
        let ticketIdHex = ticket.id.uuidString.lowercased()
        try await s.ensureSettled(extraHeaders: [
            "User-Agent": Self.userAgent,
            "yaxi-client-version": Self.clientVersion,
            "yaxi-ticket-id": ticketIdHex,
        ])
        do {
            return try await s.seal(plaintext)
        } catch {
            throw RoutexClientError.sealingFailed(
                message: "failed to seal payload",
                underlying: error
            )
        }
    }

    /// Execute a sealed request against `path` and return the unsealed
    /// response body.
    ///
    /// - On HTTP `>=400`, the response body is unsealed (best-effort) and
    ///   dispatched to a `RoutexError`.
    /// - The trace id from the response header (if any) is captured into
    ///   `traceID`.
    package func request(
        ticket: any RoutexTicket,
        path: String,
        body: Data?
    ) async throws -> Data {
        let s = settlement(for: ticket.id)
        let ticketIdHex = ticket.id.uuidString.lowercased()
        try await s.ensureSettled(extraHeaders: [
            "User-Agent": Self.userAgent,
            "yaxi-client-version": Self.clientVersion,
            "yaxi-ticket-id": ticketIdHex,
        ])

        // Seal the ticket and the body separately. The server unseals the
        // ticket from the `yaxi-ticket` header before consulting the body.
        let sealedTicket: Data
        let sealedBody: Data?
        do {
            sealedTicket = try await s.seal(Data(ticket.raw.utf8))
            if let body { sealedBody = try await s.seal(body) } else { sealedBody = nil }
        } catch {
            throw RoutexClientError.sealingFailed(
                message: "failed to seal request payload",
                underlying: error
            )
        }

        var headers: [String: String] = [
            "User-Agent": Self.userAgent,
            "yaxi-client-version": Self.clientVersion,
            "yaxi-ticket-id": ticketIdHex,
            "yaxi-ticket": sealedTicket.base64EncodedString(),
            "Accept": RoutexAPI.mediaType,
        ]
        if let sid = await s.sessionID { headers["yaxi-session-id"] = sid }
        if let r = redirectURI { headers["yaxi-redirect-uri"] = r }
        if sealedBody != nil { headers["Content-Type"] = "application/json" }

        let url = path.isEmpty ? baseURL : baseURL.appendingPathComponent(path)
        let httpRequest = HTTPRequest(
            method: sealedBody == nil ? .get : .post,
            url: url,
            headers: headers,
            body: sealedBody
        )
        let response = try await transport.execute(httpRequest)

        if let traceHeader = response.header("yaxi-trace-id"),
            let raw = Data(base64Encoded: traceHeader),
            let bytes = try? await s.unseal(raw)
        {
            self.lastTraceID = TraceID(bytes)
        }

        if response.status >= 400 {
            // Best-effort unseal: TEE-side errors come sealed; transport-
            // level errors usually do not.
            let plain = (try? await s.unseal(response.body)) ?? response.body
            throw RoutexError.dispatch(status: response.status, body: plain)
        }

        do {
            return try await s.unseal(response.body)
        } catch {
            throw RoutexClientError.unsealingFailed(
                message: "failed to unseal response",
                underlying: error
            )
        }
    }

    /// Fetch metadata for a single service connection.
    package func info(
        ticket: any RoutexTicket,
        connectionID: ConnectionID
    ) async throws -> ConnectionInfo {
        let bytes = try await request(
            ticket: ticket,
            path: "info/\(connectionID)",
            body: nil
        )
        return try WireEncoding.decode(ConnectionInfo.self, from: bytes)
    }

    /// Search for service connections matching every entry in `filters`.
    /// An empty `filters` matches nothing.
    package func search(
        ticket: any RoutexTicket,
        filters: [SearchFilter],
        ibanDetection: Bool,
        limit: Int?,
        details: [ConnectionDetails]
    ) async throws -> [ConnectionInfo] {
        if let limit, limit < 0 { throw SearchError.negativeLimit(limit) }
        let body = try WireEncoding.encode(
            SearchRequestBody(
                filters: filters,
                ibanDetection: ibanDetection,
                limit: limit,
                details: details
            )
        )
        let bytes = try await request(ticket: ticket, path: "search", body: body)
        return try WireEncoding.decode([ConnectionInfo].self, from: bytes)
    }

    private static let clientVersion = "swift/\(Version.versionString)"

    /// `RoutexClient/{version} (swift; {os}; {arch})`. Format mirrors the
    /// Rust client (`routex-client-common`), which appends `OS` and `ARCH`
    /// from `std::env::consts`. The OS / arch tokens are resolved at compile
    /// time from `#if os(…)` / `#if arch(…)`, so they reflect the build
    /// target rather than the runtime host - same as the Rust analogue.
    private static let userAgent: String = {
        let parts = ["swift", platformOS, platformArch].filter { !$0.isEmpty }
        return "RoutexClient/\(Version.versionString) (\(parts.joined(separator: "; ")))"
    }()

    private static let platformOS: String = {
        #if os(macOS)
        return "macos"
        #elseif os(iOS)
        return "ios"
        #elseif os(tvOS)
        return "tvos"
        #elseif os(watchOS)
        return "watchos"
        #elseif os(visionOS)
        return "visionos"
        #elseif os(Linux)
        return "linux"
        #elseif os(Windows)
        return "windows"
        #elseif os(Android)
        return "android"
        #elseif os(FreeBSD)
        return "freebsd"
        #elseif os(OpenBSD)
        return "openbsd"
        #else
        return ""
        #endif
    }()

    private static let platformArch: String = {
        #if arch(arm64)
        return "aarch64"
        #elseif arch(x86_64)
        return "x86_64"
        #elseif arch(arm)
        return "arm"
        #elseif arch(i386)
        return "x86"
        #else
        return ""
        #endif
    }()
}
