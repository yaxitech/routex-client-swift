import Foundation

/// Response from a YAXI Open Banking service call.
///
/// Carries either an authenticated result or an interrupt (a dialog or
/// a redirect for the user). Interrupts require user action; pass the
/// included context back to the matching per-service `confirm` /
/// `respond` method on `RoutexClient` to continue.
public enum Response<T: Decodable & Sendable>: Sendable {
    /// Final result. See ``Result`` for the authenticated payload and the
    /// optional ``Session`` / ``ConnectionData`` to feed back into subsequent
    /// calls.
    case result(Result)
    /// User dialog. Render ``Dialog/input`` and resume with the
    /// per-service `confirm` or `respond` method, depending on the
    /// input variant.
    case dialog(Dialog)
    /// User redirect. Send the user to ``Redirect/url``; on return,
    /// resume with the per-service `confirm` method.
    case redirect(Redirect)
    /// Incomplete user redirect. Resolve to a URL via
    /// `RoutexClient.registerRedirectURI` before sending the user.
    case redirectHandle(RedirectHandle)

    /// Final result of a service call: the authenticated payload together with
    /// the optional session and connection data to feed into subsequent calls.
    public struct Result: Sendable {
        /// Authenticated JWT carrying the typed payload. Forward
        /// ``Authenticated/jwt`` to a backend that holds the HMAC key for a
        /// verified read, or call ``Authenticated/decodeUnverified()``.
        public let authenticated: Authenticated<T>
        /// Session to pass to subsequent calls within the same logical session.
        public let session: Session?
        /// Opaque connection data to reuse the established consent on later
        /// calls or via the non-interactive refresh endpoints.
        public let connectionData: ConnectionData?

        /// Build a `Result`.
        public init(
            authenticated: Authenticated<T>,
            session: Session? = nil,
            connectionData: ConnectionData? = nil
        ) {
            self.authenticated = authenticated
            self.session = session
            self.connectionData = connectionData
        }
    }
}

// MARK: - Codable
//
// Externally tagged on the wire:
//   { "Result": [Authenticated<S>, Session?, ConnectionData?] } | { "Dialog": ... }
//   | { "Redirect": ... } | { "RedirectHandle": ... }

extension Response: Decodable {
    private enum Tag: String, CodingKey {
        case result = "Result"
        case dialog = "Dialog"
        case redirect = "Redirect"
        case redirectHandle = "RedirectHandle"
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: Tag.self)
        guard c.allKeys.count == 1, let tag = c.allKeys.first else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Expected one tag for Response"
                )
            )
        }
        switch tag {
        case .result:
            // Inner is a JSON array: [authenticated_jwt, session?, connection_data?]
            var inner = try c.nestedUnkeyedContainer(forKey: tag)
            let jwt = try inner.decode(String.self)
            let session = try inner.decodeIfPresent(Session.self)
            let connectionData = try inner.decodeIfPresent(ConnectionData.self)
            self = .result(
                Result(
                    authenticated: Authenticated<T>(jwt: jwt),
                    session: session,
                    connectionData: connectionData
                )
            )
        case .dialog:
            self = .dialog(try c.decode(Dialog.self, forKey: tag))
        case .redirect:
            self = .redirect(try c.decode(Redirect.self, forKey: tag))
        case .redirectHandle:
            self = .redirectHandle(try c.decode(RedirectHandle.self, forKey: tag))
        }
    }
}
