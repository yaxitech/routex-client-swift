import Foundation

/// Data authenticated with an HMAC.
///
/// Carried inside ``Response/result(_:)`` as a
/// [JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519). The trusted backend that issued the
/// matching ticket can verify the signature and read the `data` claim;
/// untrusted clients can read the same claim with ``decodeUnverified()`` for
/// display purposes only - the result must never reach a backend or drive a
/// security-sensitive decision.
public struct Authenticated<T: Decodable & Sendable>: Sendable {
    /// Raw JWT string. Forward to a backend that holds the HMAC key for
    /// verification.
    public let jwt: String

    /// Wrap an existing JWT. No validation is performed.
    public init(jwt: String) { self.jwt = jwt }

    /// Decode the JWT payload's `data` claim into `T` without verifying the
    /// signature. Output is suitable for client-only display; use
    /// signature-verifying decoding on a trusted backend instead.
    public func decodeUnverified() throws -> T {
        let segments = jwt.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count >= 2, let payload = Base64URL.decode(String(segments[1])) else {
            throw AuthenticatedDecodeError.malformedJWT
        }
        let envelope = try JSONDecoder().decode(Envelope<T>.self, from: payload)
        return envelope.data
    }

    private struct Envelope<U: Decodable & Sendable>: Decodable, Sendable { let data: U }
}
