import Foundation
@_spi(Interop) import RoutexCrypto
import RoutexModels

/// Outcome of a successful key-settlement verification.
public struct SettleResult: Sendable {
    @_spi(Interop) public let serverPublicKey: ChaChaBoxPublicKey
    /// Session id issued by the server; sent along with subsequent requests.
    public let sessionID: String
    /// Authenticated TEE system version the settlement verified.
    public let systemVersion: SystemVersionEntry
}

/// Reason why a key settlement failed.
public enum KeySettlementError: Error, Sendable, Equatable {
    /// The settlement response was not the expected JSON envelope, or the
    /// settlement endpoint answered with an HTTP error.
    case malformedResponse(reason: String)
    /// The attestation report, its VCEK chain, or the report signature
    /// failed verification.
    case attestationVerificationFailed(reason: String)
    /// The system version entry's Ed25519 signature did not verify under a
    /// trusted key.
    case systemVersionInvalid(reason: String)
    /// The verified system version's launch measurement does not match the
    /// attestation report's.
    case measurementMismatch
    /// The attestation report does not commit to the sealed handshake.
    case chachaBoxBindingMismatch
    /// The sealed handshake failed to decrypt with the client key.
    case chachaBoxDecryptFailed(reason: String)
    /// The handshake decrypted but did not carry the expected payload.
    case invalidSealedPayload(reason: String)
    /// `Settlement.seal(_:)` was called before `settle(extraHeaders:)`
    /// succeeded.
    case notReady
}
