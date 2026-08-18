// ChaChaBox: anonymous-recipient sealed-box cryptosystem. Built on X25519
// key agreement, BLAKE2b nonce derivation, HKDF-BLAKE2b-512 key derivation,
// and ChaCha20-Poly1305 (RFC 8439) authenticated encryption.
//
// Wire layout (V1):
//   ephemeral_public_key(32) || ciphertext || tag(16)

import Crypto
import Foundation

/// Public half of a ChaChaBox keypair.
@_spi(Interop) public enum ChaChaBoxPublicKey: Sendable, Hashable {
    case v1(Data)
}

/// Secret half of a ChaChaBox keypair.
@_spi(Interop) public enum ChaChaBoxSecretKey: Sendable {
    /// Raw 32-byte X25519 scalar.
    case v1(Data)
}

/// A ChaChaBox keypair.
@_spi(Interop) public struct ChaChaBoxKeys: Sendable {
    public let secret: ChaChaBoxSecretKey
    public let publicKey: ChaChaBoxPublicKey

    /// Wrap an existing keypair.
    public init(secret: ChaChaBoxSecretKey, publicKey: ChaChaBoxPublicKey) {
        self.secret = secret
        self.publicKey = publicKey
    }

    /// Generate a fresh keypair.
    public static func generate() -> ChaChaBoxKeys {
        let priv = Curve25519.KeyAgreement.PrivateKey()
        return ChaChaBoxKeys(
            secret: .v1(priv.rawRepresentation),
            publicKey: .v1(priv.publicKey.rawRepresentation)
        )
    }
}

/// Errors raised by ChaChaBox operations.
@_spi(Interop) public enum ChaChaBoxError: Error, Sendable, Equatable {
    case ciphertextTooShort
    case decryptionFailed
    case malformedKey
}

@_spi(Interop) public enum ChaChaBox {
    /// Seal `plaintext` to `recipient`.
    public static func seal(_ plaintext: Data, recipient: ChaChaBoxPublicKey) throws -> Data {
        switch recipient {
        case .v1(let recipientPK):
            return try sealV1(plaintext: plaintext, recipientPublicKey: recipientPK)
        }
    }

    /// Unseal `ciphertext` addressed to `secret`.
    public static func unseal(_ ciphertext: Data, secret: ChaChaBoxSecretKey) throws -> Data {
        switch secret {
        case .v1(let scalar):
            return try unsealV1(ciphertext: ciphertext, secretScalar: scalar)
        }
    }

    // MARK: - V1 implementation

    private static func sealV1(plaintext: Data, recipientPublicKey: Data) throws -> Data {
        guard recipientPublicKey.count == 32 else { throw ChaChaBoxError.malformedKey }

        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let ephPub = ephemeral.publicKey.rawRepresentation

        let recipient: Curve25519.KeyAgreement.PublicKey
        do {
            recipient = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKey)
        } catch {
            throw ChaChaBoxError.malformedKey
        }

        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let (key, nonce) = try session(from: shared, info: ephPub + recipientPublicKey)
        let sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce)
        return ephPub + sealed.ciphertext + sealed.tag
    }

    static func unsealV1(ciphertext: Data, secretScalar: Data) throws -> Data {
        guard ciphertext.count >= 32 + 16 else { throw ChaChaBoxError.ciphertextTooShort }
        do {
            let ephemeralPub = ciphertext.prefix(32)
            let body = ciphertext.dropFirst(32)

            let myPriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secretScalar)
            let theirPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPub)

            let shared = try myPriv.sharedSecretFromKeyAgreement(with: theirPub)
            let info = ephemeralPub + myPriv.publicKey.rawRepresentation
            let (key, nonce) = try session(from: shared, info: info)

            let tagStart = body.endIndex - 16
            let ct = body[body.startIndex..<tagStart]
            let tag = body[tagStart..<body.endIndex]
            let sealedBox = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
            return try ChaChaPoly.open(sealedBox, using: key)
        } catch {
            throw ChaChaBoxError.decryptionFailed
        }
    }

    // Derive the session ChaCha20-Poly1305 key (HKDF-BLAKE2b-512) and nonce
    // (BLAKE2b) from the X25519 shared secret and the public-key `info`.
    private static func session(
        from shared: SharedSecret,
        info: Data
    ) throws -> (key: SymmetricKey, nonce: ChaChaPoly.Nonce) {
        // SAFETY: `SharedSecret` has no safe byte accessor; the pointer is
        // read into an owned copy here and never escapes the closure.
        let ikm = shared.withUnsafeBytes { Data($0) }
        let key = HKDFBlake2b512.deriveKey(ikm: ikm, salt: Data(), info: info, length: 32)
        let nonce = try ChaChaPoly.Nonce(data: Data(Blake2b.hash(info, outputLength: 12)))
        return (SymmetricKey(data: key), nonce)
    }
}
