// ChaChaBox: anonymous-recipient sealed-box cryptosystem. Built on X25519
// (V1) or hybrid X25519 + ML-KEM-768 (V2) key agreement, BLAKE2b nonce
// derivation, HKDF-BLAKE2b-512 key derivation, and ChaCha20-Poly1305
// (RFC 8439) authenticated encryption.
//
// Wire layouts:
//   V1: 0x01 || ephemeral_public_key(32) || ciphertext || tag(16)
//   V2: 0x02 || ml_kem_ciphertext(1088) || ephemeral_public_key(32) || ciphertext || tag(16)

import Crypto
import Foundation

private let versionV1: UInt8 = 0x01
private let versionV2: UInt8 = 0x02
private let x25519KeySize = 32
private let mlkemEncapsulationKeySize = 1184
private let mlkemCiphertextSize = 1088
private let mlkemSeedSize = 64
private let tagSize = 16
private let v2KDFSalt = Data("chacha_box_ietf/v2".utf8)

/// Public half of a ChaChaBox keypair.
@_spi(Interop) public enum ChaChaBoxPublicKey: Sendable, Hashable {
    /// Raw 32-byte X25519 public key.
    case v1(Data)
    /// Raw 32-byte X25519 public key and 1184-byte ML-KEM-768 encapsulation key.
    case v2(x25519: Data, mlkem: Data)

    /// Parse a public key from ``rawRepresentation``; its length selects the
    /// version.
    public init(rawRepresentation: Data) throws {
        switch rawRepresentation.count {
        case x25519KeySize:
            self = .v1(Data(rawRepresentation))
        case x25519KeySize + mlkemEncapsulationKeySize:
            let mlkem = Data(rawRepresentation.dropFirst(x25519KeySize))
            try MLKEM768Operations.validate(encapsulationKey: mlkem)
            self = .v2(x25519: Data(rawRepresentation.prefix(x25519KeySize)), mlkem: mlkem)
        default:
            throw ChaChaBoxError.malformedKey
        }
    }

    /// The X25519 key, followed by the ML-KEM-768 encapsulation key for V2.
    public var rawRepresentation: Data {
        switch self {
        case .v1(let x25519): return x25519
        case .v2(let x25519, let mlkem): return x25519 + mlkem
        }
    }

    /// Wire format version byte.
    public var version: UInt8 {
        switch self {
        case .v1: return versionV1
        case .v2: return versionV2
        }
    }
}

/// Secret half of a ChaChaBox keypair.
@_spi(Interop) public enum ChaChaBoxSecretKey: Sendable {
    /// Raw 32-byte X25519 scalar.
    case v1(Data)
    /// Raw 32-byte X25519 scalar and ML-KEM-768 key.
    case v2(x25519: Data, mlkem: MLKEM768SecretKey)
}

/// An ML-KEM-768 key, expanded once from its seed.
@_spi(Interop) public struct MLKEM768SecretKey: Sendable {
    public let encapsulationKey: Data
    private let decapsulator: @Sendable (Data) throws -> Data

    /// Expand the 64-byte FIPS 203 key generation seed `d || z`.
    public init(seed: Data) throws {
        self = try MLKEM768Operations.expand(seed: seed)
    }

    fileprivate init(encapsulationKey: Data, decapsulator: @escaping @Sendable (Data) throws -> Data) {
        self.encapsulationKey = encapsulationKey
        self.decapsulator = decapsulator
    }

    fileprivate func decapsulate(_ ciphertext: Data) throws -> Data {
        try decapsulator(ciphertext)
    }
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

    /// Generate a fresh keypair: V2 where the platform provides ML-KEM-768,
    /// V1 otherwise.
    public static func generate() -> ChaChaBoxKeys {
        let x25519 = Curve25519.KeyAgreement.PrivateKey()
        let scalar = x25519.rawRepresentation
        let publicKey = x25519.publicKey.rawRepresentation
        guard let mlkem = MLKEM768Operations.generate() else {
            return ChaChaBoxKeys(secret: .v1(scalar), publicKey: .v1(publicKey))
        }
        return ChaChaBoxKeys(
            secret: .v2(x25519: scalar, mlkem: mlkem),
            publicKey: .v2(x25519: publicKey, mlkem: mlkem.encapsulationKey)
        )
    }
}

/// Errors raised by ChaChaBox operations.
@_spi(Interop) public enum ChaChaBoxError: Error, Sendable, Equatable {
    case ciphertextTooShort
    case decryptionFailed
    case malformedKey
    case unsupportedVersion(UInt8)
}

@_spi(Interop) public enum ChaChaBox {
    /// Seal `plaintext` to `recipient`, framed with the recipient key's
    /// version.
    public static func seal(_ plaintext: Data, recipient: ChaChaBoxPublicKey) throws -> Data {
        switch recipient {
        case .v1(let recipientPK):
            return try Data([versionV1]) + sealV1(plaintext: plaintext, recipientPublicKey: recipientPK)
        case .v2(let x25519, let mlkem):
            return try Data([versionV2])
                + sealV2(plaintext: plaintext, recipientX25519: x25519, recipientMLKEM: mlkem)
        }
    }

    /// Unseal `ciphertext` addressed to `secret`. A key opens boxes of its
    /// own version only.
    public static func unseal(_ ciphertext: Data, secret: ChaChaBoxSecretKey) throws -> Data {
        guard let version = ciphertext.first else { throw ChaChaBoxError.ciphertextTooShort }
        switch secret {
        case .v1(let scalar):
            guard version == versionV1 else { throw ChaChaBoxError.unsupportedVersion(version) }
            return try unsealV1(ciphertext: ciphertext.dropFirst(), secretScalar: scalar)
        case .v2(let x25519, let mlkem):
            guard version == versionV2 else { throw ChaChaBoxError.unsupportedVersion(version) }
            return try unsealV2(ciphertext: ciphertext.dropFirst(), secretScalar: x25519, mlkem: mlkem)
        }
    }

    // MARK: - V1 implementation

    private static func sealV1(plaintext: Data, recipientPublicKey: Data) throws -> Data {
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let ephPub = ephemeral.publicKey.rawRepresentation
        let shared = try x25519SharedSecret(ephemeral, recipientPublicKey)
        let (key, nonce) = try session(
            ikm: shared,
            salt: Data(),
            info: ephPub + recipientPublicKey,
            ephemeralPublicKey: ephPub,
            recipientPublicKey: recipientPublicKey
        )
        let sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce)
        return ephPub + sealed.ciphertext + sealed.tag
    }

    private static func unsealV1(ciphertext: Data, secretScalar: Data) throws -> Data {
        guard ciphertext.count >= x25519KeySize + tagSize else { throw ChaChaBoxError.ciphertextTooShort }
        do {
            let ephemeralPub = ciphertext.prefix(x25519KeySize)
            let myPriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secretScalar)
            let myPub = myPriv.publicKey.rawRepresentation
            let shared = try x25519SharedSecret(myPriv, ephemeralPub)
            let (key, nonce) = try session(
                ikm: shared,
                salt: Data(),
                info: ephemeralPub + myPub,
                ephemeralPublicKey: ephemeralPub,
                recipientPublicKey: myPub
            )
            return try open(ciphertext.dropFirst(x25519KeySize), using: key, nonce: nonce)
        } catch {
            throw ChaChaBoxError.decryptionFailed
        }
    }

    // MARK: - V2 implementation

    private static func sealV2(plaintext: Data, recipientX25519: Data, recipientMLKEM: Data) throws -> Data {
        let encapsulation = try MLKEM768Operations.encapsulate(to: recipientMLKEM)
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let ephPub = ephemeral.publicKey.rawRepresentation
        let shared = try x25519SharedSecret(ephemeral, recipientX25519)
        let (key, nonce) = try sessionV2(
            x25519Secret: shared,
            mlkemSecret: encapsulation.sharedSecret,
            mlkemCiphertext: encapsulation.ciphertext,
            ephemeralPublicKey: ephPub,
            recipientX25519: recipientX25519,
            recipientMLKEM: recipientMLKEM
        )
        let sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce)
        return encapsulation.ciphertext + ephPub + sealed.ciphertext + sealed.tag
    }

    private static func unsealV2(ciphertext: Data, secretScalar: Data, mlkem: MLKEM768SecretKey) throws -> Data {
        guard ciphertext.count >= mlkemCiphertextSize + x25519KeySize + tagSize else {
            throw ChaChaBoxError.ciphertextTooShort
        }
        let mlkemCiphertext = ciphertext.prefix(mlkemCiphertextSize)
        do {
            let mlkemSecret = try mlkem.decapsulate(mlkemCiphertext)
            let ephemeralPub = ciphertext.dropFirst(mlkemCiphertextSize).prefix(x25519KeySize)
            let myPriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secretScalar)
            let shared = try x25519SharedSecret(myPriv, ephemeralPub)
            let (key, nonce) = try sessionV2(
                x25519Secret: shared,
                mlkemSecret: mlkemSecret,
                mlkemCiphertext: mlkemCiphertext,
                ephemeralPublicKey: ephemeralPub,
                recipientX25519: myPriv.publicKey.rawRepresentation,
                recipientMLKEM: mlkem.encapsulationKey
            )
            return try open(ciphertext.dropFirst(mlkemCiphertextSize + x25519KeySize), using: key, nonce: nonce)
        } catch {
            throw ChaChaBoxError.decryptionFailed
        }
    }

    private static func sessionV2(
        x25519Secret: Data,
        mlkemSecret: Data,
        mlkemCiphertext: Data,
        ephemeralPublicKey: Data,
        recipientX25519: Data,
        recipientMLKEM: Data
    ) throws -> (key: SymmetricKey, nonce: ChaChaPoly.Nonce) {
        try session(
            ikm: x25519Secret + mlkemSecret,
            salt: v2KDFSalt,
            info: Data([versionV2]) + mlkemCiphertext + ephemeralPublicKey + recipientX25519 + recipientMLKEM,
            ephemeralPublicKey: ephemeralPublicKey,
            recipientPublicKey: recipientX25519
        )
    }

    // MARK: - Shared

    // Rejects a low-order public key, whose shared secret is all zeros.
    private static func x25519SharedSecret(
        _ privateKey: Curve25519.KeyAgreement.PrivateKey,
        _ publicKey: Data
    ) throws -> Data {
        let shared: Data
        do {
            let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
            // SAFETY: `SharedSecret` has no safe byte accessor; the pointer is
            // read into an owned copy here and never escapes the closure.
            shared = try privateKey.sharedSecretFromKeyAgreement(with: publicKey).withUnsafeBytes { Data($0) }
        } catch {
            throw ChaChaBoxError.malformedKey
        }
        guard shared.contains(where: { $0 != 0 }) else { throw ChaChaBoxError.malformedKey }
        return shared
    }

    // Derive the session ChaCha20-Poly1305 key (HKDF-BLAKE2b-512) and nonce
    // (BLAKE2b over the ephemeral and recipient X25519 public keys).
    private static func session(
        ikm: Data,
        salt: Data,
        info: Data,
        ephemeralPublicKey: Data,
        recipientPublicKey: Data
    ) throws -> (key: SymmetricKey, nonce: ChaChaPoly.Nonce) {
        let key = HKDFBlake2b512.deriveKey(ikm: ikm, salt: salt, info: info, length: 32)
        let nonce = try ChaChaPoly.Nonce(
            data: Blake2b.hash(ephemeralPublicKey + recipientPublicKey, outputLength: 12)
        )
        return (SymmetricKey(data: key), nonce)
    }

    private static func open(_ body: Data, using key: SymmetricKey, nonce: ChaChaPoly.Nonce) throws -> Data {
        let tagStart = body.endIndex - tagSize
        let sealedBox = try ChaChaPoly.SealedBox(
            nonce: nonce,
            ciphertext: body[body.startIndex..<tagStart],
            tag: body[tagStart..<body.endIndex]
        )
        return try ChaChaPoly.open(sealedBox, using: key)
    }
}

extension MLKEM768Operations {
    // CryptoKit defers the FIPS 203 encapsulation key check (section 7.2) to
    // encapsulation.
    static func validate(encapsulationKey: Data) throws {
        _ = try encapsulate(to: encapsulationKey)
    }
}

// On Apple platforms, swift-crypto re-exports CryptoKit, which ships
// ML-KEM-768 only with the OS 26 SDKs (Swift 6.2). Elsewhere, swift-crypto
// implements it with BoringSSL.
#if !canImport(CryptoKit) || compiler(>=6.2)
private enum MLKEM768Operations {
    static func generate() -> MLKEM768SecretKey? {
        guard #available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *),
            let key = try? MLKEM768.PrivateKey()
        else {
            return nil
        }
        return secretKey(key)
    }

    static func expand(seed: Data) throws -> MLKEM768SecretKey {
        guard #available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *) else {
            throw ChaChaBoxError.unsupportedVersion(versionV2)
        }
        // CryptoKit traps instead of throwing on a seed of the wrong length.
        guard seed.count == mlkemSeedSize else {
            throw ChaChaBoxError.malformedKey
        }
        let key: MLKEM768.PrivateKey
        do {
            key = try MLKEM768.PrivateKey(seedRepresentation: seed, publicKey: nil)
        } catch {
            throw ChaChaBoxError.malformedKey
        }
        return secretKey(key)
    }

    static func encapsulate(to encapsulationKey: Data) throws -> (ciphertext: Data, sharedSecret: Data) {
        guard #available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *) else {
            throw ChaChaBoxError.unsupportedVersion(versionV2)
        }
        let result: KEM.EncapsulationResult
        do {
            result = try MLKEM768.PublicKey(rawRepresentation: encapsulationKey).encapsulate()
        } catch {
            throw ChaChaBoxError.malformedKey
        }
        return (result.encapsulated, result.sharedSecret.withUnsafeBytes { Data($0) })
    }

    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    private static func secretKey(_ key: MLKEM768.PrivateKey) -> MLKEM768SecretKey {
        MLKEM768SecretKey(encapsulationKey: key.publicKey.rawRepresentation) {
            try key.decapsulate($0).withUnsafeBytes { Data($0) }
        }
    }
}
#else
private enum MLKEM768Operations {
    static func generate() -> MLKEM768SecretKey? {
        nil
    }

    static func expand(seed: Data) throws -> MLKEM768SecretKey {
        throw ChaChaBoxError.unsupportedVersion(versionV2)
    }

    static func encapsulate(to encapsulationKey: Data) throws -> (ciphertext: Data, sharedSecret: Data) {
        throw ChaChaBoxError.unsupportedVersion(versionV2)
    }
}
#endif
