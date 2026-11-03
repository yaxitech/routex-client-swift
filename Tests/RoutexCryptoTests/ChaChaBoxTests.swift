import Crypto
import Foundation
@_spi(Interop) import RoutexCrypto
import Testing

/// Sealed-box construction, pinned against boxes the reference
/// implementation sealed. V2 needs ML-KEM-768, so its tests skip on Apple
/// platforms before OS 26.
@Suite("ChaChaBox")
struct ChaChaBoxTests {
    private static let plaintext = Data("wurzelpfropf".utf8)

    /// V1 secret key that `legacyBox` and `v1Box` are sealed to.
    private static let v1Secret = "31eNwO39w4HcvZzmcUzKCq1uPHMP5FlazyVhl/K2u8g="
    private static let legacyBox = "Rtu9M9NV4Y5bSPZoKAGMYfFHBnj1mRS+oNmUNDGuzhBTNvOErnAmUCCF+36G8KERMae/5FQ2jlOMYWHC"
    private static let v1Box = "AQ1yZkiR3gIT6hH1CGKYL/OepI+vsrZgpBZCBU47hzII/adnsEzXTDVY5ybsRqqNpSBvswuXC7zT91Jp3Q=="

    /// V2 secret key (X25519 scalar and ML-KEM-768 seed) that `v2Box` is
    /// sealed to.
    private static let v2Secret = """
        B+l9rW+HZLDH4JMosa4Te7MytgQwWCwpTqHI16t2NSuLucdgAQtURG+Nx4+o1XXoGiYU9CY8S76a\
        TzDAA+AzteZeMHkdu1alxqctHMTpmno0j1vzxj41VTKwQPYVVVXK
        """
    private static let v2Box = """
        Aj0NHElgG+2rEPMOmMURDY5Oy1D1jD1Q4u6Y1CMwCGbnkQiiAew8UThPc0IiBSQCeutrSshOIsLp\
        0Ogid2CAQ1Ehmp+BIGX8DKPC97AoJeB1BcQzUOKFKrCouj2vanaq1Hzfxriu1jqmt1b5UZyNsU/w\
        mMLG3rwTFzaDyHqe7JHf4suoQFq33ZPmB9h8VJo/4dBQ1czcS62q/78x0jnCZLLt1MUhibvxJJxM\
        ocwbW8Dmo3vvoUr+qa7DXiZSD4CJ85BeaNvmtkQU02rXSClIFtSGGLz3JfELKDRlOfns9SoK6cTx\
        xDe8BZzbSkWMLUL8bXhOICUR5zWLdiaut8UbrTqV6zWez8b6HXPi4aZ1YFdbrOCFRpYKsOjVHAht\
        4jnFLkHV3PPl3zbUBxKnWKSg6PKHc4pRB1EPD8gmb10Kw9E7hzKJ+BjdivwBBw0U6wKI4jODRISK\
        BmD9HF8XWfq4s3ck4IXWA4eaA8q+SFWPEmzu/Y5D5PSqfqBY3Dpk6IQTISbaFCmt/m7BAx6HGeIS\
        TmO9D19hjpejOd309HKTV8xPRsrAcqHZESlKuqA8XAfvHvlh+aFPHPZHl0oD0wcUVpUW2AyiI0RM\
        IArn1OPgG6V0FjwKPj1xAq63LxfyMTKWfxuHeRcNMQ95eKnZYhcRi6x7D/m7eXXpFeVw8neQA6jV\
        qUW//hdsAESmspiXxFa58ZpXWDWjWJIwBhLbxvWpylo6Nq9SPYb+6OW8W46YM20Y0hvgn1pU+ZER\
        ZhgWt5EoWfrwegQkOkiZyE9jToVO3Hh/uE7PIEmXES+NDKe2+g+Dg02gGKK/cWGsLkLzRBgJCNKI\
        wyZxMHafWB2Jnpb5/AJ2YhkAkhDulABtt68svQcgfOzwuk3qPgNcJpIck/79xjeS0Y9D6zd1kmk+\
        2faj3hvOi/O8hZS+1p6m2e3nr19rTwWWqj6f07/ACZJW0jRb/UtNyANiZ8NjhimV+9XM1ophZahQ\
        gWm0tJ9Cu5VXjHF64PepYoaa7WUpD5NKAqxl1b7qeoUILvnymvoEr2hsp/DB081v/QqmYmK/aMxa\
        76kNL2Jjfpc3p0HjdhkvNemWrJ11LYO/mq2yh7xqDEzCePbFVtwrJCiHJ1fOrvZlTZs9QVZStynf\
        rCd4oIDqboGczY+YMpZ7F/quHakD30Tmatwe0nHO9iljeUgFeIGNMaqdOKOgrBsTXHXu0ldW8zQQ\
        wrxUaDzeRgzrVPoorodk5pQL3eXNfcGtNOeJ8UYxDHqj+wlTuPWH3aTvKolCUjcf7nvnbOL8Bl50\
        v+1oRtuD2C0SCcOb/qUKyVyLsbhOI0jRyAUn4O1h0MOiBGdSvOxN0N45czUAsYCe3Mq4zSa+1bpN\
        ettaco3Gue1Qr8XiLbmzl7r+6IkPK/mokFbWvz1OxBMXQBhKL4fpo4l8t0bva1xmfhepdOTTAwlw\
        rAFAUfPDKUBOoj6OeRnOZUfNEke/UUNwfnmcIJrGkxxP8uYMrWL7qjSKu+dofmISKptfaHpsgm9W\
        RPvRtVJEUJsB
        """

    private static func bytes(_ base64: String) -> Data {
        Data(base64Encoded: base64)!
    }

    private static func v1Keys() -> ChaChaBoxKeys {
        let key = Curve25519.KeyAgreement.PrivateKey()
        return ChaChaBoxKeys(secret: .v1(key.rawRepresentation), publicKey: .v1(key.publicKey.rawRepresentation))
    }

    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    private static func v2Keys() throws -> ChaChaBoxKeys {
        let keys = ChaChaBoxKeys.generate()
        try #require(keys.publicKey.version == 0x02)
        return keys
    }

    // MARK: - V1

    @Test("a V1 box carries its version byte and opens")
    func v1RoundTrip() throws {
        let keys = Self.v1Keys()
        let sealed = try ChaChaBox.seal(Self.plaintext, recipient: keys.publicKey)
        #expect(sealed.first == 0x01)
        #expect(sealed.count == 1 + 32 + Self.plaintext.count + 16)
        #expect(try ChaChaBox.unseal(sealed, secret: keys.secret) == Self.plaintext)
    }

    @Test("a V1 key opens a V1 box of the reference implementation")
    func v1Fixture() throws {
        let secret = ChaChaBoxSecretKey.v1(Self.bytes(Self.v1Secret))
        #expect(try ChaChaBox.unseal(Self.bytes(Self.v1Box), secret: secret) == Self.plaintext)
    }

    @Test("a V1 key refuses an unversioned box of the reference implementation")
    func v1RefusesLegacy() throws {
        let secret = ChaChaBoxSecretKey.v1(Self.bytes(Self.v1Secret))
        #expect(throws: ChaChaBoxError.unsupportedVersion(0x46)) {
            _ = try ChaChaBox.unseal(Self.bytes(Self.legacyBox), secret: secret)
        }
    }

    @Test("a tampered V1 box fails to open")
    func v1Tamper() throws {
        let keys = Self.v1Keys()
        let sealed = try ChaChaBox.seal(Self.plaintext, recipient: keys.publicKey)
        var version = sealed
        version[0] ^= 0x01
        #expect(throws: ChaChaBoxError.unsupportedVersion(0x00)) {
            _ = try ChaChaBox.unseal(version, secret: keys.secret)
        }
        // Ephemeral key, ciphertext, and tag regions.
        for index in [1, 33, sealed.count - 1] {
            var copy = sealed
            copy[index] ^= 0x01
            #expect(throws: ChaChaBoxError.decryptionFailed) {
                _ = try ChaChaBox.unseal(copy, secret: keys.secret)
            }
        }
    }

    @Test("a truncated V1 box is rejected")
    func v1Truncation() throws {
        let keys = Self.v1Keys()
        let sealed = try ChaChaBox.seal(Data(), recipient: keys.publicKey)
        for length in 0..<sealed.count {
            #expect(throws: ChaChaBoxError.self) {
                _ = try ChaChaBox.unseal(sealed.prefix(length), secret: keys.secret)
            }
        }
        #expect(throws: ChaChaBoxError.ciphertextTooShort) {
            _ = try ChaChaBox.unseal(sealed.prefix(47), secret: keys.secret)
        }
    }

    @Test("a public key of no version's length is rejected", arguments: [0, 31, 33, 1215, 1217])
    func invalidPublicKeyLength(length: Int) {
        #expect(throws: ChaChaBoxError.malformedKey) {
            _ = try ChaChaBoxPublicKey(rawRepresentation: Data(count: length))
        }
    }

    @Test("sealing to a low-order V1 key fails")
    func v1LowOrderRecipient() {
        #expect(throws: ChaChaBoxError.malformedKey) {
            _ = try ChaChaBox.seal(Self.plaintext, recipient: .v1(Data(count: 32)))
        }
    }

    // MARK: - V2

    @Test("a V2 box carries its version byte and opens")
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func v2RoundTrip() throws {
        let keys = try Self.v2Keys()
        #expect(keys.publicKey.rawRepresentation.count == 32 + 1184)
        let sealed = try ChaChaBox.seal(Self.plaintext, recipient: keys.publicKey)
        #expect(sealed.first == 0x02)
        #expect(sealed.count == 1 + 1088 + 32 + Self.plaintext.count + 16)
        #expect(try ChaChaBox.unseal(sealed, secret: keys.secret) == Self.plaintext)
    }

    @Test("a V2 key opens a V2 box of the reference implementation")
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func v2Fixture() throws {
        let secret = Self.bytes(Self.v2Secret)
        let key = ChaChaBoxSecretKey.v2(
            x25519: secret.prefix(32),
            mlkem: try MLKEM768SecretKey(seed: secret.dropFirst(32))
        )
        #expect(try ChaChaBox.unseal(Self.bytes(Self.v2Box), secret: key) == Self.plaintext)
    }

    @Test("an ML-KEM seed of invalid length is rejected", arguments: [0, 63, 65])
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func invalidMLKEMSeedLength(length: Int) {
        #expect(throws: ChaChaBoxError.malformedKey) {
            _ = try MLKEM768SecretKey(seed: Data(count: length))
        }
    }

    @Test("a V2 key refuses V1 and unversioned boxes")
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func v2RefusesDowngrade() throws {
        let keys = try Self.v2Keys()
        let x25519 = keys.publicKey.rawRepresentation.prefix(32)
        let sealed = try ChaChaBox.seal(Self.plaintext, recipient: .v1(x25519))
        #expect(throws: ChaChaBoxError.unsupportedVersion(0x01)) {
            _ = try ChaChaBox.unseal(sealed, secret: keys.secret)
        }
        #expect(throws: ChaChaBoxError.self) {
            _ = try ChaChaBox.unseal(sealed.dropFirst(), secret: keys.secret)
        }
    }

    @Test("a V1 key refuses a V2 box")
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func v1RefusesV2() throws {
        let sealed = try ChaChaBox.seal(Self.plaintext, recipient: Self.v2Keys().publicKey)
        #expect(throws: ChaChaBoxError.unsupportedVersion(0x02)) {
            _ = try ChaChaBox.unseal(sealed, secret: Self.v1Keys().secret)
        }
    }

    @Test("a tampered V2 box fails to open")
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func v2Tamper() throws {
        let keys = try Self.v2Keys()
        let sealed = try ChaChaBox.seal(Self.plaintext, recipient: keys.publicKey)
        var version = sealed
        version[0] ^= 0x01
        #expect(throws: ChaChaBoxError.unsupportedVersion(0x03)) {
            _ = try ChaChaBox.unseal(version, secret: keys.secret)
        }
        // ML-KEM ciphertext, ephemeral key, ciphertext, and tag regions.
        for index in [1, 1 + 1088, 1 + 1088 + 32, sealed.count - 1] {
            var copy = sealed
            copy[index] ^= 0x01
            #expect(throws: ChaChaBoxError.decryptionFailed) {
                _ = try ChaChaBox.unseal(copy, secret: keys.secret)
            }
        }
    }

    @Test("a truncated V2 box is rejected")
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func v2Truncation() throws {
        let keys = try Self.v2Keys()
        let sealed = try ChaChaBox.seal(Data(), recipient: keys.publicKey)
        for length in 0..<sealed.count {
            #expect(throws: ChaChaBoxError.self) {
                _ = try ChaChaBox.unseal(sealed.prefix(length), secret: keys.secret)
            }
        }
        #expect(throws: ChaChaBoxError.ciphertextTooShort) {
            _ = try ChaChaBox.unseal(Data([0x02, 1, 3, 3, 7]), secret: keys.secret)
        }
    }

    @Test("a V2 public key round-trips through its raw representation")
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func v2PublicKeyEncoding() throws {
        let publicKey = try Self.v2Keys().publicKey
        let parsed = try ChaChaBoxPublicKey(rawRepresentation: publicKey.rawRepresentation)
        #expect(parsed == publicKey)
        #expect(parsed.version == 0x02)
    }

    @Test("an ML-KEM encapsulation key failing the modulus check is rejected")
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func invalidEncapsulationKey() throws {
        var bytes = try Self.v2Keys().publicKey.rawRepresentation
        // First 12-bit coefficient to 0xfff, beyond the modulus q = 3329.
        bytes[32] = 0xff
        bytes[33] |= 0x0f
        #expect(throws: ChaChaBoxError.malformedKey) {
            _ = try ChaChaBoxPublicKey(rawRepresentation: bytes)
        }
        let recipient = ChaChaBoxPublicKey.v2(x25519: bytes.prefix(32), mlkem: bytes.dropFirst(32))
        #expect(throws: ChaChaBoxError.malformedKey) {
            _ = try ChaChaBox.seal(Self.plaintext, recipient: recipient)
        }
    }

    @Test("sealing to a V2 key with a low-order X25519 part fails")
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func v2LowOrderRecipient() throws {
        let mlkem = try Self.v2Keys().publicKey.rawRepresentation.dropFirst(32)
        #expect(throws: ChaChaBoxError.malformedKey) {
            _ = try ChaChaBox.seal(Self.plaintext, recipient: .v2(x25519: Data(count: 32), mlkem: mlkem))
        }
    }
}
