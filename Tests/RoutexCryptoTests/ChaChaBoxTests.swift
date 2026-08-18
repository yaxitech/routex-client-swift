import Foundation
@_spi(Interop) import RoutexCrypto
import Testing

/// Negative paths of the sealed-box construction; the happy path is pinned
/// cross-implementation by the settlement fixture suite.
@Suite("ChaChaBox")
struct ChaChaBoxTests {
    @Test("a tampered box fails to open")
    func tamper() throws {
        let keys = ChaChaBoxKeys.generate()
        let sealed = try ChaChaBox.seal(Data("payload".utf8), recipient: keys.publicKey)
        // Ephemeral key, ciphertext, and tag regions.
        for index in [0, 32, sealed.count - 1] {
            var copy = sealed
            copy[index] ^= 0x01
            #expect(throws: ChaChaBoxError.decryptionFailed) {
                _ = try ChaChaBox.unseal(copy, secret: keys.secret)
            }
        }
    }

    @Test("a truncated box is rejected")
    func truncation() throws {
        let keys = ChaChaBoxKeys.generate()
        let sealed = try ChaChaBox.seal(Data(), recipient: keys.publicKey)
        #expect(throws: ChaChaBoxError.ciphertextTooShort) {
            _ = try ChaChaBox.unseal(sealed.prefix(47), secret: keys.secret)
        }
    }
}
