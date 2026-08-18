import Foundation
@_spi(Interop) import RoutexCrypto
@_spi(Interop) import RoutexSettlement
import Testing

// External-consumer posture: `@_spi(Interop)` without `@testable`.
@Suite struct InteropSeamTests {
    @Test func keygenSealUnsealRoundTrips() throws {
        let keys = ChaChaBoxKeys.generate()
        let ciphertext = try ChaChaBox.seal(Data("hi".utf8), recipient: keys.publicKey)
        #expect(try ChaChaBox.unseal(ciphertext, secret: keys.secret) == Data("hi".utf8))
    }

    @Test func verifyAndServerKeyAreReachable() throws {
        let keys = ChaChaBoxKeys.generate()
        #expect(throws: (any Error).self) {
            _ = try Settlement.verify(responseBytes: Data(), clientKeys: keys).serverPublicKey
        }
    }
}
