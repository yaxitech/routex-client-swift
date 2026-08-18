import Crypto
import Foundation
import RoutexClient
@_spi(Interop) import RoutexCrypto
import RoutexModels
import Testing

@testable import RoutexSettlement

/// Round-trip the encrypted-IBAN flow: encrypt locally with
/// HKDF-Blake2b-512(`info: "on-file-data"`) + ChaCha20-Poly1305 using the
/// API secret, pass it as `DebtorAccountIdentifier.encryptedIBAN`, expect
/// the bank to decrypt back to the original IBAN.
@Suite("Live: collectPayment (encrypted IBAN)", .enabled(if: LiveEnvironment.isAvailable))
struct EncryptedIbanTests {
    @Test func encryptedIbanRoundTrips() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let plainIban = "DE02120300000000202051"
        let blob = encryptOnFileData(plaintext: Data(plainIban.utf8), secret: env.secret)

        let ticket = try DemoData.collectPaymentTicket(env.issuer)

        let response = try await client.collectPayment(
            ticket: ticket,
            credentials: Credentials(
                connectionID: DemoData.demoConnection,
                userID: "result"
            ),
            account: DebtorAccountReference(id: .encryptedIBAN(blob), currency: "EUR")
        )
        guard case .result(let result) = response else {
            Issue.record("expected .result, got \(response)")
            return
        }
        let decoded = try result.authenticated.decodeUnverified()

        #expect(decoded.data.debtorIBAN == plainIban)
    }

    /// Local encryption matching the routex `on-file-data` envelope:
    /// `nonce(12) | ChaCha20-Poly1305-Encrypt(K, nonce, plaintext) | tag(16)`
    /// with `K = HKDF-Blake2b-512(secret, salt: empty, info: "on-file-data", L=32)`.
    private func encryptOnFileData(plaintext: Data, secret: Data) -> Data {
        let key = HKDFBlake2b512.deriveKey(
            ikm: secret,
            salt: Data(),
            info: Data("on-file-data".utf8),
            length: 32
        )
        var nonceBytes = Data(count: 12)
        nonceBytes.withUnsafeMutableBytes { _ = SystemRandomNumberGenerator.fill($0) }
        let nonce = try! ChaChaPoly.Nonce(data: nonceBytes)
        let sealed = try! ChaChaPoly.seal(
            plaintext,
            using: SymmetricKey(data: key),
            nonce: nonce
        )
        return nonceBytes + sealed.ciphertext + sealed.tag
    }
}

extension SystemRandomNumberGenerator {
    fileprivate static func fill(_ buf: UnsafeMutableRawBufferPointer) -> Int {
        var rng = SystemRandomNumberGenerator()
        for i in 0..<buf.count {
            buf[i] = UInt8.random(in: 0...255, using: &rng)
        }
        return buf.count
    }
}
