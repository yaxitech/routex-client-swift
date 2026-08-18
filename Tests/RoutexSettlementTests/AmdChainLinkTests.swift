import Foundation
@_spi(Interop) import RoutexCrypto
import Testing

@testable import RoutexSettlement

/// The pinned AMD roots exercise `verifySignature(issuedBy:)` offline: each
/// family's ASK is signed by its ARK, and the ARKs are self-signed.
@Suite("AMD chain links")
struct AmdChainLinkTests {
    @Test(
        "every pinned ARK is self-signed and signs its ASK",
        arguments: [
            CPUFamily.milan, .genoa, .turin,
        ]
    )
    func pinnedChainLinks(family: CPUFamily) throws {
        let chain = try #require(AmdRootStore.byFamily[family])
        try chain[0].verifySignature(issuedBy: chain[0])
        try chain[1].verifySignature(issuedBy: chain[0])
    }

    @Test("a signature by the wrong issuer is rejected")
    func wrongIssuer() throws {
        let chain = try #require(AmdRootStore.byFamily[.milan])
        #expect(throws: AmdCertificateError.signatureVerificationFailed) {
            try chain[1].verifySignature(issuedBy: chain[1])
        }
    }
}
