import Foundation
@_spi(Interop) import RoutexCrypto
import Testing

@_spi(Routex) @testable import RoutexSettlement

/// The pinned AMD roots are real CA certificates; the standard-constraint
/// accessors must read their Basic Constraints, Key Usage, and Validity
/// faithfully. These pin the parsing the chain validator relies on.
@Suite("AmdCertificate: standard X.509 constraints")
struct CertificateConstraintsTests {
    private static func genoaRoots() throws -> [AmdCertificate] {
        try #require(AmdRootStore.byFamily[.genoa])
    }

    @Test("ARK is a CA permitted to sign certificates, with no path-length limit")
    func arkConstraints() throws {
        let ark = try #require(try Self.genoaRoots().first { $0.subjectDN == $0.issuerDN })
        #expect(ark.isCertificateAuthority)
        #expect(ark.allowsCertificateSigning)
        #expect(ark.maxIntermediateCertificates == nil)
    }

    @Test("ASK is a CA limited to leaf issuance (pathlen 0)")
    func askConstraints() throws {
        let ask = try #require(try Self.genoaRoots().first { $0.subjectDN != $0.issuerDN })
        #expect(ask.isCertificateAuthority)
        #expect(ask.allowsCertificateSigning)
        #expect(ask.maxIntermediateCertificates == 0)
    }

    @Test("subject common name parses from the DER distinguished name")
    func subjectCommonNameParses() throws {
        let ark = try #require(try Self.genoaRoots().first { $0.subjectDN == $0.issuerDN })
        #expect(ark.subjectCommonName == "ARK-Genoa")
        let ask = try #require(try Self.genoaRoots().first { $0.subjectDN != $0.issuerDN })
        #expect(ask.subjectCommonName == "SEV-Genoa")
    }

    @Test("validity windows parse and the roots are currently valid")
    func validityParsed() throws {
        let now = Date()
        for cert in try Self.genoaRoots() {
            #expect(cert.notValidBefore < cert.notValidAfter)
            #expect(cert.notValidBefore <= now && now <= cert.notValidAfter)
        }
    }

    @Test("ARK and ASK serial numbers parse nonzero")
    func serialNumbersParse() throws {
        for cert in try Self.genoaRoots() {
            #expect(cert.serialNumber.contains { $0 != 0 })
        }
    }

    @Test("root public keys are RSA, not EC P-384")
    func rootKeysAreNotEcP384() throws {
        for cert in try Self.genoaRoots() {
            #expect((try? cert.p384PublicKey()) == nil)
            #expect((try? cert.rsaPublicKey()) != nil)
        }
    }
}
