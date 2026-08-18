import Foundation
@_spi(Interop) import RoutexCrypto
import Testing

/// Structural guards in the hand-rolled X.509 parser that no real or
/// synthetic certificate can reach (a malformed cert that still parses as
/// DER but is missing required fields). Driven directly with hand-built
/// DER, since no fixture can produce such a certificate.
@Suite("AmdCertificate structural guards")
struct AmdCertificateGuardsTests {
    // MARK: - Minimal DER builders (short-form lengths; all bodies < 128 B)

    private static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        precondition(content.count < 128)
        return [tag, UInt8(content.count)] + content
    }
    private static func seq(_ children: [[UInt8]]) -> [UInt8] {
        tlv(0x30, children.flatMap { $0 })
    }
    private static func ctx3(_ content: [UInt8]) -> [UInt8] { tlv(0xA3, content) }
    private static let emptySeq: [UInt8] = [0x30, 0x00]
    private static func int(_ bytes: [UInt8]) -> [UInt8] { tlv(0x02, bytes) }
    private static func bitString(paddingBits: UInt8, _ content: [UInt8]) -> [UInt8] {
        tlv(0x03, [paddingBits] + content)
    }
    // A well-formed AlgorithmIdentifier (rsassa-pss OID), enough to parse.
    private static let algoId: [UInt8] = seq([
        tlv(0x06, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a])
    ])
    private static let okSig: [UInt8] = bitString(paddingBits: 0, [0x01])
    private static func utcTime(_ ascii: String) -> [UInt8] { tlv(0x17, Array(ascii.utf8)) }
    // A well-formed Validity (UTCTime notBefore/notAfter), enough to parse past.
    private static let validity: [UInt8] = seq([
        utcTime("240101000000Z"), utcTime("440101000000Z"),
    ])

    private static func parse(_ der: [UInt8]) throws {
        _ = try AmdCertificate(der: Data(der))
    }

    private static func expectMalformed(_ der: [UInt8]) {
        #expect(throws: AmdCertificateError.self) { try parse(der) }
    }

    // MARK: - Certificate level

    @Test("input that is not well-formed DER is rejected")
    func notValidDER() {
        // SEQUENCE claiming 3 content bytes but carrying a truncated INTEGER.
        Self.expectMalformed([0x30, 0x03, 0x02, 0x01])
    }

    @Test("Certificate SEQUENCE with fewer than three fields is rejected")
    func certificateMissingFields() {
        Self.expectMalformed(Self.seq([Self.emptySeq]))
    }

    @Test("signature BIT STRING with non-zero padding bits is rejected")
    func nonByteAlignedSignature() {
        Self.expectMalformed(
            Self.seq([Self.emptySeq, Self.algoId, Self.bitString(paddingBits: 1, [0x00])])
        )
    }

    @Test("AlgorithmIdentifier without an OID is rejected")
    func algorithmIdentifierWithoutOID() {
        Self.expectMalformed(Self.seq([Self.emptySeq, Self.emptySeq, Self.okSig]))
    }

    // MARK: - TBS level

    /// Build a Certificate whose TBS holds exactly `tbsChildren`.
    private static func certWithTBS(_ tbsChildren: [[UInt8]]) -> [UInt8] {
        seq([seq(tbsChildren), algoId, okSig])
    }

    @Test("TBS without a serialNumber is rejected")
    func tbsMissingSerial() {
        Self.expectMalformed(Self.certWithTBS([]))
    }

    @Test("TBS without a signature algorithm is rejected")
    func tbsMissingSignatureAlgo() {
        Self.expectMalformed(Self.certWithTBS([Self.int([0x01])]))
    }

    @Test("TBS without an issuer is rejected")
    func tbsMissingIssuer() {
        Self.expectMalformed(Self.certWithTBS([Self.int([0x01]), Self.algoId]))
    }

    @Test("TBS without a validity is rejected")
    func tbsMissingValidity() {
        Self.expectMalformed(Self.certWithTBS([Self.int([0x01]), Self.algoId, Self.emptySeq]))
    }

    @Test("TBS without a subject is rejected")
    func tbsMissingSubject() {
        Self.expectMalformed(
            Self.certWithTBS([Self.int([0x01]), Self.algoId, Self.emptySeq, Self.validity])
        )
    }

    @Test("TBS without a subjectPublicKeyInfo is rejected")
    func tbsMissingSPKI() {
        Self.expectMalformed(
            Self.certWithTBS([
                Self.int([0x01]), Self.algoId, Self.emptySeq, Self.validity, Self.emptySeq,
            ])
        )
    }

    // MARK: - Extension level

    /// A TBS with all mandatory fields plus an `[3]` extensions block wrapping
    /// `extension`.
    private static func certWithExtension(_ ext: [UInt8]) -> [UInt8] {
        certWithTBS([
            int([0x01]),  // serialNumber
            algoId,  // signature
            emptySeq,  // issuer
            validity,  // validity
            emptySeq,  // subject
            emptySeq,  // subjectPublicKeyInfo
            ctx3(seq([ext])),  // extensions [3] { SEQUENCE { ext } }
        ])
    }

    @Test("extension without an OID is rejected")
    func extensionWithoutOID() {
        Self.expectMalformed(Self.certWithExtension(Self.emptySeq))
    }

    @Test("extension with an OID but no payload is rejected")
    func extensionWithoutPayload() {
        Self.expectMalformed(
            Self.certWithExtension(Self.seq([Self.tlv(0x06, [0x55, 0x1d, 0x13])]))
        )
    }

    @Test("extension with a critical flag but no value is rejected")
    func extensionCriticalWithoutValue() {
        let boolTrue: [UInt8] = [0x01, 0x01, 0xFF]
        Self.expectMalformed(
            Self.certWithExtension(Self.seq([Self.tlv(0x06, [0x55, 0x1d, 0x13]), boolTrue]))
        )
    }

    @Test("duplicate extension OIDs are rejected")
    func duplicateExtensionOIDs() {
        // A well-formed basicConstraints extension, twice.
        let ext = Self.seq([Self.tlv(0x06, [0x55, 0x1d, 0x13]), Self.tlv(0x04, [0x30, 0x00])])
        Self.expectMalformed(
            Self.certWithTBS([
                Self.int([0x01]), Self.algoId, Self.emptySeq, Self.validity, Self.emptySeq,
                Self.emptySeq, Self.ctx3(Self.seq([ext, ext])),
            ])
        )
    }
}
