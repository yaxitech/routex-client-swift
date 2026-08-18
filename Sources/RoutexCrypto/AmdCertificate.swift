// Minimal X.509 certificate parser, scoped to the fields the AMD VCEK chain
// validator needs (RFC 5280 section 4.1). Hand-rolled because RSASSA-PSS-signed certs
// (the format AMD's KDS uses) are not parsed by the available higher-level
// Apple X.509 stack.

import Crypto
import Foundation
import SwiftASN1
import _CryptoExtras

/// Subset of an X.509 certificate used by AMD VCEK chain validation.
@_spi(Interop)
public struct AmdCertificate: Sendable, Hashable {
    /// Inner `tbsCertificate` SEQUENCE bytes - the data the parent signs over.
    public let tbsBytes: Data
    /// `issuer` Distinguished Name encoded bytes.
    public let issuerDN: Data
    /// `subject` Distinguished Name encoded bytes.
    public let subjectDN: Data
    /// `subjectPublicKeyInfo` SEQUENCE bytes.
    public let subjectPublicKeyInfoBytes: Data
    /// OID of the algorithm used to sign this certificate.
    public let signatureAlgorithmOID: ASN1ObjectIdentifier
    /// `parameters` field of the AlgorithmIdentifier, if present.
    public let signatureAlgorithmParameters: Data?
    /// Raw signature bytes (BIT STRING content, padding bits stripped).
    public let signatureBytes: Data
    /// `serialNumber` INTEGER content octets (big-endian two's complement).
    public let serialNumber: Data
    /// Start of the validity window (`notBefore`).
    public let notValidBefore: Date
    /// End of the validity window (`notAfter`).
    public let notValidAfter: Date
    /// Extensions, indexed by OID for fast lookup.
    public let extensions: [ASN1ObjectIdentifier: AmdExtension]

    /// Parse a single DER-encoded certificate.
    public init(der bytes: Data) throws {
        do {
            let root = try DER.parse(Array(bytes))
            try self.init(node: root)
        } catch let e as AmdCertificateError {
            throw e
        } catch {
            throw AmdCertificateError.malformed(reason: "DER parse failed: \(error)")
        }
    }

    private init(node: ASN1Node) throws {
        // Certificate ::= SEQUENCE { tbs, sigAlgo, sigValue }
        var tbsBytes: Data?
        var sigOID: ASN1ObjectIdentifier?
        var sigParams: Data?
        var sigBytes: Data?
        var tbsParts: TBSParts?

        try DER.sequence(node, identifier: .sequence) { children in
            guard let tbsNode = children.next(),
                let sigAlgoNode = children.next(),
                let sigValueNode = children.next()
            else {
                throw AmdCertificateError.malformed(reason: "Certificate: missing fields")
            }

            tbsBytes = Data(tbsNode.encodedBytes)
            let (oid, params) = try Self.parseAlgorithmIdentifier(sigAlgoNode)
            sigOID = oid
            sigParams = params

            let sigBitString = try ASN1BitString(derEncoded: sigValueNode)
            guard sigBitString.paddingBits == 0 else {
                throw AmdCertificateError.malformed(reason: "non-byte-aligned signature BIT STRING")
            }
            sigBytes = Data(sigBitString.bytes)

            tbsParts = try Self.parseTBS(tbsNode)
        }

        guard let tbsBytes, let sigOID, let sigBytes, let tbsParts else {
            throw AmdCertificateError.malformed(reason: "Certificate: incomplete parse")
        }
        self.tbsBytes = tbsBytes
        self.signatureAlgorithmOID = sigOID
        self.signatureAlgorithmParameters = sigParams
        self.signatureBytes = sigBytes
        self.issuerDN = tbsParts.issuerDN
        self.subjectDN = tbsParts.subjectDN
        self.subjectPublicKeyInfoBytes = tbsParts.subjectPublicKeyInfoBytes
        self.serialNumber = tbsParts.serialNumber
        self.notValidBefore = tbsParts.notValidBefore
        self.notValidAfter = tbsParts.notValidAfter
        self.extensions = tbsParts.extensions
    }

    // MARK: - TBS parsing

    private struct TBSParts {
        let issuerDN: Data
        let subjectDN: Data
        let subjectPublicKeyInfoBytes: Data
        let serialNumber: Data
        let notValidBefore: Date
        let notValidAfter: Date
        let extensions: [ASN1ObjectIdentifier: AmdExtension]
    }

    // TBSCertificate ::= SEQUENCE {
    //   version         [0] EXPLICIT Version DEFAULT v1,
    //   serialNumber    INTEGER,
    //   signature       AlgorithmIdentifier,
    //   issuer          Name,
    //   validity        Validity,
    //   subject         Name,
    //   subjectPublicKeyInfo SubjectPublicKeyInfo,
    //   issuerUniqueID  [1] IMPLICIT BIT STRING OPTIONAL,
    //   subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL,
    //   extensions      [3] EXPLICIT Extensions OPTIONAL
    // }
    private static func parseTBS(_ tbsNode: ASN1Node) throws -> TBSParts {
        var issuer: Data?
        var subject: Data?
        var spki: Data?
        var serial: Data?
        var notBefore: Date?
        var notAfter: Date?
        var exts: [ASN1ObjectIdentifier: AmdExtension] = [:]

        try DER.sequence(tbsNode, identifier: .sequence) { children in
            // Optional [0] EXPLICIT version.
            var next = children.next()
            if let n = next, case .constructed = n.content,
                n.identifier == .init(tagWithNumber: 0, tagClass: .contextSpecific)
            {
                next = children.next()
            }

            guard let serialNode = next, serialNode.identifier == .integer,
                case .primitive(let serialBytes) = serialNode.content
            else {
                throw AmdCertificateError.malformed(reason: "TBS: missing serialNumber")
            }
            serial = Data(serialBytes)
            guard children.next() != nil else {
                throw AmdCertificateError.malformed(reason: "TBS: missing signature algo")
            }
            guard let issuerNode = children.next() else {
                throw AmdCertificateError.malformed(reason: "TBS: missing issuer")
            }
            issuer = Data(issuerNode.encodedBytes)
            guard let validityNode = children.next() else {
                throw AmdCertificateError.malformed(reason: "TBS: missing validity")
            }
            (notBefore, notAfter) = try Self.parseValidity(validityNode)
            guard let subjectNode = children.next() else {
                throw AmdCertificateError.malformed(reason: "TBS: missing subject")
            }
            subject = Data(subjectNode.encodedBytes)
            guard let spkiNode = children.next() else {
                throw AmdCertificateError.malformed(reason: "TBS: missing SPKI")
            }
            spki = Data(spkiNode.encodedBytes)

            while let n = children.next() {
                let id = n.identifier
                guard id.tagClass == .contextSpecific else { continue }
                if id.tagNumber == 3 {
                    if case .constructed(let inner) = n.content {
                        for child in inner {
                            try Self.parseExtensions(child, into: &exts)
                        }
                    }
                }
            }
        }

        guard let issuer = issuer, let subject = subject, let spki = spki,
            let serial = serial, let notBefore = notBefore, let notAfter = notAfter
        else {
            throw AmdCertificateError.malformed(reason: "TBS: missing required field")
        }
        return TBSParts(
            issuerDN: issuer,
            subjectDN: subject,
            subjectPublicKeyInfoBytes: spki,
            serialNumber: serial,
            notValidBefore: notBefore,
            notValidAfter: notAfter,
            extensions: exts
        )
    }

    // Validity ::= SEQUENCE { notBefore Time, notAfter Time }
    // Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
    private static func parseValidity(_ node: ASN1Node) throws -> (Date, Date) {
        var notBefore: Date?
        var notAfter: Date?
        try DER.sequence(node, identifier: .sequence) { times in
            guard let beforeNode = times.next(), let afterNode = times.next() else {
                throw AmdCertificateError.malformed(reason: "Validity: missing field")
            }
            notBefore = try Self.parseTime(beforeNode)
            notAfter = try Self.parseTime(afterNode)
        }
        guard let notBefore, let notAfter else {
            throw AmdCertificateError.malformed(reason: "Validity: incomplete")
        }
        return (notBefore, notAfter)
    }

    private static func parseTime(_ node: ASN1Node) throws -> Date {
        if let utc = try? UTCTime(derEncoded: node) {
            return try Self.makeDate(
                utc.year,
                utc.month,
                utc.day,
                utc.hours,
                utc.minutes,
                utc.seconds
            )
        }
        if let generalized = try? GeneralizedTime(derEncoded: node) {
            return try Self.makeDate(
                generalized.year,
                generalized.month,
                generalized.day,
                generalized.hours,
                generalized.minutes,
                generalized.seconds
            )
        }
        throw AmdCertificateError.malformed(reason: "Validity: unsupported time encoding")
    }

    private static let utcCalendar: Calendar = {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar
    }()

    private static func makeDate(
        _ year: Int,
        _ month: Int,
        _ day: Int,
        _ hours: Int,
        _ minutes: Int,
        _ seconds: Int
    ) throws -> Date {
        var components = DateComponents()
        components.year = year
        components.month = month
        components.day = day
        components.hour = hours
        components.minute = minutes
        components.second = seconds
        guard let date = Self.utcCalendar.date(from: components) else {
            throw AmdCertificateError.malformed(reason: "Validity: invalid date components")
        }
        return date
    }

    private static func parseExtensions(
        _ node: ASN1Node,
        into exts: inout [ASN1ObjectIdentifier: AmdExtension]
    ) throws {
        try DER.sequence(node, identifier: .sequence) { iter in
            while let extNode = iter.next() {
                let ext = try AmdExtension(node: extNode)
                guard exts.updateValue(ext, forKey: ext.oid) == nil else {
                    throw AmdCertificateError.malformed(reason: "duplicate extension \(ext.oid)")
                }
            }
        }
    }

    // MARK: - Algorithm identifier

    private static func parseAlgorithmIdentifier(
        _ node: ASN1Node
    ) throws -> (
        ASN1ObjectIdentifier, Data?
    ) {
        var oid: ASN1ObjectIdentifier?
        var params: Data?
        try DER.sequence(node, identifier: .sequence) { iter in
            guard let oidNode = iter.next() else {
                throw AmdCertificateError.malformed(reason: "AlgorithmIdentifier: no OID")
            }
            oid = try ASN1ObjectIdentifier(derEncoded: oidNode)
            if let pNode = iter.next() {
                params = Data(pNode.encodedBytes)
            }
        }
        guard let resolvedOID = oid else {
            throw AmdCertificateError.malformed(reason: "AlgorithmIdentifier: missing OID")
        }
        return (resolvedOID, params)
    }
}

/// One X.509 extension (RFC 5280 section 4.1.2.9).
@_spi(Interop)
public struct AmdExtension: Sendable, Hashable {
    public let oid: ASN1ObjectIdentifier
    public let critical: Bool
    /// Bytes inside the OCTET STRING (i.e., the `extnValue` payload).
    public let value: Data

    init(node: ASN1Node) throws {
        var oid: ASN1ObjectIdentifier?
        var critical = false
        var value: Data?
        try DER.sequence(node, identifier: .sequence) { iter in
            guard let oidNode = iter.next() else {
                throw AmdCertificateError.malformed(reason: "Extension: no OID")
            }
            oid = try ASN1ObjectIdentifier(derEncoded: oidNode)

            guard let secondNode = iter.next() else {
                throw AmdCertificateError.malformed(reason: "Extension: missing payload")
            }
            if secondNode.identifier == .boolean {
                critical = (try? Bool(derEncoded: secondNode)) ?? false
                guard let octet = iter.next() else {
                    throw AmdCertificateError.malformed(reason: "Extension: missing value")
                }
                let s = try ASN1OctetString(derEncoded: octet)
                value = Data(s.bytes)
            } else {
                let s = try ASN1OctetString(derEncoded: secondNode)
                value = Data(s.bytes)
            }
        }
        guard let resolvedOID = oid, let resolvedValue = value else {
            throw AmdCertificateError.malformed(reason: "Extension: missing required fields")
        }
        self.oid = resolvedOID
        self.critical = critical
        self.value = resolvedValue
    }
}

@_spi(Interop)
public enum AmdCertificateError: Error, Sendable, Equatable {
    case malformed(reason: String)
    case unsupportedSignatureAlgorithm(ASN1ObjectIdentifier)
    case publicKeyParseFailed(reason: String)
    case signatureVerificationFailed
}

// MARK: - Public-key helpers

extension AmdCertificate {
    /// Decode the cert's subject public key as an RSA key.
    public func rsaPublicKey() throws -> _RSA.Signing.PublicKey {
        do {
            return try _RSA.Signing.PublicKey(derRepresentation: subjectPublicKeyInfoBytes)
        } catch {
            throw AmdCertificateError.publicKeyParseFailed(reason: "RSA: \(error)")
        }
    }

    /// Decode the cert's subject public key as a P-384 ECDSA key.
    public func p384PublicKey() throws -> P384.Signing.PublicKey {
        do {
            return try P384.Signing.PublicKey(derRepresentation: subjectPublicKeyInfoBytes)
        } catch {
            throw AmdCertificateError.publicKeyParseFailed(reason: "P-384: \(error)")
        }
    }
}

// MARK: - Chain and extension helpers

extension AmdCertificate {
    /// Parse a PEM bundle into certificates, in document order.
    public static func parseChain(pem: String) throws -> [AmdCertificate] {
        let docs: [PEMDocument]
        do {
            docs = try PEMDocument.parseMultiple(pemString: pem)
        } catch {
            throw AmdCertificateError.malformed(reason: "PEM parse: \(error)")
        }
        guard !docs.isEmpty else {
            throw AmdCertificateError.malformed(reason: "no PEM blocks")
        }
        return try docs.map { doc in
            do {
                return try AmdCertificate(der: Data(doc.derBytes))
            } catch {
                throw AmdCertificateError.malformed(reason: "DER parse: \(error)")
            }
        }
    }

    /// Verify this certificate's RSASSA-PSS signature (SHA-384, MGF1-SHA384)
    /// against `issuer`'s RSA public key.
    public func verifySignature(issuedBy issuer: AmdCertificate) throws {
        guard signatureAlgorithmOID == X509AlgorithmOID.rsaPSS else {
            throw AmdCertificateError.unsupportedSignatureAlgorithm(signatureAlgorithmOID)
        }
        let issuerKey = try issuer.rsaPublicKey()
        let signature = _RSA.Signing.RSASignature(rawRepresentation: signatureBytes)
        let digest = SHA384.hash(data: tbsBytes)
        guard issuerKey.isValidSignature(signature, for: digest, padding: .PSS) else {
            throw AmdCertificateError.signatureVerificationFailed
        }
    }

    /// Decode extension `oid` as an IA5String; `nil` when absent.
    public func ia5StringExtension(_ oid: ASN1ObjectIdentifier) throws -> String? {
        guard let ext = extensions[oid] else { return nil }
        do {
            let s = try ASN1IA5String(derEncoded: Array(ext.value))
            return String(decoding: s.bytes, as: UTF8.self)
        } catch {
            throw AmdCertificateError.malformed(
                reason: "extension \(oid) is not an IA5String: \(error)"
            )
        }
    }

    /// Decode extension `oid` as an INTEGER; `nil` when absent.
    public func integerExtension(_ oid: ASN1ObjectIdentifier) throws -> Int? {
        guard let ext = extensions[oid] else { return nil }
        do {
            return try Int(derEncoded: Array(ext.value))
        } catch {
            throw AmdCertificateError.malformed(
                reason: "extension \(oid) is not an INTEGER: \(error)"
            )
        }
    }

    // MARK: - Standard X.509 constraints

    /// The subject's `commonName` (OID 2.5.4.3), or `nil` when absent.
    public var subjectCommonName: String? {
        Self.commonName(inDistinguishedName: subjectDN)
    }

    // Name ::= SEQUENCE OF RelativeDistinguishedName
    // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
    // AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
    private static func commonName(inDistinguishedName der: Data) -> String? {
        guard let root = try? DER.parse(Array(der)) else { return nil }
        var commonName: String?
        try? DER.sequence(root, identifier: .sequence) { rdns in
            while let rdn = rdns.next() {
                guard case .constructed(let attributes) = rdn.content else { continue }
                for attribute in attributes {
                    guard case .constructed(let pair) = attribute.content else { continue }
                    var fields = pair.makeIterator()
                    guard let oidNode = fields.next(), let valueNode = fields.next(),
                        let oid = try? ASN1ObjectIdentifier(derEncoded: oidNode),
                        oid == X509AttributeOID.commonName,
                        case .primitive(let bytes) = valueNode.content
                    else { continue }
                    commonName = String(decoding: bytes, as: UTF8.self)
                }
            }
        }
        return commonName
    }

    /// Whether Basic Constraints marks this certificate as a CA (`cA = true`).
    /// Malformed or absent Basic Constraints reads as non-CA.
    public var isCertificateAuthority: Bool {
        basicConstraints?.isCA ?? false
    }

    /// Basic Constraints `pathLenConstraint`: the maximum number of intermediate
    /// CA certificates permitted below this one. `nil` when unconstrained or absent.
    public var maxIntermediateCertificates: Int? {
        basicConstraints?.pathLen ?? nil
    }

    /// Whether Key Usage permits certificate signing (`keyCertSign`). `true` when
    /// the Key Usage extension is absent (no restriction); a present but malformed
    /// extension reads as `false`.
    public var allowsCertificateSigning: Bool {
        guard let ext = extensions[X509ExtensionOID.keyUsage] else { return true }
        guard let node = try? DER.parse(Array(ext.value)),
            let bits = try? ASN1BitString(derEncoded: node)
        else { return false }
        // KeyUsage is a big-endian BIT STRING; keyCertSign is bit 5 of byte 0.
        let bytes = Array(bits.bytes)
        return bytes.first.map { $0 & 0x04 != 0 } ?? false
    }

    // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
    //                                 pathLenConstraint INTEGER (0..MAX) OPTIONAL }
    private var basicConstraints: (isCA: Bool, pathLen: Int?)? {
        guard let ext = extensions[X509ExtensionOID.basicConstraints],
            let node = try? DER.parse(Array(ext.value))
        else { return nil }
        var isCA = false
        var pathLen: Int?
        do {
            try DER.sequence(node, identifier: .sequence) { fields in
                guard let first = fields.next() else { return }
                if first.identifier == .boolean {
                    isCA = (try? Bool(derEncoded: first)) ?? false
                    if let second = fields.next() {
                        pathLen = try? Int(derEncoded: second)
                    }
                } else {
                    pathLen = try? Int(derEncoded: first)
                }
            }
        } catch {
            return nil
        }
        return (isCA, pathLen)
    }
}

private enum X509ExtensionOID {
    /// `basicConstraints` (RFC 5280 section 4.2.1.9).
    static let basicConstraints: ASN1ObjectIdentifier = "2.5.29.19"
    /// `keyUsage` (RFC 5280 section 4.2.1.3).
    static let keyUsage: ASN1ObjectIdentifier = "2.5.29.15"
}

private enum X509AttributeOID {
    /// `commonName` (RFC 4519 section 2.3).
    static let commonName: ASN1ObjectIdentifier = "2.5.4.3"
}

// MARK: - Signature algorithm OIDs

@_spi(Interop)
public enum X509AlgorithmOID {
    /// `rsassa-pss` (RFC 4055 section 3.1).
    public static let rsaPSS: ASN1ObjectIdentifier = "1.2.840.113549.1.1.10"
    /// `sha384WithRSAEncryption` (RFC 8017 section A.2).
    public static let sha384WithRSA: ASN1ObjectIdentifier = "1.2.840.113549.1.1.12"
    /// `ecdsa-with-SHA384` (RFC 5758 section 3.2).
    public static let ecdsaWithSHA384: ASN1ObjectIdentifier = "1.2.840.10045.4.3.3"
    /// `ed25519` (RFC 8410 section 3).
    public static let ed25519: ASN1ObjectIdentifier = "1.3.101.112"
}
