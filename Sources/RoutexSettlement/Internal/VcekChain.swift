// AMD VCEK certificate chain validator. Walks the leaf back to a self-signed
// AMD root (ARK) by issuer-DN matching, RSA-PSS-SHA384 verifies every link,
// then reads the AMD extensions on the leaf to expose product and TCB SPLs.
// AMD doc 57230 §3.

import Foundation
@_spi(Interop) import RoutexCrypto

/// Source of the trust anchor (and optional intermediate) used when validating
/// a VCEK certificate chain.
enum VcekRootStore: Sendable {
    /// Built-in AMD KDS roots.
    case amd
    /// Caller-supplied PEM trust material; intermediate optional.
    case pem(anchorPem: String, intermediatePem: String? = nil)
}

enum VcekChainError: Error, Sendable, Equatable {
    case malformedPem(reason: String)
    case chainBroken(reason: String)
    case missingRoot(reason: String)
    case unexpectedProduct(name: String)
    case invalidExtensionValue(reason: String)
}

/// Result of verifying a VCEK certificate chain. The leaf is retained so the
/// attestation-report verifier can use it for the ECDSA P-384 signature check.
struct VcekChainVerifyResult: Sendable {
    let leafSubjectDN: Data
    let family: CPUFamily
    let productName: VcekProduct
    let leaf: AmdCertificate
    let vcekTcb: VcekTcb
}

enum VcekChainOps {
    static func verify(
        vcekChainPem: String,
        rootStore: VcekRootStore,
        now: Date = Date()
    ) throws -> VcekChainVerifyResult {
        let parsed = try parseChain(vcekChainPem)
        guard let leaf = parsed.first else {
            throw VcekChainError.malformedPem(reason: "empty VCEK chain")
        }
        let intermediates = Array(parsed.dropFirst())

        let roots: [AmdCertificate]
        switch rootStore {
        case .amd:
            // Issuer-DN matching pins the correct family across all anchors.
            roots = AmdRootStore.byFamily.values.flatMap { $0 }
        case .pem(let anchor, let intermediate):
            roots = try loadPemRoots(anchor: anchor, intermediate: intermediate)
        }

        let path = try buildPath(leaf: leaf, intermediates: intermediates, roots: roots)
        try verifyPathSignatures(path)
        try verifyConstraints(path, now: now)

        // The leaf is the VCEK; AMD doc 57230 Table 9 fixes its subject CN.
        guard leaf.subjectCommonName == "SEV-VCEK" else {
            throw VcekChainError.chainBroken(reason: "leaf subject common name is not SEV-VCEK")
        }

        // AMD doc 57230 Table 9: the VCEK serial number is zero.
        guard leaf.serialNumber.allSatisfy({ $0 == 0 }) else {
            throw VcekChainError.chainBroken(reason: "leaf serial number is not zero")
        }

        // AMD doc 57230 Table 9: the VCEK public key is ECDSA on curve P-384.
        guard (try? leaf.p384PublicKey()) != nil else {
            throw VcekChainError.chainBroken(reason: "leaf public key is not an EC P-384 key")
        }

        let product: VcekProduct
        do {
            product = try leaf.amdProductName()
        } catch {
            throw VcekChainError.invalidExtensionValue(reason: "product name: \(error)")
        }

        let tcb: VcekTcb
        do {
            tcb = try leaf.amdVcekTcb()
        } catch {
            throw VcekChainError.invalidExtensionValue(reason: "tcb: \(error)")
        }

        guard let family = product.family else {
            throw VcekChainError.unexpectedProduct(name: product.rawValue)
        }

        return VcekChainVerifyResult(
            leafSubjectDN: leaf.subjectDN,
            family: family,
            productName: product,
            leaf: leaf,
            vcekTcb: tcb
        )
    }

    // MARK: - PEM parsing

    static func parseChain(_ pem: String) throws -> [AmdCertificate] {
        do {
            return try AmdCertificate.parseChain(pem: pem)
        } catch AmdCertificateError.malformed(let reason) {
            throw VcekChainError.malformedPem(reason: reason)
        }
    }

    private static func loadPemRoots(
        anchor: String,
        intermediate: String?
    ) throws -> [AmdCertificate] {
        var combined = anchor
        if let intermediate {
            if !combined.hasSuffix("\n") { combined += "\n" }
            combined += intermediate
        }
        do {
            return try parseChain(combined)
        } catch {
            throw VcekChainError.missingRoot(reason: "PEM root bundle: \(error)")
        }
    }

    // MARK: - Path building

    private static func buildPath(
        leaf: AmdCertificate,
        intermediates: [AmdCertificate],
        roots: [AmdCertificate]
    ) throws -> [AmdCertificate] {
        var path: [AmdCertificate] = [leaf]
        var current = leaf
        while true {
            // Anchor against the trusted roots only, never the supplied chain.
            if let anchor = roots.first(where: { $0.subjectDN == current.issuerDN }) {
                path.append(anchor)
                return path
            }
            guard
                let issuer = intermediates.first(where: {
                    $0.subjectDN == current.issuerDN && !path.contains($0)
                })
            else {
                throw VcekChainError.chainBroken(
                    reason: "no trusted issuer for subject DN (\(current.subjectDN.count) bytes)"
                )
            }
            path.append(issuer)
            current = issuer
        }
    }

    // MARK: - Signature verification

    // Last entry is a trusted root; verify each link beneath it.
    private static func verifyPathSignatures(_ path: [AmdCertificate]) throws {
        for i in 0..<(path.count - 1) {
            try verifyOne(subject: path[i], issuer: path[i + 1], label: "chain[\(i)]")
        }
    }

    // MARK: - Standard X.509 constraints

    // RFC 5280-style constraints layered on the pinned-anchor trust model:
    // validity and the CA / key-usage gates apply to everything the anchor
    // vouches for (leaf plus intermediates); path length is honored for every
    // CA including the anchor. The trusted anchor is accepted as configured -
    // its own validity and CA flags are never re-derived from its bytes.
    private static func verifyConstraints(_ path: [AmdCertificate], now: Date) throws {
        guard path.count >= 2 else { return }
        let anchorIndex = path.count - 1

        // The leaf (VCEK) is an end-entity and must not be a CA.
        if path[0].isCertificateAuthority {
            throw VcekChainError.chainBroken(reason: "leaf certificate is a CA")
        }

        // Validity: leaf and intermediates, not the trusted anchor.
        for i in 0..<anchorIndex {
            let cert = path[i]
            if now < cert.notValidBefore {
                throw VcekChainError.chainBroken(reason: "certificate chain[\(i)] is not yet valid")
            }
            if now > cert.notValidAfter {
                throw VcekChainError.chainBroken(reason: "certificate chain[\(i)] has expired")
            }
        }

        // Issuer gates: every intermediate that signs another cert must be a CA
        // permitted to sign certificates.
        for i in 1..<anchorIndex {
            let issuer = path[i]
            guard issuer.isCertificateAuthority else {
                throw VcekChainError.chainBroken(reason: "intermediate chain[\(i)] is not a CA")
            }
            guard issuer.allowsCertificateSigning else {
                throw VcekChainError.chainBroken(
                    reason: "intermediate chain[\(i)] may not sign certificates"
                )
            }
        }

        // Path length: each CA (intermediates and the anchor) must permit the
        // number of intermediate CAs that sit beneath it in the path.
        for i in 1...anchorIndex {
            guard let maxBelow = path[i].maxIntermediateCertificates else { continue }
            if (i - 1) > maxBelow {
                throw VcekChainError.chainBroken(
                    reason: "path length constraint exceeded at chain[\(i)]"
                )
            }
        }
    }

    private static func verifyOne(
        subject: AmdCertificate,
        issuer: AmdCertificate,
        label: String
    ) throws {
        do {
            try subject.verifySignature(issuedBy: issuer)
        } catch AmdCertificateError.unsupportedSignatureAlgorithm(let oid) {
            throw VcekChainError.chainBroken(
                reason: "unsupported signature algorithm \(oid) for \(label)"
            )
        } catch AmdCertificateError.signatureVerificationFailed {
            throw VcekChainError.chainBroken(reason: "signature invalid for \(label)")
        } catch {
            throw VcekChainError.chainBroken(
                reason: "issuer public key for \(label): \(error)"
            )
        }
    }
}
