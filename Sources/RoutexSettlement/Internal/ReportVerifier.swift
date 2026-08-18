// SEV-SNP attestation report verifier. Layered checks, evaluated in order:
//   1. Signature algorithm = ECDSA-P384-SHA384.
//   2. Both ECDSA scalar slots have zero trailing pads.
//   3. Report signature verifies under the VCEK leaf's public key.
//   4. (pinned only) Platform alias-check complete.
//   5. (pinned only) Guest policy disallows debug.
//   6. (pinned only) VMPL ≤ 3.
//   7. (pinned only) Report was signed by a VCEK.
//   8. (pinned only) Committed firmware version ≥ bulletin floor.
//   9. (pinned only) Committed SNP TCB ≥ bulletin floor.
//  10. (pinned only) `LAUNCH_MIT_VECTOR` and `CURRENT_MIT_VECTOR` cover required bits.
//  11. (pinned only) Microcode ≥ bulletin floor for (family, model, step) or fallback.
//  12. Reported TCB SPLs match the VCEK certificate.

import Crypto
import Foundation
@_spi(Interop) import RoutexCrypto

enum ReportVerificationError: Error, Sendable, Equatable {
    case unsupportedSignatureAlgorithm(code: UInt32)
    case unexpectedSignatureBits
    case badSignature(reason: String)
    case aliasCheckMissing
    case debugEnabled
    case migrationAgentAllowed
    case vmplTooHigh(vmpl: UInt32)
    case signingKeyNotVcek(rawCode: UInt8)
    case unknownCPUFamily(reason: String)
    case tcbMismatch(field: String, expected: UInt8, actual: UInt8)
    case committedVersionBelow(required: FirmwareVersion, actual: FirmwareVersion)
    case committedSnpBelow(required: UInt8, actual: UInt8)
    case microcodeBelow(required: UInt8, actual: UInt8)
    case mitVectorBelow(field: String, required: UInt64, actual: UInt64?)
}

enum ReportVerifier {
    /// Verify a parsed attestation report against a verified VCEK chain.
    static func verify(
        report: AttestationReport,
        chain: VcekChainVerifyResult
    ) throws {
        // Algorithm + signature shape + cryptographic verify.
        guard report.signatureAlgorithm == .ecdsaP384Sha384 else {
            throw ReportVerificationError.unsupportedSignatureAlgorithm(code: report.signatureAlgo)
        }
        guard report.signatureZeroPaddingValid else {
            throw ReportVerificationError.unexpectedSignatureBits
        }
        try verifyReportSignature(report: report, chain: chain)

        // Policy gates.
        if !report.platformInfo.aliasCheckComplete {
            throw ReportVerificationError.aliasCheckMissing
        }
        if report.policy.debugAllowed {
            throw ReportVerificationError.debugEnabled
        }
        if report.policy.migrateMaAllowed {
            throw ReportVerificationError.migrationAgentAllowed
        }
        if report.vmpl > 3 {
            throw ReportVerificationError.vmplTooHigh(vmpl: report.vmpl)
        }
        if report.keyInfo.signingKeyKind != .vcek {
            throw ReportVerificationError.signingKeyNotVcek(rawCode: report.keyInfo.signingKey)
        }

        let perProduct = Requirements.forFamily(chain.family)

        // Firmware floors.
        if report.committedVersion < perProduct.minCommittedVersion {
            throw ReportVerificationError.committedVersionBelow(
                required: perProduct.minCommittedVersion,
                actual: report.committedVersion
            )
        }
        let committedTcb = try report.committedTcb()
        if committedTcb.snp < perProduct.minCommittedTcbSnp {
            throw ReportVerificationError.committedSnpBelow(
                required: perProduct.minCommittedTcbSnp,
                actual: committedTcb.snp
            )
        }

        try verifyMitVector(
            field: "current",
            required: perProduct.minMitVector,
            actual: report.version >= 5 ? report.currentMitVector : nil
        )
        try verifyMitVector(
            field: "launch",
            required: perProduct.minMitVector,
            actual: report.version >= 5 ? report.launchMitVector : nil
        )

        let minMicrocode: UInt8
        if report.version >= 3 {
            // v3+ reports expose CPUID model/stepping; look up the per-tuple floor.
            guard
                let value = perProduct.microcode.floor(
                    model: report.cpuid.model,
                    stepping: report.cpuid.step
                )
            else {
                throw ReportVerificationError.unknownCPUFamily(
                    reason: "no microcode requirement for family=\(chain.family) "
                        + "model=\(report.cpuid.model) step=\(report.cpuid.step)"
                )
            }
            minMicrocode = value
        } else {
            // Pre-v3 reports zero CPUID model/stepping.
            minMicrocode = perProduct.microcode.strictestFloor
        }
        if committedTcb.microcode < minMicrocode {
            throw ReportVerificationError.microcodeBelow(
                required: minMicrocode,
                actual: committedTcb.microcode
            )
        }

        try verifyTcbAgainstVcek(
            reported: report.reportedTcb(),
            vcek: chain.vcekTcb
        )
    }

    // MARK: - Internals

    private static func verifyReportSignature(
        report: AttestationReport,
        chain: VcekChainVerifyResult
    ) throws {
        let leafKey: P384.Signing.PublicKey
        do {
            leafKey = try chain.leaf.p384PublicKey()
        } catch {
            throw ReportVerificationError.badSignature(reason: "leaf P-384 key: \(error)")
        }
        // Little-endian on the wire (AMD spec); ECDSA verify wants r||s big-endian.
        let rBE = Data(report.signatureRLittleEndian.reversed())
        let sBE = Data(report.signatureSLittleEndian.reversed())
        guard rBE.count == 48, sBE.count == 48 else {
            throw ReportVerificationError.badSignature(reason: "scalar size")
        }
        let signature: P384.Signing.ECDSASignature
        do {
            signature = try P384.Signing.ECDSASignature(rawRepresentation: rBE + sBE)
        } catch {
            throw ReportVerificationError.badSignature(reason: "signature decode: \(error)")
        }
        let digest = SHA384.hash(data: report.tbsBytes)
        guard leafKey.isValidSignature(signature, for: digest) else {
            throw ReportVerificationError.badSignature(reason: "verify failed")
        }
    }

    private static func verifyMitVector(
        field: String,
        required: UInt64,
        actual: UInt64?
    ) throws {
        if required == 0 { return }
        guard let actual else {
            throw ReportVerificationError.mitVectorBelow(
                field: field,
                required: required,
                actual: nil
            )
        }
        if (actual & required) != required {
            throw ReportVerificationError.mitVectorBelow(
                field: field,
                required: required,
                actual: actual
            )
        }
    }

    private static func verifyTcbAgainstVcek(reported: TcbVersion, vcek: VcekTcb) throws {
        if reported.bootloader != vcek.bootloader {
            throw ReportVerificationError.tcbMismatch(
                field: "bootloader",
                expected: vcek.bootloader,
                actual: reported.bootloader
            )
        }
        if reported.tee != vcek.tee {
            throw ReportVerificationError.tcbMismatch(
                field: "tee",
                expected: vcek.tee,
                actual: reported.tee
            )
        }
        if reported.snp != vcek.snp {
            throw ReportVerificationError.tcbMismatch(
                field: "snp",
                expected: vcek.snp,
                actual: reported.snp
            )
        }
        if reported.microcode != vcek.microcode {
            throw ReportVerificationError.tcbMismatch(
                field: "microcode",
                expected: vcek.microcode,
                actual: reported.microcode
            )
        }
        let reportedFmc = reported.fmc ?? 0
        let vcekFmc = vcek.fmc ?? 0
        if reportedFmc != vcekFmc {
            throw ReportVerificationError.tcbMismatch(
                field: "fmc",
                expected: vcekFmc,
                actual: reportedFmc
            )
        }
    }
}
