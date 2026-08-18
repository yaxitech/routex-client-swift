// AMD SEV-SNP attestation report parser (AMD spec 56860 v1.58 Table 23).
// Supports report versions 2, 3, and 5. Versions 3+ add the CPUID
// family/model/step triple at offsets 0x188..0x18A; version 5 adds the
// `LAUNCH_MIT_VECTOR` and `CURRENT_MIT_VECTOR` fields at 0x1F8 and 0x200.

import Foundation

/// Total binary length of an attestation report.
let attestationReportLength: Int = 1184

/// Length of the report bytes covered by the ECDSA signature (everything
/// before the signature field itself), per spec Table 23 footer.
let attestationReportSignedLength: Int = 0x2A0

/// One AMD SEV-SNP attestation report.
struct AttestationReport: Sendable, Hashable {
    let version: UInt32
    let guestSvn: UInt32
    let policy: GuestPolicy
    let familyID: Data  // 16 bytes
    let imageID: Data  // 16 bytes
    let vmpl: UInt32
    let signatureAlgo: UInt32
    let currentTcbBytes: Data  // 8 bytes; layout depends on CPU family
    let platformInfo: PlatformInfo
    let keyInfo: KeyInfo
    let reportData: Data  // 64 bytes
    let measurement: Data  // 48 bytes (SHA-384 launch measurement)
    let hostData: Data  // 32 bytes
    let idKeyDigest: Data  // 48 bytes
    let authorKeyDigest: Data  // 48 bytes
    let reportID: Data  // 32 bytes
    let reportIDMA: Data  // 32 bytes
    let reportedTcbBytes: Data  // 8 bytes
    let cpuid: CPUID  // version >= 3, else zero
    let chipID: Data  // 64 bytes
    let committedTcbBytes: Data  // 8 bytes
    let currentBuild: UInt8
    let currentMinor: UInt8
    let currentMajor: UInt8
    let committedBuild: UInt8
    let committedMinor: UInt8
    let committedMajor: UInt8
    let launchTcbBytes: Data  // 8 bytes
    let launchMitVector: UInt64  // version >= 5, else 0
    let currentMitVector: UInt64  // version >= 5, else 0

    /// Whether the TCB_VERSION fields use the Turin (Table 3) layout, derived
    /// from the report itself rather than the VCEK product.
    let turinLikeLayout: Bool

    /// Bytes 0..0x2A0 of the report; exactly what the ECDSA signature covers.
    let tbsBytes: Data
    /// Raw 512-byte SIGNATURE field (Table 141 layout).
    let signatureBytes: Data
    /// The full underlying report bytes, retained so callers can hash them.
    let raw: Data

    init(_ raw: Data) throws {
        guard raw.count == attestationReportLength else {
            throw AttestationReportError.invalidLength(raw.count)
        }
        let r = ByteReader(raw)

        self.version = try r.u32LE(at: 0x00)
        self.guestSvn = try r.u32LE(at: 0x04)
        self.policy = GuestPolicy(raw: try r.u64LE(at: 0x08))
        self.familyID = try r.bytes(at: 0x10, length: 16)
        self.imageID = try r.bytes(at: 0x20, length: 16)
        self.vmpl = try r.u32LE(at: 0x30)
        self.signatureAlgo = try r.u32LE(at: 0x34)
        self.currentTcbBytes = try r.bytes(at: 0x38, length: 8)
        self.platformInfo = PlatformInfo(raw: try r.u64LE(at: 0x40))
        self.keyInfo = KeyInfo(raw: try r.u32LE(at: 0x48))
        self.reportData = try r.bytes(at: 0x50, length: 64)
        self.measurement = try r.bytes(at: 0x90, length: 48)
        self.hostData = try r.bytes(at: 0xC0, length: 32)
        self.idKeyDigest = try r.bytes(at: 0xE0, length: 48)
        self.authorKeyDigest = try r.bytes(at: 0x110, length: 48)
        self.reportID = try r.bytes(at: 0x140, length: 32)
        self.reportIDMA = try r.bytes(at: 0x160, length: 32)
        self.reportedTcbBytes = try r.bytes(at: 0x180, length: 8)

        // Versions 1 & 2 zeroed the CPUID bytes at 0x188..0x18A. Versions 3+
        // populate them. We always read the bytes; CPUFamily.from(...) returns
        // `nil` when zero so callers can fall back to reportedTcb-driven
        // inference if needed.
        self.cpuid = CPUID(
            family: try r.u8(at: 0x188),
            model: try r.u8(at: 0x189),
            step: try r.u8(at: 0x18A)
        )
        // bytes 0x18B..0x19F reserved

        self.chipID = try r.bytes(at: 0x1A0, length: 64)
        self.committedTcbBytes = try r.bytes(at: 0x1E0, length: 8)
        self.currentBuild = try r.u8(at: 0x1E8)
        self.currentMinor = try r.u8(at: 0x1E9)
        self.currentMajor = try r.u8(at: 0x1EA)
        // 0x1EB reserved
        self.committedBuild = try r.u8(at: 0x1EC)
        self.committedMinor = try r.u8(at: 0x1ED)
        self.committedMajor = try r.u8(at: 0x1EE)
        // 0x1EF reserved
        self.launchTcbBytes = try r.bytes(at: 0x1F0, length: 8)

        // v5+ mitigation vectors. Earlier reports have zeros here per spec.
        if self.version >= 5 {
            self.launchMitVector = try r.u64LE(at: 0x1F8)
            self.currentMitVector = try r.u64LE(at: 0x200)
        } else {
            self.launchMitVector = 0
            self.currentMitVector = 0
        }

        self.tbsBytes = try r.bytes(at: 0, length: attestationReportSignedLength)
        self.signatureBytes = try r.bytes(at: attestationReportSignedLength, length: 512)
        self.raw = raw

        self.turinLikeLayout = try Self.isTurinLikeLayout(
            version: self.version,
            cpuid: self.cpuid,
            chipID: self.chipID
        )
    }

    /// AMD family `0x19` (Milan/Genoa) uses the legacy TCB_VERSION layout;
    /// Turin/Venice and anything newer use the Turin layout. For v<3 reports
    /// the CPUID fields are absent, so fall back to a CHIP_ID heuristic: a
    /// fully-populated CHIP_ID is Milan/Genoa, an 8-byte-only one is Turin.
    private static func isTurinLikeLayout(
        version: UInt32,
        cpuid: CPUID,
        chipID: Data
    ) throws
        -> Bool
    {
        let milanGenoaFamily: UInt8 = 0x19
        if version >= 3 {
            return cpuid.family != milanGenoaFamily
        }
        if chipID.allSatisfy({ $0 == 0 }) {
            throw AttestationReportError.maskedChipIDInLegacyReport
        }
        return chipID.dropFirst(8).allSatisfy { $0 == 0 }
    }

    /// Convenience: decoded `currentTcb` using the report's TCB layout.
    func currentTcb() throws -> TcbVersion {
        try TcbVersion(bytes: currentTcbBytes, turinLike: turinLikeLayout)
    }

    /// Convenience: decoded `reportedTcb` using the report's TCB layout.
    func reportedTcb() throws -> TcbVersion {
        try TcbVersion(bytes: reportedTcbBytes, turinLike: turinLikeLayout)
    }

    /// Convenience: decoded `committedTcb` using the report's TCB layout.
    func committedTcb() throws -> TcbVersion {
        try TcbVersion(bytes: committedTcbBytes, turinLike: turinLikeLayout)
    }

    /// Convenience: decoded `launchTcb` using the report's TCB layout.
    func launchTcb() throws -> TcbVersion {
        try TcbVersion(bytes: launchTcbBytes, turinLike: turinLikeLayout)
    }
}

enum AttestationReportError: Error, Sendable, Equatable {
    case invalidLength(Int)
    case maskedChipIDInLegacyReport
}
