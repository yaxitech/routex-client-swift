import Foundation
import Testing

@testable import RoutexSettlement

/// Forward-compatibility for the TCB_VERSION layout selection. The layout is
/// derived from the report itself (CPU_FAM_ID for v>=3, a CHIP_ID heuristic
/// for v<3) rather than the VCEK product, so an unknown future family parses
/// with the Turin layout and a masked legacy CHIP_ID is rejected.
@Suite("Attestation report TCB layout")
struct AttestationReportLayoutTests {
    // A real v2 Milan report (no CPUID fields), shared with the other clients'
    // parser tests.
    private static let milanV2Base64 =
        "AgAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAADAAAAAAAIcwEAAAAAAAAAAAAAAAAAAADUR7VdGXSRv+Fc8pj53pmGt6fEviRotPbi1Ttx18ZFgQsPLN/KAEBDO+Bj/BqCk/Dz+Nrnt5/ss9HNgr1qk+v9eh5cJmwBCNvJu5T6kmlRMglAkV0Kr7QkZL2ItXnqFY0+Gg3DmyxgvZW5xIDNgYQfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACSs7R9WfCioQp0xWeIaKgCOM9ZPAGoLzz/uHjpBMKNW///////////////////////////////////////////AwAAAAAACHMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADUlVTscX9OWw/msUO88EBb164wRyft9GYD8qdq72o6vBXXrzjbdXA5Ap8O+s/QjiRDJIhHOMcrCC4vh6RNVB62AwAAAAAACHMENAEABDQBAAMAAAAAAAhzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYatPEapmGZdiXyM99CpK1URA7repbqY94XDLwpw3wAXLVAVIgex9K+5WmwLQf4JyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIJ1+ub6Rmh0Lrx1X/m6/6rvFO3eMbpd+QLFcqTG7bUTFq54wz9xzRstBrAg7kL9JAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    private static func fixture() -> Data { Data(base64Encoded: milanV2Base64)! }

    private static func patched(_ offset: Int, _ replacement: [UInt8]) -> Data {
        var bytes = fixture()
        bytes.replaceSubrange(offset..<(offset + replacement.count), with: replacement)
        return bytes
    }

    @Test("v<3 report with a full CHIP_ID uses the legacy (Milan/Genoa) layout")
    func legacyChipIdNotTurinLike() throws {
        let report = try AttestationReport(Self.fixture())
        #expect(!report.turinLikeLayout)
    }

    @Test("v<3 report with an 8-byte CHIP_ID selects the Turin layout")
    func shortChipIdIsTurinLike() throws {
        // Zero everything past the first 8 CHIP_ID bytes (0x1A0).
        let report = try AttestationReport(
            Self.patched(0x1A0 + 8, [UInt8](repeating: 0, count: 56))
        )
        #expect(report.turinLikeLayout)
    }

    @Test("unknown CPUID_FAM_ID (v>=3) selects the Turin layout")
    func unknownFamilyIsTurinLike() throws {
        var bytes = Self.patched(0x000, [5, 0, 0, 0])  // version = 5
        bytes[0x188] = 0xFF  // CPUID_FAM_ID
        let report = try AttestationReport(bytes)
        #expect(report.turinLikeLayout)
        #expect(try report.currentTcb().fmc != nil, "Turin layout exposes an FMC component")
    }

    @Test("v<3 report with a fully masked CHIP_ID is rejected")
    func maskedChipIdRejected() {
        #expect(throws: AttestationReportError.maskedChipIDInLegacyReport) {
            _ = try AttestationReport(Self.patched(0x1A0, [UInt8](repeating: 0, count: 64)))
        }
    }
}
