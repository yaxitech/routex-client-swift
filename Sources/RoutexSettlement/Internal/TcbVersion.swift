// TCB_VERSION decoding per AMD spec 56860 v1.58, Tables 3 (Turin) and 4
// (Genoa/Milan).
//
// On the wire the field is a little-endian 64-bit integer; the byte at
// offset 0 corresponds to bits 7:0 of the 64-bit value, the byte at offset 7
// to bits 63:56. The same little-endian byte interpretation is used by the
// VCEK certificate's TCB SPL extensions, so the comparison between
// `report.reportedTcb` and the VCEK extensions is byte-wise.

import Foundation

/// Decoded TCB_VERSION. Field layout depends on the CPU family.
struct TcbVersion: Sendable, Hashable {
    let bootloader: UInt8
    let tee: UInt8
    let snp: UInt8
    let microcode: UInt8
    /// FMC component, present only in Turin reports. `nil` for Milan/Genoa.
    let fmc: UInt8?

    /// Parse an 8-byte LE TCB_VERSION buffer. The layout is selected by
    /// `turinLike`, derived from the report itself (see
    /// `AttestationReport.turinLikeLayout`), not the VCEK product.
    /// AMD spec 56860 v1.58:
    /// - Turin-like (Table 3): byte0=FMC, byte1=BOOT_LOADER, byte2=TEE, byte3=SNP, bytes4..6=reserved, byte7=MICROCODE.
    /// - Genoa/Milan (Table 4): byte0=BOOT_LOADER, byte1=TEE, bytes2..5=reserved, byte6=SNP, byte7=MICROCODE.
    init(bytes: Data, turinLike: Bool) throws {
        guard bytes.count == 8 else {
            throw TcbVersionError.invalidLength(bytes.count)
        }
        let s = bytes.startIndex
        if turinLike {
            self.fmc = bytes[s + 0]
            self.bootloader = bytes[s + 1]
            self.tee = bytes[s + 2]
            self.snp = bytes[s + 3]
            // bytes 4..6 reserved
            self.microcode = bytes[s + 7]
        } else {
            self.bootloader = bytes[s + 0]
            self.tee = bytes[s + 1]
            // bytes 2..5 reserved
            self.snp = bytes[s + 6]
            self.microcode = bytes[s + 7]
            self.fmc = nil
        }
    }
}

enum TcbVersionError: Error, Sendable, Equatable {
    case invalidLength(Int)
}
