// KEY_INFO field of the attestation report (AMD spec 56860 v1.58 Table 23,
// offset 0x48). 32-bit little-endian word with three meaningful bits.

import Foundation

/// Encodes the key used to sign the attestation report.
enum SigningKey: UInt8, Sendable, Hashable {
    case vcek = 0
    case vlek = 1
    /// MASK_CHIP_KEY=1 produces an unsigned report with this signing-key code.
    case none = 7
}

struct KeyInfo: Sendable, Hashable {
    /// True when the digest of an author key is present in AUTHOR_KEY_DIGEST.
    let authorKeyEn: Bool
    /// True when the firmware was configured to mask the chip key out of
    /// signatures and key derivations.
    let maskChipKey: Bool
    /// Encoded value of bits 4:2.
    let signingKey: UInt8

    /// Strongly-typed view of `signingKey` when it matches a defined code.
    var signingKeyKind: SigningKey? { SigningKey(rawValue: signingKey) }

    var raw: UInt32

    init(raw: UInt32) {
        self.raw = raw
        self.authorKeyEn = (raw & 0x1) != 0
        self.maskChipKey = (raw & 0x2) != 0
        self.signingKey = UInt8((raw >> 2) & 0x7)
    }
}
