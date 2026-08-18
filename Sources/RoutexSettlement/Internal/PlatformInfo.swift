// PLATFORM_INFO field of the attestation report (AMD spec 56860 v1.58
// Table 24). Decoded from a little-endian 64-bit value at report offset 0x40.

import Foundation

struct PlatformInfo: Sendable, Hashable {
    let smtEnabled: Bool
    let tsmeEnabled: Bool
    let eccEnabled: Bool
    let raplDisabled: Bool
    let ciphertextHidingEnabled: Bool
    /// Indicates that the CVE-2024-21944 alias-detection mitigation has run
    /// since the last reset and detected no aliasing. Required for SB-3020.
    let aliasCheckComplete: Bool
    let tioEnabled: Bool

    /// Raw 64-bit value, retained for forward-compatibility with future bits.
    let raw: UInt64

    init(raw: UInt64) {
        self.raw = raw
        self.smtEnabled = (raw & (1 << 0)) != 0
        self.tsmeEnabled = (raw & (1 << 1)) != 0
        self.eccEnabled = (raw & (1 << 2)) != 0
        self.raplDisabled = (raw & (1 << 3)) != 0
        self.ciphertextHidingEnabled = (raw & (1 << 4)) != 0
        self.aliasCheckComplete = (raw & (1 << 5)) != 0
        // bit 6 reserved
        self.tioEnabled = (raw & (1 << 7)) != 0
    }
}
