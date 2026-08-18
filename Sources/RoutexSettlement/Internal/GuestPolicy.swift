// POLICY field of the attestation report (AMD spec 56860 v1.58 Table 9).
// Decoded from a little-endian 64-bit value at report offset 0x08.

import Foundation

struct GuestPolicy: Sendable, Hashable {
    let abiMinor: UInt8
    let abiMajor: UInt8
    let smtAllowed: Bool
    /// Per AMD spec, bit 17 must always be set to 1.
    let reservedMustBe1: Bool
    let migrateMaAllowed: Bool
    let debugAllowed: Bool
    let singleSocketRequired: Bool
    let cxlAllowed: Bool
    let memAes256Xts: Bool
    let raplDis: Bool
    let ciphertextHiding: Bool
    let pageSwapDisabled: Bool

    let raw: UInt64

    init(raw: UInt64) {
        self.raw = raw
        self.abiMinor = UInt8(raw & 0xff)
        self.abiMajor = UInt8((raw >> 8) & 0xff)
        self.smtAllowed = (raw & (1 << 16)) != 0
        self.reservedMustBe1 = (raw & (1 << 17)) != 0
        self.migrateMaAllowed = (raw & (1 << 18)) != 0
        self.debugAllowed = (raw & (1 << 19)) != 0
        self.singleSocketRequired = (raw & (1 << 20)) != 0
        self.cxlAllowed = (raw & (1 << 21)) != 0
        self.memAes256Xts = (raw & (1 << 22)) != 0
        self.raplDis = (raw & (1 << 23)) != 0
        self.ciphertextHiding = (raw & (1 << 24)) != 0
        self.pageSwapDisabled = (raw & (1 << 25)) != 0
    }
}
