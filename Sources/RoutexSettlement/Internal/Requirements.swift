// Bulletin-pinned verification floors: per-CPU-family minimums for committed
// firmware version, committed SNP TCB level, microcode (per CPU model /
// stepping), and the bitmask of mitigation bits required in the v5+
// `LAUNCH_MIT_VECTOR` and `CURRENT_MIT_VECTOR` fields.

import Foundation

/// One row of a bulletin's per-CPU microcode table.
struct MicrocodeFloor: Sendable, Hashable {
    let model: UInt8
    let stepping: UInt8
    let floor: UInt8
}

extension [MicrocodeFloor] {
    /// Floor for `model` / `stepping`, or `nil` when the pair is not on the
    /// bulletin's approved list. Callers must treat that as a failure.
    func floor(model: UInt8, stepping: UInt8) -> UInt8? {
        first { $0.model == model && $0.stepping == stepping }?.floor
    }

    /// Floor for reports that do not expose CPUID model / stepping. The
    /// strictest entry, so it cannot accept what a lookup would reject.
    var strictestFloor: UInt8 { map(\.floor).max() ?? .max }
}

/// Per-CPU-family verification floor for one bulletin.
struct PerProduct: Sendable, Hashable {
    let minCommittedVersion: FirmwareVersion
    let minCommittedTcbSnp: UInt8
    /// Microcode floors per CPU model / stepping, as published.
    let microcode: [MicrocodeFloor]
    /// Bitmask: every set bit must also be set in both
    /// `currentMitVector` and `launchMitVector`. Zero disables the check.
    let minMitVector: UInt64
}

/// AMD-SB-3023 (https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3023.html),
/// the bulletin this client pins.
enum Requirements {
    /// Per-family floor.
    static func forFamily(_ family: CPUFamily) -> PerProduct {
        sb3023Floor(family)
    }

    // MARK: - SB-3020

    private static func sb3020Floor(_ family: CPUFamily) -> PerProduct {
        switch family {
        case .milan:
            return PerProduct(
                minCommittedVersion: FirmwareVersion(major: 0x1, minor: 0x37, build: 0x23),
                minCommittedTcbSnp: 0x1B,
                microcode: [
                    MicrocodeFloor(model: 0x01, stepping: 0x01, floor: 0xDE),
                    MicrocodeFloor(model: 0x01, stepping: 0x02, floor: 0x45),
                ],
                minMitVector: 1 << 1
            )
        case .genoa:
            return PerProduct(
                minCommittedVersion: FirmwareVersion(major: 0x1, minor: 0x37, build: 0x31),
                minCommittedTcbSnp: 0x1B,
                microcode: [
                    MicrocodeFloor(model: 0x11, stepping: 0x01, floor: 0x56),
                    MicrocodeFloor(model: 0x11, stepping: 0x02, floor: 0x51),
                    MicrocodeFloor(model: 0xA0, stepping: 0x02, floor: 0x1B),
                ],
                minMitVector: 1 << 1
            )
        case .turin:
            return PerProduct(
                minCommittedVersion: FirmwareVersion(major: 0x1, minor: 0x37, build: 0x41),
                minCommittedTcbSnp: 0x04,
                microcode: [
                    MicrocodeFloor(model: 0x02, stepping: 0x01, floor: 0x50),
                    MicrocodeFloor(model: 0x11, stepping: 0x00, floor: 0x4D),
                ],
                minMitVector: 1 << 0
            )
        }
    }

    // MARK: - SB-3023 (strict superset of SB-3020)

    private static func sb3023Floor(_ family: CPUFamily) -> PerProduct {
        let base = sb3020Floor(family)
        switch family {
        case .milan:
            return PerProduct(
                minCommittedVersion: base.minCommittedVersion,
                minCommittedTcbSnp: base.minCommittedTcbSnp,
                microcode: [
                    MicrocodeFloor(model: 0x01, stepping: 0x01, floor: 0xDE),
                    MicrocodeFloor(model: 0x01, stepping: 0x02, floor: 0x47),
                ],
                minMitVector: base.minMitVector
            )
        case .genoa:
            return PerProduct(
                minCommittedVersion: base.minCommittedVersion,
                minCommittedTcbSnp: base.minCommittedTcbSnp,
                microcode: base.microcode,
                minMitVector: (1 << 0) | (1 << 1)
            )
        case .turin:
            return PerProduct(
                minCommittedVersion: base.minCommittedVersion,
                minCommittedTcbSnp: base.minCommittedTcbSnp,
                microcode: [
                    MicrocodeFloor(model: 0x02, stepping: 0x01, floor: 0x51),
                    MicrocodeFloor(model: 0x11, stepping: 0x00, floor: 0x4E),
                ],
                minMitVector: (1 << 0) | (1 << 1) | (1 << 2) | (1 << 4) | (1 << 5)
            )
        }
    }
}
