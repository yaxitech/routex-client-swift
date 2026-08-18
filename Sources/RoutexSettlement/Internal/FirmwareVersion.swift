// AMD SEV-SNP firmware version triple (current/committed) from the attestation
// report (AMD spec 56860 Table 23, offsets 0x1E8/0x1EC).

import Foundation

/// Firmware version triple, compared lexicographically (major, minor, build).
package struct FirmwareVersion: Sendable, Hashable, Comparable {
    package let major: UInt8
    package let minor: UInt8
    package let build: UInt8

    package init(major: UInt8, minor: UInt8, build: UInt8) {
        self.major = major
        self.minor = minor
        self.build = build
    }

    package var packed: UInt32 {
        (UInt32(major) << 16) | (UInt32(minor) << 8) | UInt32(build)
    }

    package static func < (lhs: FirmwareVersion, rhs: FirmwareVersion) -> Bool {
        lhs.packed < rhs.packed
    }
}

extension AttestationReport {
    /// Committed firmware version triple from the report (offset 0x1EC..0x1EE).
    var committedVersion: FirmwareVersion {
        FirmwareVersion(major: committedMajor, minor: committedMinor, build: committedBuild)
    }
}
