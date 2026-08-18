// CPU family detection from the attestation report's `CPUID_FAM_ID`,
// `CPUID_MOD_ID`, and `CPUID_STEP` fields.
//
// AMD product → CPUID identifier mapping is published in the routex-client
// `sev_constants.json` fixture and documented in the AMD SB-3020 advisory.
// We embed the same mapping here so that:
//
//   - The CPU family selects the right `TcbVersion` byte layout (Turin vs.
//     Genoa/Milan; see AMD spec 56860 Tables 3 and 4).
//   - The VCEK chain validator chooses the correct AMD root certificate.

import Foundation

/// AMD SEV-SNP CPU family of interest to the routex protocol.
package enum CPUFamily: String, Sendable, Hashable, CaseIterable {
    case milan
    case genoa
    case turin

    /// Specific product label within a family (Genoa vs. Genoa-X vs.
    /// Bergamo/Siena, etc.). Exposed for diagnostics; not load-bearing.
    package enum Product: String, Sendable, Hashable {
        case milan = "Milan"
        case milanX = "Milan-X"
        case genoa = "Genoa"
        case genoaX = "Genoa-X"
        case bergamoSiena = "Bergamo/Siena"
        case turinClassic = "Turin Classic"
        case turinDense = "Turin Dense"
    }
}

/// AMD CPUID-derived identifier from the attestation report.
package struct CPUID: Sendable, Hashable {
    package let family: UInt8
    package let model: UInt8
    package let step: UInt8

    package init(family: UInt8, model: UInt8, step: UInt8) {
        self.family = family
        self.model = model
        self.step = step
    }
}

extension CPUFamily {
    /// Best-effort family detection from a CPUID triple. Returns `nil` for
    /// unknown processors (e.g. report version 2 from "OAK" testbeds where
    /// the CPUID fields are zero-filled).
    static func from(cpuid: CPUID) -> Self? {
        product(from: cpuid)?.0
    }

    /// Both family and product label, for diagnostics and validation.
    static func product(from cpuid: CPUID) -> (CPUFamily, Product)? {
        // Mapping mirrors `sev_constants.json :: productCpuFamilies`.
        switch (cpuid.family, cpuid.model, cpuid.step) {
        case (25, 1, 1): return (.milan, .milan)
        case (25, 1, 2): return (.milan, .milanX)
        case (25, 17, 1): return (.genoa, .genoa)
        case (25, 17, 2): return (.genoa, .genoaX)
        case (25, 160, 2): return (.genoa, .bergamoSiena)
        case (26, 2, 1): return (.turin, .turinClassic)
        case (26, 17, 0): return (.turin, .turinDense)
        default: return nil
        }
    }
}
