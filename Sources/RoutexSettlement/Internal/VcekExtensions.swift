// AMD VCEK certificate extension OIDs and decoding helpers (AMD doc 57230 §3.1
// Tables 10 + 11). VCEK certs carry a product label and per-component TCB
// SPLs; the chain validator reads them to pick the right `CPUFamily` and to
// verify the report's `REPORTED_TCB`.

import Foundation
@_spi(Interop) import RoutexCrypto
internal import SwiftASN1

/// AMD VCEK extension OIDs (AMD doc 57230 §3.1).
enum VcekExtensionOID {
    static let structVersion: ASN1ObjectIdentifier = "1.3.6.1.4.1.3704.1.1"
    static let productName: ASN1ObjectIdentifier = "1.3.6.1.4.1.3704.1.2"
    static let blSPL: ASN1ObjectIdentifier = "1.3.6.1.4.1.3704.1.3.1"
    static let teeSPL: ASN1ObjectIdentifier = "1.3.6.1.4.1.3704.1.3.2"
    static let snpSPL: ASN1ObjectIdentifier = "1.3.6.1.4.1.3704.1.3.3"
    static let ucodeSPL: ASN1ObjectIdentifier = "1.3.6.1.4.1.3704.1.3.8"
    static let fmcSPL: ASN1ObjectIdentifier = "1.3.6.1.4.1.3704.1.3.9"
    static let hwID: ASN1ObjectIdentifier = "1.3.6.1.4.1.3704.1.4"
}

/// AMD VCEK product label, parsed from the `productName` extension.
enum VcekProduct: Sendable, Hashable {
    case milanB0
    case genoaA0
    case genoaB0
    case turinA0
    case turinB0
    case other(String)

    static func from(_ wireValue: String) -> VcekProduct {
        switch wireValue {
        case "Milan-B0": return .milanB0
        case "Genoa-A0": return .genoaA0
        case "Genoa-B0": return .genoaB0
        case "Turin-A0": return .turinA0
        case "Turin-B0": return .turinB0
        default: return .other(wireValue)
        }
    }

    /// CPU family inferred from the product label.
    var family: CPUFamily? {
        let base = String(rawValue.split(separator: "-").first ?? Substring(rawValue))
            .trimmingCharacters(in: .whitespaces)
        switch base {
        case "Milan": return .milan
        case "Genoa", "Siena", "Bergamo": return .genoa
        case "Turin": return .turin
        default: return nil
        }
    }

    var rawValue: String {
        switch self {
        case .milanB0: return "Milan-B0"
        case .genoaA0: return "Genoa-A0"
        case .genoaB0: return "Genoa-B0"
        case .turinA0: return "Turin-A0"
        case .turinB0: return "Turin-B0"
        case .other(let s): return s
        }
    }
}

enum VcekExtensionError: Error, Sendable, Equatable {
    case missingExtension(oid: String)
    case malformedExtension(reason: String)
}

extension AmdCertificate {
    /// Decode the AMD `productName` extension as an IA5String. Throws
    /// `VcekExtensionError.missingExtension` when absent.
    func amdProductName() throws -> VcekProduct {
        let name: String?
        do {
            name = try ia5StringExtension(VcekExtensionOID.productName)
        } catch {
            throw VcekExtensionError.malformedExtension(reason: "productName: \(error)")
        }
        guard let name else {
            throw VcekExtensionError.missingExtension(oid: "1.3.6.1.4.1.3704.1.2")
        }
        return VcekProduct.from(name)
    }

    /// Decode an AMD TCB SPL extension as a `UInt8`. SPLs are always
    /// single-byte INTEGERs. `optional` returns `nil` instead of throwing
    /// when the extension is absent.
    func amdSPL(_ oid: ASN1ObjectIdentifier, optional: Bool = false) throws -> UInt8? {
        let value: Int?
        do {
            value = try integerExtension(oid)
        } catch {
            throw VcekExtensionError.malformedExtension(reason: "SPL \(oid): \(error)")
        }
        guard let value else {
            if optional { return nil }
            throw VcekExtensionError.missingExtension(oid: String(describing: oid))
        }
        guard (0...255).contains(value) else {
            throw VcekExtensionError.malformedExtension(
                reason: "SPL out of range for \(oid): \(value)"
            )
        }
        return UInt8(value)
    }
}

/// TCB SPLs decoded from a VCEK certificate's AMD extensions.
struct VcekTcb: Sendable, Hashable {
    let bootloader: UInt8
    let tee: UInt8
    let snp: UInt8
    let microcode: UInt8
    /// Present only on Turin VCEK certs (Family 1Ah).
    let fmc: UInt8?
}

extension AmdCertificate {
    /// Read all AMD-specific TCB extensions out of a VCEK certificate.
    func amdVcekTcb() throws -> VcekTcb {
        VcekTcb(
            bootloader: try amdSPL(VcekExtensionOID.blSPL)!,
            tee: try amdSPL(VcekExtensionOID.teeSPL)!,
            snp: try amdSPL(VcekExtensionOID.snpSPL)!,
            microcode: try amdSPL(VcekExtensionOID.ucodeSPL)!,
            fmc: try amdSPL(VcekExtensionOID.fmcSPL, optional: true)
        )
    }
}
