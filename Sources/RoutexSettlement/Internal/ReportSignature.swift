// Typed view over the 512-byte SIGNATURE field of an attestation report
// (AMD spec 56860 Table 141). For ECDSA-P384-SHA384 the layout is
// `R[0..48] ‖ pad[48..72] ‖ S[72..120] ‖ pad[120..144] ‖ reserved[144..512]`,
// with R and S in little-endian.

import Foundation

enum SignatureAlgorithm: Equatable, Sendable {
    case ecdsaP384Sha384
    case unknown(UInt32)

    static func fromCode(_ code: UInt32) -> SignatureAlgorithm {
        switch code {
        case 1: return .ecdsaP384Sha384
        case _: return .unknown(code)
        }
    }
}

extension AttestationReport {
    var signatureAlgorithm: SignatureAlgorithm {
        SignatureAlgorithm.fromCode(signatureAlgo)
    }

    /// 48-byte little-endian R scalar of the ECDSA signature.
    var signatureRLittleEndian: Data {
        let bytes = Array(signatureBytes)
        return Data(bytes[0..<48])
    }
    /// 48-byte little-endian S scalar of the ECDSA signature.
    var signatureSLittleEndian: Data {
        let bytes = Array(signatureBytes)
        return Data(bytes[72..<120])
    }

    /// True when the 24-byte trailing pads of both ECDSA scalar slots are zero,
    /// as required for an ECDSA-P384-SHA384 signature in a 72-byte slot.
    var signatureZeroPaddingValid: Bool {
        guard signatureBytes.count >= 144 else { return false }
        let bytes = Array(signatureBytes)
        for i in 48..<72 {
            if bytes[i] != 0 { return false }
            if bytes[72 + i] != 0 { return false }
        }
        return true
    }
}
