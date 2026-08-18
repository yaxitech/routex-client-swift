// System-version Ed25519 verifier. The settlement response carries a
// `SystemVersionEntry` that names the running stack and pins its launch
// measurement; the entry is signed with one of the trusted Ed25519 keys.
//
// Signed message layout (UTF-8 concatenation, no JSON):
//   kind ‖ generation_decimal ‖ createdAt_normalized(Z→+00:00) ‖ ref ‖ measurement_bytes

import Crypto
import Foundation
import RoutexModels

enum SystemVersionDecodeError: Error, Sendable, Equatable {
    case unknownKeyID(String)
    case invalidSignature(reason: String)
    case malformedInput(reason: String)
}

enum SystemVersionVerifier {
    /// Verify the entry's Ed25519 signature against `verifyingKeys` (key id
    /// → 32-byte raw public key). Returns the launch measurement on success.
    @discardableResult
    static func verify(
        entry: SystemVersionEntry,
        verifyingKeys: [String: Data]
    ) throws -> LaunchMeasurement {
        guard let keyBytes = verifyingKeys[entry.signature.keyID] else {
            throw SystemVersionDecodeError.unknownKeyID(entry.signature.keyID)
        }
        let publicKey: Curve25519.Signing.PublicKey
        do {
            publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: keyBytes)
        } catch {
            throw SystemVersionDecodeError.malformedInput(
                reason: "verifying key not 32 raw Ed25519 bytes: \(error)"
            )
        }

        guard let signatureBytes = Data(base64Encoded: entry.signature.value) else {
            throw SystemVersionDecodeError.malformedInput(
                reason: "signature value is not valid base64"
            )
        }

        // Normalize trailing `Z` to `+00:00` for byte-stable signing input.
        let createdAt: String
        if entry.createdAt.hasSuffix("Z") {
            createdAt = String(entry.createdAt.dropLast()) + "+00:00"
        } else {
            createdAt = entry.createdAt
        }

        var message = Data()
        message.append(Data(entry.kind.utf8))
        message.append(Data(String(entry.generation).utf8))
        message.append(Data(createdAt.utf8))
        message.append(Data(entry.ref.utf8))
        message.append(entry.launchMeasurement.signedBytes)

        let valid = publicKey.isValidSignature(signatureBytes, for: message)
        guard valid else {
            throw SystemVersionDecodeError.invalidSignature(reason: "Ed25519 verify failed")
        }
        return entry.launchMeasurement
    }
}

extension LaunchMeasurement {
    /// Measurement bytes as covered by the entry's Ed25519 signature.
    var signedBytes: Data {
        switch self {
        case .v1(let digest): return digest
        }
    }

    /// Whether this signed measurement vouches for the launch measurement
    /// carried by the attestation report.
    func matches(reportMeasurement: Data) -> Bool {
        switch self {
        case .v1(let digest): return digest == reportMeasurement
        }
    }
}
