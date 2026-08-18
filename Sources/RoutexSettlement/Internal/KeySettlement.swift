// Key-settlement verification. Parses the envelope returned by
// `/key-settlement` and runs every cryptographic check, in order:
//   1. JSON envelope decodes; base64 fields decode.
//   2. AMD attestation report parses.
//   3. VCEK chain verifies up to a trusted root.
//   4. Report signature, policy gates, and TCB checks (per `Requirements`).
//   5. SHA-256(chachaBox) == report.reportData[0..<32] - binds the sealed
//      handshake to the report.
//   6. SystemVersion entry's Ed25519 signature verifies.
//   7. SystemVersion launch measurement matches report.measurement.
//   8. ChaChaBox unseals to {publicKey, sessionId}.

import Crypto
import Foundation
@_spi(Interop) import RoutexCrypto
import RoutexModels

enum KeySettlement {
    static func verify(
        responseBytes: Data,
        clientKeys: ChaChaBoxKeys,
        vcekRoots: VcekRootStore,
        systemVersionKeys: [String: Data]
    ) throws -> SettleResult {
        let response = try decodeResponse(responseBytes)
        let reportBytes = try decodeBase64(response.attestationReport, field: "attestationReport")
        let chachaBoxBytes = try decodeBase64(response.chachaBox, field: "chachaBox")

        // Attestation: parse + chain + report verifier.
        let report: AttestationReport
        let chain: VcekChainVerifyResult
        do {
            chain = try VcekChainOps.verify(vcekChainPem: response.vcek, rootStore: vcekRoots)
        } catch {
            throw KeySettlementError.attestationVerificationFailed(
                reason: "VCEK chain: \(error)"
            )
        }
        do {
            report = try AttestationReport(reportBytes)
        } catch {
            throw KeySettlementError.attestationVerificationFailed(
                reason: "report parse: \(error)"
            )
        }
        do {
            try ReportVerifier.verify(report: report, chain: chain)
        } catch {
            throw KeySettlementError.attestationVerificationFailed(
                reason: "report verify: \(error)"
            )
        }

        // SHA-256(chachaBox) is committed in the report - tamper-evidence on
        // the sealed handshake.
        let chachaHash = Data(SHA256.hash(data: chachaBoxBytes))
        let reportBinding = Data(Array(report.reportData).prefix(32))
        guard chachaHash == reportBinding else {
            throw KeySettlementError.chachaBoxBindingMismatch
        }

        // System version: Ed25519 signature, then launch-measurement match.
        let measurement: LaunchMeasurement
        do {
            measurement = try SystemVersionVerifier.verify(
                entry: response.systemVersion,
                verifyingKeys: systemVersionKeys
            )
        } catch {
            throw KeySettlementError.systemVersionInvalid(reason: "\(error)")
        }
        guard measurement.matches(reportMeasurement: report.measurement) else {
            throw KeySettlementError.measurementMismatch
        }

        // Unseal the negotiated session material.
        let plaintext: Data
        do {
            plaintext = try ChaChaBox.unseal(chachaBoxBytes, secret: clientKeys.secret)
        } catch {
            throw KeySettlementError.chachaBoxDecryptFailed(reason: "\(error)")
        }
        let payload = try decodeSealedPayload(plaintext)
        return SettleResult(
            serverPublicKey: payload.serverPublicKey,
            sessionID: payload.sessionID,
            systemVersion: response.systemVersion
        )
    }

    // MARK: - JSON envelope

    private struct WireResponse: Decodable {
        let attestationReport: String
        let vcek: String
        let chachaBox: String
        let systemVersion: SystemVersionEntry
    }

    private static func decodeResponse(_ bytes: Data) throws -> WireResponse {
        do {
            let decoder = JSONDecoder()
            return try decoder.decode(WireResponse.self, from: bytes)
        } catch {
            throw KeySettlementError.malformedResponse(reason: "JSON decode: \(error)")
        }
    }

    private static func decodeBase64(_ value: String, field: String) throws -> Data {
        guard let data = Data(base64Encoded: value) else {
            throw KeySettlementError.malformedResponse(reason: "\(field) is not valid base64")
        }
        return data
    }

    // MARK: - Sealed payload

    private struct SealedPayload {
        let serverPublicKey: ChaChaBoxPublicKey
        let sessionID: String
    }

    private struct SealedPayloadJSON: Decodable {
        let publicKey: String
        let sessionID: String

        private enum CodingKeys: String, CodingKey {
            case publicKey
            case sessionID = "sessionId"
        }
    }

    private static func decodeSealedPayload(_ plaintext: Data) throws -> SealedPayload {
        let parsed: SealedPayloadJSON
        do {
            parsed = try JSONDecoder().decode(SealedPayloadJSON.self, from: plaintext)
        } catch {
            throw KeySettlementError.invalidSealedPayload(
                reason: "sealed plaintext is not the expected JSON shape: \(error)"
            )
        }
        guard let serverKeyBytes = Data(base64Encoded: parsed.publicKey) else {
            throw KeySettlementError.invalidSealedPayload(
                reason: "publicKey is not valid base64"
            )
        }
        return SealedPayload(
            serverPublicKey: .v1(serverKeyBytes),
            sessionID: parsed.sessionID
        )
    }
}
