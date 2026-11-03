import Crypto
import Foundation
@_spi(Interop) import RoutexCrypto
import RoutexModels
import RoutexTransport
import Testing

@testable import RoutexSettlement

/// Runs `KeySettlement.verify` against a recorded settlement response: a
/// real SEV-SNP Genoa attestation report with its AMD VCEK chain, and the
/// system version signed by the CI test key. It is `routex-keys-fixtures`'
/// V2 settlement, which needs ML-KEM-768.
@Suite("Key settlement fixture")
struct SettlementFixtureTests {
    // MARK: - Fixture

    /// X25519 scalar and ML-KEM-768 seed the fixture's chacha box is sealed to.
    private static let clientSecret = Data(
        base64Encoded:
            "zRHWSF1bWnLjDELVCOaIJi//LZHTRzFchgh5jyC9EqGqfmheuosz8P3YT6JgktfxWw3xdbdmuYFo8AG9jxhQ+6hFEcBSOr4rwYxtoJy91PBedsoREqDvzYnZ97TRLJpt"
    )!

    private static let signingKeys: [String: Data] = [
        "dYa685dhHap8RSUtB4DDy1l4UcycsGhklBnV5a/4HSg=": Data([
            171, 50, 224, 14, 116, 94, 129, 184, 144, 205, 142, 53, 234, 47, 127, 48,
            41, 107, 152, 202, 118, 226, 55, 7, 205, 165, 130, 89, 37, 146, 186, 208,
        ])
    ]

    private static let chachaBox =
        "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"
        + "15bi0EMc/pB9uiZd0NVf87n0HET4Dq9DDBrvXg=="

    private static let attestationReport =
        "BQAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAMAAAAAAAcWCUAAAAAAAAA"
        + "AAAAAAAAAAAKZmjE/DP5/aA4bLtRtdV26vZSW95qet709MoZkH1L4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "TMssXBMAGZpBwJLXgPEdf/Pi5JdPUY7QQLPBAoLDSc9ZUiBKrzul8hEIbNLQV7+JAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADzx4p+EO16mBo42bbKmTZwLAzb8xTvcPClAPTyxHpxo///////////"
        + "////////////////////////////////DAAAAAAAHFgZEQEAAAAAAAAAAAAAAAAAAAAAAAAAAADgI0vts5GEMfVO4nkHh9ev"
        + "E4pnvh5YGiI2UOgQyUU0K8mujR/qg7McSdyMw020VwvPJb1teTmFaTqfDCEz3zPYDAAAAAAAHFgCOgEAAjoBAAwAAAAAABxY"
        + "CwAAAAAAAAALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAihYgpg9LJ7iLHD5ZnX5BfBvee9BIbT3NSj3AZ8LN9BhMeCRbLVWKlq+/xWeGzPS8"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbt5S86xpMpn88WlEwHF2L2CyNdGF3hZQ7lgNvy9O1QWS+6RQMGH7ey6a5/cDtvB/"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    private static let vcek = """
        -----BEGIN CERTIFICATE-----
        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
        3iKB
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        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
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        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
        /wMz1R1BHg==
        -----END CERTIFICATE-----
        """

    private static func fixture() -> [String: Any] {
        [
            "chachaBox": chachaBox,
            "attestationReport": attestationReport,
            "vcek": vcek,
            "systemVersion": [
                "kind": "release",
                "generation": 1,
                "createdAt": "2026-11-02T11:32:48.069055202+00:00",
                "ref": "",
                "launchMeasurement":
                    "TMssXBMAGZpBwJLXgPEdf/Pi5JdPUY7QQLPBAoLDSc9ZUiBKrzul8hEIbNLQV7+J",
                "signature": [
                    "keyId": "dYa685dhHap8RSUtB4DDy1l4UcycsGhklBnV5a/4HSg=",
                    "value":
                        "k/0reFqCkIWQjqgp9mdfvcnljxj2Cx+lYDAxxKH0Au8L7ugPlL1NQR4p8aFy4ojCfMYaIJC1EXn7T1YsTE9aAg==",
                ] as [String: Any],
            ] as [String: Any],
        ]
    }

    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    private static func clientKeys() throws -> ChaChaBoxKeys {
        let x25519 = clientSecret.prefix(32)
        let mlkem = try MLKEM768SecretKey(seed: clientSecret.dropFirst(32))
        return ChaChaBoxKeys(
            secret: .v2(x25519: x25519, mlkem: mlkem),
            publicKey: .v2(
                x25519: try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: x25519).publicKey.rawRepresentation,
                mlkem: mlkem.encapsulationKey
            )
        )
    }

    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    private static func verify(
        signingKeys: [String: Data] = SettlementFixtureTests.signingKeys,
        mutate: (inout [String: Any]) -> Void = { _ in }
    ) throws -> SettleResult {
        var object = fixture()
        mutate(&object)
        let bytes = try JSONSerialization.data(withJSONObject: object)
        return try KeySettlement.verify(
            responseBytes: bytes,
            clientKeys: clientKeys(),
            vcekRoots: .amd,
            systemVersionKeys: signingKeys
        )
    }

    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    private func expectFailure(
        _ isExpected: (KeySettlementError) -> Bool,
        signingKeys: [String: Data] = SettlementFixtureTests.signingKeys,
        mutate: (inout [String: Any]) -> Void = { _ in }
    ) throws {
        do {
            _ = try Self.verify(signingKeys: signingKeys, mutate: mutate)
            Issue.record("verification unexpectedly succeeded")
        } catch let error as KeySettlementError {
            #expect(isExpected(error), "unexpected settlement error: \(error)")
        }
    }

    // MARK: - Tests

    @Test("the recorded settlement response verifies")
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func fixtureVerifies() throws {
        let result = try Self.verify()
        let sessionID = Data("fixedkeyfixedkeyfixedkeyfixedkey".utf8).base64EncodedString()
        #expect(result.sessionID == sessionID)
        #expect(result.systemVersion.generation == 1)
        #expect(result.systemVersion.kind == "release")
    }

    @Test("a tampered report fails attestation")
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func tamperedReport() throws {
        try expectFailure(
            { if case .attestationVerificationFailed = $0 { true } else { false } },
            mutate: {
                var report = Data(base64Encoded: $0["attestationReport"] as! String)!
                report[0x51] ^= 0xFF
                $0["attestationReport"] = report.base64EncodedString()
            }
        )
    }

    @Test("a tampered chacha box breaks the report binding")
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func tamperedChachaBox() throws {
        try expectFailure(
            { $0 == .chachaBoxBindingMismatch },
            mutate: {
                var box = Data(base64Encoded: $0["chachaBox"] as! String)!
                box[40] ^= 0xFF
                $0["chachaBox"] = box.base64EncodedString()
            }
        )
    }

    @Test("a broken VCEK chain fails attestation")
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func invalidVcek() throws {
        try expectFailure(
            { if case .attestationVerificationFailed = $0 { true } else { false } },
            mutate: { $0["vcek"] = "invalid" }
        )
    }

    @Test("an unknown system-version key is rejected")
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func unknownSigningKey() throws {
        try expectFailure(
            { if case .systemVersionInvalid = $0 { true } else { false } },
            signingKeys: [:]
        )
    }

    // MARK: - Settlement request

    private struct RequestBody: Decodable {
        let publicKey: String
        let version: Int
    }

    private actor RecordingTransport: HTTPTransport {
        private let response: HTTPResponse
        private(set) var requests: [HTTPRequest] = []

        init() throws {
            let body = try JSONSerialization.data(withJSONObject: SettlementFixtureTests.fixture())
            response = HTTPResponse(status: 200, headers: [:], body: body)
        }

        func execute(_ request: HTTPRequest) -> HTTPResponse {
            requests.append(request)
            return response
        }
    }

    /// A settlement against the recorded response, and the transport that
    /// records its request.
    private static func settlement(
        clientKeys: ChaChaBoxKeys
    ) throws -> (settlement: Settlement, transport: RecordingTransport) {
        let transport = try RecordingTransport()
        let settlement = Settlement(
            baseURL: URL(string: "https://routex.invalid")!,
            transport: transport,
            signingKeys: signingKeys,
            clientKeys: clientKeys
        )
        return (settlement, transport)
    }

    private static func requestBody(_ transport: RecordingTransport) async throws -> RequestBody {
        let body = try #require(await transport.requests.first?.body)
        return try JSONDecoder().decode(RequestBody.self, from: body)
    }

    @Test("a V1 client key settles with version 1 and refuses the V2 box")
    func v1Request() async throws {
        let key = Curve25519.KeyAgreement.PrivateKey()
        let keys = ChaChaBoxKeys(secret: .v1(key.rawRepresentation), publicKey: .v1(key.publicKey.rawRepresentation))
        let (settlement, transport) = try Self.settlement(clientKeys: keys)
        let error = await #expect(throws: KeySettlementError.self) {
            try await settlement.settle()
        }
        guard case .chachaBoxDecryptFailed = error else {
            Issue.record("unexpected settlement error: \(String(describing: error))")
            return
        }
        let body = try await Self.requestBody(transport)
        #expect(body.publicKey == keys.publicKey.rawRepresentation.base64EncodedString())
        #expect(body.version == 1)
    }

    @Test("a V2 client key settles with version 2")
    @available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *)
    func v2Request() async throws {
        let keys = try Self.clientKeys()
        let (settlement, transport) = try Self.settlement(clientKeys: keys)
        try await settlement.settle()
        let body = try await Self.requestBody(transport)
        #expect(body.publicKey == keys.publicKey.rawRepresentation.base64EncodedString())
        #expect(body.version == 2)
    }
}
