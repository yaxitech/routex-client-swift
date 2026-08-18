import Crypto
import Foundation
@_spi(Interop) import RoutexCrypto
import RoutexModels
import Testing

@testable import RoutexSettlement

/// Runs `KeySettlement.verify` against a recorded settlement response: a
/// real SEV-SNP Genoa attestation report with its AMD VCEK chain, and the
/// system version signed by the CI test key. The js client pins the same
/// fixture.
@Suite("Key settlement fixture")
struct SettlementFixtureTests {
    // MARK: - Fixture

    /// X25519 secret the fixture's chacha box is sealed to.
    private static let clientSecret = Data([
        227, 151, 53, 216, 6, 18, 173, 191, 95, 36, 131, 207, 133, 116, 233, 223,
        94, 166, 160, 29, 222, 28, 20, 215, 39, 100, 3, 67, 142, 220, 254, 209,
    ])

    private static let signingKeys: [String: Data] = [
        "dYa685dhHap8RSUtB4DDy1l4UcycsGhklBnV5a/4HSg=": Data([
            171, 50, 224, 14, 116, 94, 129, 184, 144, 205, 142, 53, 234, 47, 127, 48,
            41, 107, 152, 202, 118, 226, 55, 7, 205, 165, 130, 89, 37, 146, 186, 208,
        ])
    ]

    private static let chachaBox =
        "c70P//zXw5WDN4ZVVBLbU6UVJdC4EswlNWUpM7Plvl+6yjgkv5+PTYzR5YKpArBhMiNEAD8PNhH65s7ZeZxmETOZF/EXUWC4"
        + "Gr4hM0XOGUMvVWzeAbVHSVfRgNUb72z2PkP64zpkaRsz7CMZuSmwjOngXMmZBoJ3U9GOBCBUkF6Wr7PL5j6nrFcABO2x1rK7"
        + "OZzxWHnm1PYZbNajoYInt0B//6PU5vk="

    private static let attestationReport =
        "BQAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAKAAAAAAAbWCUAAAAAAAAA"
        + "AAAAAAAAAAC7hR4gN0fDaF15opkQ52xTlXiW2/bmiDW2TqLCsr59tgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "vs5zmaTaBUpjouP6Gkf/mMiOOR1DeRJvxOdcZ38lts1r/Y72CahjgEljOsfgDkrBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABi7rIj6+Czg/wjqW/1+ebErc8VNceg/WAmdAfxkwukIf//////////"
        + "////////////////////////////////CgAAAAAAG1gZEQEAAAAAAAAAAAAAAAAAAAAAAAAAAADgI0vts5GEMfVO4nkHh9ev"
        + "E4pnvh5YGiI2UOgQyUU0K8mujR/qg7McSdyMw020VwvPJb1teTmFaTqfDCEz3zPYCgAAAAAAG1gxNwEAMTcBAAoAAAAAABtY"
        + "CwAAAAAAAAALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZYrjOIJQEkOAa96UY4bNzGBfb3rkU/nkYlrJPreawo+VxJapz1dauh50ZJaQlQAn"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALN/WkfrqKgMOMMcOriyKfs6OwtTjsN6iSWKTnl7uQEpVKdNW8vEm/MBFYVbq8iKy"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    private static let vcek = """
        -----BEGIN CERTIFICATE-----
        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
        FqMo
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
                "createdAt": "2025-11-14T17:32:12.826119714+00:00",
                "ref": "",
                "launchMeasurement":
                    "vs5zmaTaBUpjouP6Gkf/mMiOOR1DeRJvxOdcZ38lts1r/Y72CahjgEljOsfgDkrB",
                "signature": [
                    "keyId": "dYa685dhHap8RSUtB4DDy1l4UcycsGhklBnV5a/4HSg=",
                    "value":
                        "7J2D/9SOBeHAU1Z9Vr87Sf2jZuS6+5xofLUJX3y8SlDgQWZyArsxHfjKq6TACV9iQw8ZACndi72f8cqyC7i8DA==",
                ] as [String: Any],
            ] as [String: Any],
        ]
    }

    private static func clientKeys() throws -> ChaChaBoxKeys {
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: clientSecret)
        return ChaChaBoxKeys(
            secret: .v1(clientSecret),
            publicKey: .v1(key.publicKey.rawRepresentation)
        )
    }

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
    func fixtureVerifies() throws {
        let result = try Self.verify()
        let sessionID = Data("fixedkeyfixedkeyfixedkeyfixedkey".utf8).base64EncodedString()
        #expect(result.sessionID == sessionID)
        #expect(result.systemVersion.generation == 1)
        #expect(result.systemVersion.kind == "release")
    }

    @Test("a tampered report fails attestation")
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
    func invalidVcek() throws {
        try expectFailure(
            { if case .attestationVerificationFailed = $0 { true } else { false } },
            mutate: { $0["vcek"] = "invalid" }
        )
    }

    @Test("an unknown system-version key is rejected")
    func unknownSigningKey() throws {
        try expectFailure(
            { if case .systemVersionInvalid = $0 { true } else { false } },
            signingKeys: [:]
        )
    }
}
