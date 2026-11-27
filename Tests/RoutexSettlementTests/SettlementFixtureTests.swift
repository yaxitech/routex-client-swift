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
        "An4a14xNho4b6pg4CsN7QpK5XyufnEn70ZBTHuvRlJZQpP2iA3BLlVFxt+DxZ8/i6m441KKe2m3xytRaqxkdu/fzdDhYq9eX"
        + "jJoIgzLyB6ZIXqiOhvuVMUrMHpr5KoVtHOkF8NTSRf8xtu8GxdsW3+p9cOxS3pncs2chM8rZjyFZ6ZZ5qs+7p96IvGByJEcn"
        + "hz1vZkbEQA2p1HS0ujjsuilY2jWWQlE83exydGZquvPtCC7x/Pyjh323db3XkPFAMnuPHEW41jaay1hgQqjQGoVRtObr3Ow3"
        + "khxSq/zOf3Qch757MlUw31y0oBBkaijtKS2mLGWSJrHULWnXmrqs1bDaHLFp2SgW4MqHsWTjKpkB3c6nBV6IkWj15CQ10Xul"
        + "gJ6oFNAdFX5VrKR9XabzVfum3NnO+ZVewbcpD22M/hSQDQKrxMpKn9jY52pS2BLo1ZQMJhTrWqH7qHep4+ccPzsThEM3rmV0"
        + "RWR2U69MuKdgi5k+GK3ErRqVYX07WUaTjmp1WMcYIm6Hed26ZeyLs4NeTRfzQorkZ1kqIlMwcl9juE2zFZkhtNnMwNiCNFCB"
        + "boWhiJhYSFzgr4q86o1pSLwWnW429H2kp1ACrd7d+IjZ0fwJ0fvcdToopMNSIPXh7NzgNmedWlCvOJRytN2htC1isNFJq9Pu"
        + "HVzL30hEAlSZwXxLkXEhE+MyQoGbnTGgx68SlHeSuBehKtFWfMgRzNKTlV6xDv0KXdkVUZaPjmJrVi9K2j33Tu98JH0qoxlA"
        + "oHZ0gLQVIbQNGAWucnGRWnmpPXMR6OVUIMHuJgjjWfJ+5uBQMcTdF048gJFGCQV6n+A5MZpjU7MrqTmlvtQda3sLd4ifmZls"
        + "qNpIfJU2Mj9ukybMNM/rLx37qW2EVRHr9uLCQySXjP5UNE84MqfXEE9WUwMWM8frONeAI3koUprudzsyMgafJpbv6ajz7U/W"
        + "EYIm8l1bboamp/PSXoF1O7wyXOLCOCFqi248dmb1n7XR6XpSUNghQ0EfWzY+0aHn7tJU3EEYfscrzD+dBQM85WJuo7kxTKg9"
        + "Fn+eta1JI9EQmnOgGgk8IZ1EAZDWX6pk6+nZCtYlJ26M9Xw5ebTGX9z85JA2WWnaegNbnydQc1dxjM8mISv+U2Y8SxN9DBPj"
        + "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"
        + "OyE61UtGvwyTE23g+S46YchD5jgV2Jc1+Eheqw=="

    private static let attestationReport =
        "BQAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAMAAAAAAAeWyUAAAAAAAAA"
        + "AAAAAAAAAAA59wg9E8/RItcFwnx5DmtGRSXEQdC4gQv/8wVzpUsshgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "+7+vfLyQ79/AO0/m72l9Yeyq/17LpqO4fx8FAADRWDRYwksUXOdVNI6orKM5QxCxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADL5SEYpVhYewuC836vkLymgT+1HG7oBSvNaBtFYVbuVf//////////"
        + "////////////////////////////////DAAAAAAAHlsZEQEAAAAAAAAAAAAAAAAAAAAAAAAAAADafZC2fblvUW3qkb5+ry/U"
        + "fhmyFN0zOo8NtZnvdPB2+EOe1AqZSqdoeDlcWg628HSY3rxiRh2e5+5Yo2A17iHCDAAAAAAAHlsEOgEABDoBAAwAAAAAAB5b"
        + "+wMAAAAAAAD7AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAd8cG9mJ+m4qtpPQntPUfYsOrcJgYh8IQBgpZ9ZSkARwS7J7Dc6voI9QYpQfmOPPp"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADeqTZSDKvgjfAAF8xh3EeOHfzQ6+bUoj9eFzxNHE5ix40yC6cL7+qHDzytti9wxp"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    private static let vcek = """
        -----BEGIN CERTIFICATE-----
        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
        Vcoe+5OF1MacwG/FUivxiIUc0eqCzg==
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        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
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        MIIGYzCCBBKgAwIBAgIDAgAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC
        BQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS
        BgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg
        Q2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp
        Y2VzMRIwEAYDVQQDDAlBUkstR2Vub2EwHhcNMjIwMTI2MTUzNDM3WhcNNDcwMTI2
        MTUzNDM3WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS
        BgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j
        ZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLUdlbm9hMIICIjANBgkqhkiG
        9w0BAQEFAAOCAg8AMIICCgKCAgEA3Cd95S/uFOuRIskW9vz9VDBF69NDQF79oRhL
        /L2PVQGhK3YdfEBgpF/JiwWFBsT/fXDhzA01p3LkcT/7LdjcRfKXjHl+0Qq/M4dZ
        kh6QDoUeKzNBLDcBKDDGWo3v35NyrxbA1DnkYwUKU5AAk4P94tKXLp80oxt84ahy
        HoLmc/LqsGsp+oq1Bz4PPsYLwTG4iMKVaaT90/oZ4I8oibSru92vJhlqWO27d/Rx
        c3iUMyhNeGToOvgx/iUo4gGpG61NDpkEUvIzuKcaMx8IdTpWg2DF6SwF0IgVMffn
        vtJmA68BwJNWo1E4PLJdaPfBifcJpuBFwNVQIPQEVX3aP89HJSp8YbY9lySS6PlV
        EqTBBtaQmi4ATGmMR+n2K/e+JAhU2Gj7jIpJhOkdH9firQDnmlA2SFfJ/Cc0mGNz
        W9RmIhyOUnNFoclmkRhl3/AQU5Ys9Qsan1jT/EiyT+pCpmnA+y9edvhDCbOG8F2o
        xHGRdTBkylungrkXJGYiwGrR8kaiqv7NN8QhOBMqYjcbrkEr0f8QMKklIS5ruOfq
        lLMCBw8JLB3LkjpWgtD7OpxkzSsohN47Uom86RY6lp72g8eXHP1qYrnvhzaG1S70
        vw6OkbaaC9EjiH/uHgAJQGxon7u0Q7xgoREWA/e7JcBQwLg80Hq/sbRuqesxz7wB
        WSY254cCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSfXfn+Ddjz
        WtAzGiXvgSlPvjGoWzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG
        KWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvR2Vub2EvY3JsMEYGCSqG
        SIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI
        AWUDBAICBQCiAwIBMKMDAgEBA4ICAQAdIlPBC7DQmvH7kjlOznFx3i21SzOPDs5L
        7SgFjMC9rR07292GQCA7Z7Ulq97JQaWeD2ofGGse5swj4OQfKfVv/zaJUFjvosZO
        nfZ63epu8MjWgBSXJg5QE/Al0zRsZsp53DBTdA+Uv/s33fexdenT1mpKYzhIg/cK
        tz4oMxq8JKWJ8Po1CXLzKcfrTphjlbkh8AVKMXeBd2SpM33B1YP4g1BOdk013kqb
        7bRHZ1iB2JHG5cMKKbwRCSAAGHLTzASgDcXr9Fp7Z3liDhGu/ci1opGmkp12QNiJ
        uBbkTU+xDZHm5X8Jm99BX7NEpzlOwIVR8ClgBDyuBkBC2ljtr3ZSaUIYj2xuyWN9
        5KFY49nWxcz90CFa3Hzmy4zMQmBe9dVyls5eL5p9bkXcgRMDTbgmVZiAf4afe8DL
        dmQcYcMFQbHhgVzMiyZHGJgcCrQmA7MkTwEIds1wx/HzMcwU4qqNBAoZV7oeIIPx
        dqFXfPqHqiRlEbRDfX1TG5NFVaeByX0GyH6jzYVuezETzruaky6fp2bl2bczxPE8
        HdS38ijiJmm9vl50RGUeOAXjSuInGR4bsRufeGPB9peTa9BcBOeTWzstqTUB/F/q
        aZCIZKr4X6TyfUuSDz/1JDAGl+lxdM0P9+lLaP9NahQjHCVf0zf1c1salVuGFk2w
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
                "createdAt": "2026-11-26T14:01:58.872068015+00:00",
                "ref": "",
                "launchMeasurement":
                    "+7+vfLyQ79/AO0/m72l9Yeyq/17LpqO4fx8FAADRWDRYwksUXOdVNI6orKM5QxCx",
                "signature": [
                    "keyId": "dYa685dhHap8RSUtB4DDy1l4UcycsGhklBnV5a/4HSg=",
                    "value":
                        "+jDUXgbfAXVnD2g271ECuCseIBaLbSbGHxqKOMnw26QcTQzRc+CpJ/zmw4+W78L2zkWzAaAWcyMYBxdmLwodAQ==",
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
