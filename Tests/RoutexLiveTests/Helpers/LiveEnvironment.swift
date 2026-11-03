import Crypto
import Foundation
import RoutexCore
@_spi(Interop) import RoutexCrypto
import RoutexModels
import RoutexSettlement
import RoutexTransport

@testable import RoutexClient
@testable import RoutexRefresh
@testable import RoutexTickets

/// Live-test environment loaded from exported env vars. Suites are auto-skipped
/// via `.enabled(if: LiveEnvironment.isAvailable)` when the required vars are
/// absent, so `swift test` stays green offline.
struct LiveEnvironment: Sendable {
    let baseURL: URL
    let keyID: String
    let secret: Data
    let issuer: RoutexTicketIssuer
    /// CI test signing keys (set when `TEST_SIGNING_KEYS=true` is exported).
    /// `nil` means use the built-in production verifier keys.
    let testSigningKeys: [String: Data]?
    /// Fixed client keypair for runs against an unattested routex (set when
    /// `ROUTEX_UNATTESTED=true` is exported). The unattested service replays
    /// a canned settlement response sealed to it, so the regular verification
    /// chain still passes. `nil` for attested runs.
    let unattestedClientKeys: ChaChaBoxKeys?

    /// Whether all required env vars are present.
    static var isAvailable: Bool { load() != nil }

    /// Load `LiveEnvironment` from the process env, or `nil` if any required
    /// var is missing.
    static func load() -> LiveEnvironment? {
        let env = ProcessInfo.processInfo.environment
        guard let urlString = env["YAXI_API_URL"],
            let url = URL(string: urlString),
            let keyID = env["YAXI_API_KEY_ID"],
            let secretB64 = env["YAXI_API_KEY_SECRET"],
            let secretBytes = Data(base64Encoded: secretB64),
            let issuer = try? RoutexTicketIssuer(apiKeyID: keyID, apiKeySecret: secretBytes)
        else {
            return nil
        }
        func flag(_ name: String) -> Bool {
            let value = env[name]?.lowercased()
            return value == "true" || value == "1"
        }
        // The unattested routex's canned system version entry is signed with
        // the CI test key, so unattested runs imply the test signing keys.
        let unattested = flag("ROUTEX_UNATTESTED")
        let useTestKeys = flag("TEST_SIGNING_KEYS") || unattested
        return LiveEnvironment(
            baseURL: url,
            keyID: keyID,
            secret: secretBytes,
            issuer: issuer,
            testSigningKeys: useTestKeys ? Self.ciTestSigningKeys : nil,
            unattestedClientKeys: unattested ? Self.fixedUnattestedClientKeys : nil
        )
    }

    /// An accounts ticket whose `exp` is already in the past, for exercising the
    /// server's expired-ticket handling.
    func expiredAccountsTicket() throws -> AccountsTicket {
        try RoutexTicketIssuer(
            apiKeyID: keyID,
            apiKeySecret: secret,
            ttl: 300,
            now: { Date(timeIntervalSinceNow: -600) }
        ).accounts()
    }

    /// An accounts ticket signed with an unknown key ID the route, for
    /// exercising the server's unknown-key handling.
    func unknownKeyAccountsTicket() throws -> AccountsTicket {
        try RoutexTicketIssuer(
            apiKeyID: "api-key-949daeb8-728f-480e-bf66-a0f0c374b2c7",
            apiKeySecret: secret
        ).accounts()
    }

    /// Settlement factory honoring the `TEST_SIGNING_KEYS` and
    /// `ROUTEX_UNATTESTED` overrides, or `nil` when the production
    /// constructor applies.
    private func settlementFactory(transport: any HTTPTransport) -> SettlementCoreFactory? {
        guard let signingKeys = testSigningKeys else { return nil }
        let baseURL = self.baseURL
        let clientKeys = unattestedClientKeys
        return { _ in
            Settlement(
                baseURL: baseURL,
                transport: transport,
                signingKeys: signingKeys,
                clientKeys: clientKeys ?? .generate()
            )
        }
    }

    /// Build a `RoutexClient`. When `TEST_SIGNING_KEYS` or
    /// `ROUTEX_UNATTESTED` is set, the settlement factory is overridden
    /// accordingly; otherwise the production constructor is used.
    func makeClient(transport: any HTTPTransport = URLSessionTransport()) -> RoutexClient {
        guard let factory = settlementFactory(transport: transport) else {
            return RoutexClient(baseURL: baseURL, transport: transport)
        }
        let core = RoutexClientCore(
            baseURL: baseURL,
            transport: transport,
            settlementFactory: factory
        )
        return RoutexClient(core: core)
    }

    /// Build a `RoutexRefreshClient`, applying the same overrides as
    /// ``makeClient(transport:)``.
    func makeRefreshClient(
        transport: any HTTPTransport = URLSessionTransport()
    )
        -> RoutexRefreshClient
    {
        guard let factory = settlementFactory(transport: transport) else {
            return RoutexRefreshClient(baseURL: baseURL, transport: transport)
        }
        let core = RoutexClientCore(
            baseURL: baseURL,
            transport: transport,
            settlementFactory: factory
        )
        return RoutexRefreshClient(core: core)
    }

    /// CI test signing key pair, matching the Ed25519 key that `clerk
    /// sign-release` uses in continuous integration. Co-located with the
    /// verifier on every routex client.
    private static let ciTestSigningKeys: [String: Data] = [
        "dYa685dhHap8RSUtB4DDy1l4UcycsGhklBnV5a/4HSg=":
            Data(base64Encoded: "qzLgDnRegbiQzY416i9/MClrmMp24jcHzaWCWSWSutA=")!
    ]

    /// Keypair the unattested routex's canned V2 settlement response is
    /// sealed to, mirroring `routex-keys-fixtures`. Public by design; an
    /// unattested run provides no confidentiality. It is a development fixture
    /// for a locally built unattested routex and grants no access anywhere, so
    /// it must never be used against `api.yaxi.tech`.
    private static let fixedUnattestedClientKeys: ChaChaBoxKeys = {
        guard #available(iOS 26, macOS 26, macCatalyst 26, tvOS 26, watchOS 26, visionOS 26, *) else {
            preconditionFailure("ROUTEX_UNATTESTED needs ML-KEM-768")
        }
        let secret = Data(
            base64Encoded:
                "zRHWSF1bWnLjDELVCOaIJi//LZHTRzFchgh5jyC9EqGqfmheuosz8P3YT6JgktfxWw3xdbdmuYFo8AG9jxhQ+6hFEcBSOr4rwYxtoJy91PBedsoREqDvzYnZ97TRLJpt"
        )!
        let x25519 = secret.prefix(32)
        let mlkem = try! MLKEM768SecretKey(seed: secret.dropFirst(32))
        return ChaChaBoxKeys(
            secret: .v2(x25519: x25519, mlkem: mlkem),
            publicKey: .v2(
                x25519: try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: x25519).publicKey.rawRepresentation,
                mlkem: mlkem.encapsulationKey
            )
        )
    }()
}
