// One TEE-attested key-settlement session. The first call to `settle()`
// performs the handshake and caches the result; subsequent calls return the
// cached result and are safe to invoke without coordination.

import Foundation
@_spi(Interop) import RoutexCrypto
import RoutexModels
import RoutexTransport

/// TEE-attested key-settlement session.
///
/// Consumers typically reach this through `RoutexClient`, which constructs
/// and caches one `Settlement` per ticket.
public actor Settlement {
    private let baseURL: URL
    private let transport: any HTTPTransport
    private let signingKeys: [String: Data]
    private let path: String
    private let clientKeys: ChaChaBoxKeys
    private let vcekRoots: VcekRootStore

    private var settled: SettleResult?
    /// In-flight settle task; new callers await this rather than firing a
    /// fresh HTTP request. Cleared on completion (success or failure).
    private var inFlight: Task<SettleResult, Error>?

    /// Build a session against `baseURL`, using built-in trust material.
    public init(baseURL: URL, transport: any HTTPTransport) {
        self.init(
            baseURL: baseURL,
            transport: transport,
            signingKeys: YaxiSystemVersionKeys.default
        )
    }

    /// Build a session with caller-supplied trust material and overrides.
    package init(
        baseURL: URL,
        transport: any HTTPTransport,
        signingKeys: [String: Data],
        path: String = "key-settlement",
        clientKeys: ChaChaBoxKeys = .generate()
    ) {
        self.baseURL = baseURL
        self.transport = transport
        self.signingKeys = signingKeys
        self.path = path
        self.clientKeys = clientKeys
        self.vcekRoots = .amd
    }

    /// `true` once a successful settlement has been cached.
    public var isSettled: Bool { settled != nil }

    /// Session id issued by the server, or `nil` before `settle()` succeeds.
    public var sessionID: String? { settled?.sessionID }

    /// Authenticated TEE system version, or `nil` before `settle()` succeeds.
    public var systemVersion: SystemVersionEntry? { settled?.systemVersion }

    /// Public half of the client keypair used by the session.
    package var clientPublicKey: ChaChaBoxPublicKey { clientKeys.publicKey }

    /// Run the handshake on first call; return the cached result on every
    /// subsequent call. Idempotent.
    ///
    /// `extraHeaders` are forwarded only on the call that performs the
    /// handshake; subsequent calls ignore them.
    @discardableResult
    public func settle(extraHeaders: [String: String] = [:]) async throws -> SettleResult {
        if let existing = settled { return existing }
        if let task = inFlight { return try await task.value }

        let task = Task<SettleResult, Error> {
            [baseURL, path, transport, clientKeys, vcekRoots, signingKeys] in
            let url = baseURL.appendingPathComponent(path)
            var headers: [String: String] = [
                "Accept": RoutexAPI.mediaType,
                "Content-Type": "application/json",
            ]
            for (name, value) in extraHeaders { headers[name] = value }

            let publicKeyBase64: String = {
                switch clientKeys.publicKey {
                case .v1(let bytes): return bytes.base64EncodedString()
                }
            }()
            let body = Data(#"{"publicKey":"\#(publicKeyBase64)"}"#.utf8)

            let response = try await transport.execute(
                HTTPRequest(method: .post, url: url, headers: headers, body: body)
            )
            guard response.status < 400 else {
                let text = String(data: response.body, encoding: .utf8) ?? "<non-utf8 body>"
                throw KeySettlementError.malformedResponse(
                    reason: "settlement HTTP \(response.status): \(text)"
                )
            }
            return try KeySettlement.verify(
                responseBytes: response.body,
                clientKeys: clientKeys,
                vcekRoots: vcekRoots,
                systemVersionKeys: signingKeys
            )
        }
        inFlight = task
        defer { inFlight = nil }
        let result = try await task.value
        settled = result
        return result
    }

    /// Seal `plaintext` for transmission to the server. Throws
    /// `KeySettlementError.notReady` if `settle()` has not succeeded.
    public func seal(_ plaintext: Data) throws -> Data {
        guard let result = settled else { throw KeySettlementError.notReady }
        return try ChaChaBox.seal(plaintext, recipient: result.serverPublicKey)
    }

    /// Unseal `ciphertext` addressed to this session's client keypair.
    public func unseal(_ ciphertext: Data) throws -> Data {
        try ChaChaBox.unseal(ciphertext, secret: clientKeys.secret)
    }

    /// Verify a caller-fetched key-settlement response with the built-in trust
    /// material, for interop consumers that do the HTTP themselves.
    @_spi(Interop)
    public static func verify(
        responseBytes: Data,
        clientKeys: ChaChaBoxKeys
    ) throws -> SettleResult {
        try KeySettlement.verify(
            responseBytes: responseBytes,
            clientKeys: clientKeys,
            vcekRoots: .amd,
            systemVersionKeys: YaxiSystemVersionKeys.default
        )
    }
}
