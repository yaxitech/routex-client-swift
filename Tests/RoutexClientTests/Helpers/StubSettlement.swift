import Foundation
import RoutexCore
import RoutexModels
import RoutexSettlement

/// A no-op settlement that passes payloads straight through. Lets us drive
/// the request/response code path without involving the real TEE handshake.
struct PassthroughSettlement: SettlementCore {
    func ensureSettled(extraHeaders: [String: String]) async throws {}
    func seal(_ plaintext: Data) async throws -> Data { plaintext }
    func unseal(_ ciphertext: Data) async throws -> Data { ciphertext }
    var sessionID: String? { get async { "test-session" } }
    var systemVersion: SystemVersionEntry? { get async { nil } }
}
