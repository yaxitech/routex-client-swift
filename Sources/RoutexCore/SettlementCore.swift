// Internal abstraction over the per-ticket TEE settlement state. Lets the
// client be tested with a stub that bypasses the cryptographic handshake
// while keeping the full request-execution code path under test.

import Foundation
import RoutexModels

/// One per-ticket settlement context. Implementations cache the negotiated
/// session and TEE measurement on first `ensureSettled(...)` and reuse them
/// for every subsequent `seal`/`unseal`. The method is named `ensureSettled`
/// rather than `settle` so the `Settlement` conformance does not collide
/// with the actor's own `settle(...) -> SettleResult` method.
package protocol SettlementCore: Sendable {
    func ensureSettled(extraHeaders: [String: String]) async throws
    func seal(_ plaintext: Data) async throws -> Data
    func unseal(_ ciphertext: Data) async throws -> Data
    var sessionID: String? { get async }
    var systemVersion: SystemVersionEntry? { get async }
}

/// Factory that produces a fresh `SettlementCore` for a given ticket id.
package typealias SettlementCoreFactory = @Sendable (UUID) -> any SettlementCore
