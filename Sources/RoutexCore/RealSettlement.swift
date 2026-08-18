// Bridges `Settlement` to the `SettlementCore` protocol consumed by
// `RoutexClientCore`. The protocol exposes `ensureSettled(extraHeaders:)`
// (Void), so this conformance can call the actor's own
// `settle(extraHeaders:) -> SettleResult` directly without an overload
// collision.

import Foundation
import RoutexSettlement

extension Settlement: SettlementCore {
    package func ensureSettled(extraHeaders: [String: String]) async throws {
        _ = try await self.settle(extraHeaders: extraHeaders)
    }
}
