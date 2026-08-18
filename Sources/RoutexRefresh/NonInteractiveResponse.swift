import RoutexModels

/// Envelope returned by every ``RoutexRefreshClient`` service call.
///
/// Unlike the interactive `Response`, there are no interrupt branches: a
/// non-interactive call either throws or yields a decoded `result`.
public struct NonInteractiveResponse<Payload: Sendable & Decodable>: Sendable, Decodable {
    /// Decoded service payload (e.g. `[Account]`, `Balances`).
    public let result: Payload
    /// Opaque `Session` to pass into the next call in the same flow, if any.
    public let session: Session?
    /// Refreshed `ConnectionData` to persist for future calls, if any.
    public let connectionData: ConnectionData?

    /// Build a `NonInteractiveResponse`.
    public init(result: Payload, session: Session? = nil, connectionData: ConnectionData? = nil) {
        self.result = result
        self.session = session
        self.connectionData = connectionData
    }
}
