import Foundation

/// Errors that originate inside the client itself (sealing, unsealing,
/// malformed responses). These indicate a protocol or transport-layer
/// problem rather than a service-level outcome and warrant reporting to
/// YAXI support together with `RoutexClient.traceID`.
public enum RoutexClientError: Error, Sendable {
    /// Sealing a request failed under the established ChaCha20-Poly1305
    /// key.
    case sealingFailed(message: String, underlying: (any Error)?)
    /// Unsealing a server-sealed response failed.
    case unsealingFailed(message: String, underlying: (any Error)?)
    /// The response was structurally invalid for the expected shape.
    case malformedResponse(message: String, underlying: (any Error)?)
}

extension RoutexClientError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .sealingFailed(let m, _): return "sealingFailed: \(m)"
        case .unsealingFailed(let m, _): return "unsealingFailed: \(m)"
        case .malformedResponse(let m, _): return "malformedResponse: \(m)"
        }
    }
}

extension RoutexClientError: LocalizedError {
    public var errorDescription: String? { description }
}
