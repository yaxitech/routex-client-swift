import Foundation

/// Signed entry identifying the running TEE stack and its launch
/// measurement. Returned by `RoutexClient.systemVersion(...)` after the
/// first request for a ticket.
public struct SystemVersionEntry: Sendable, Hashable, Codable {
    /// Kind of system being attested (e.g. routex variant tag).
    public let kind: String
    /// Monotonic generation counter for this kind.
    public let generation: UInt64
    /// Server-side timestamp when the entry was created. Kept as the wire
    /// string because the entry's ``signature`` covers it; parse it if you
    /// need a `Date`.
    public let createdAt: String
    /// Build reference (commit hash, version tag) the measurement
    /// corresponds to.
    public let ref: String
    /// Authenticated launch measurement.
    public let launchMeasurement: LaunchMeasurement
    /// Ed25519 signature over the entry.
    public let signature: SystemVersionSignature

    /// Build a `SystemVersionEntry`.
    public init(
        kind: String,
        generation: UInt64,
        createdAt: String,
        ref: String,
        launchMeasurement: LaunchMeasurement,
        signature: SystemVersionSignature
    ) {
        self.kind = kind
        self.generation = generation
        self.createdAt = createdAt
        self.ref = ref
        self.launchMeasurement = launchMeasurement
        self.signature = signature
    }
}
