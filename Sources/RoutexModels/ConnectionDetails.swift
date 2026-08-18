import Foundation

/// Optional per-connection details that a search call may request.
public enum ConnectionDetails: String, Sendable, Codable, Hashable, CaseIterable {
    /// Populate ``ConnectionInfo/bics`` on each result.
    case bics
    /// Populate ``ConnectionInfo/bankCodes`` on each result.
    case bankCodes
}
