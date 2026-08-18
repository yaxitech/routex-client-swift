import Foundation

/// One option in a ``DialogInput/selection(options:context:)`` dialog.
public struct DialogOption: Sendable, Hashable, Codable {
    /// Stable key that identifies this option. Submit back via
    /// the per-service `respond` method.
    public let key: String
    /// Short label for the option, ready to render in a UI.
    public let label: String
    /// Optional longer explanation (e.g. tooltip / secondary line).
    public let explanation: String?

    /// Build a `DialogOption`.
    public init(key: String, label: String, explanation: String? = nil) {
        self.key = key
        self.label = label
        self.explanation = explanation
    }
}
