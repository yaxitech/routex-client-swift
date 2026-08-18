import Foundation

/// Type of a free-form input field. May drive hints, dedicated keyboard
/// layouts, and input restrictions or validation.
public enum InputType: String, Sendable, Codable, Hashable, CaseIterable {
    case date = "Date"
    case email = "Email"
    case number = "Number"
    case phone = "Phone"
    case text = "Text"
}
