import Foundation

/// User dialog the bank wants the front end to render.
///
/// A `Dialog` consists of a display part (``message``, optional ``image``,
/// ``context`` for layout hints) and an interactive part (``input``). The
/// integrator typically also offers a way to cancel the flow alongside
/// whichever input variant is rendered.
public struct Dialog: Sendable, Hashable, Codable {
    /// Hint about the kind of dialog so a UI can render the right header /
    /// styling.
    public let context: DialogContext?
    /// Plain-text message to display.
    public let message: String?
    /// Image to display alongside the message (e.g. a photo TAN).
    public let image: Image?
    /// What the user must do to continue.
    public let input: DialogInput

    /// Build a `Dialog`.
    public init(
        context: DialogContext? = nil,
        message: String? = nil,
        image: Image? = nil,
        input: DialogInput
    ) {
        self.context = context
        self.message = message
        self.image = image
        self.input = input
    }
}
