import Foundation

/// Interactive part of a ``Dialog``. The case picks how the user resumes
/// the flow.
public enum DialogInput: Sendable, Hashable, Codable {
    /// A primary action to confirm the dialog.
    ///
    /// `context` is the opaque continuation token to pass to
    /// the per-service `confirm` method. `pollingDelay`, when non-nil, is
    /// how long to wait before automatically confirming; drivers can use
    /// it to poll long-running flows.
    case confirmation(context: ConfirmationContext, pollingDelay: TimeInterval?)
    /// A list of options for the user to pick from. Render `options` and
    /// submit the selected ``DialogOption/key`` via
    /// the per-service `respond` method.
    case selection(options: [DialogOption], context: InputContext)
    /// A free-form input field. Render the prompt, collect the user's
    /// answer, and submit it via the per-service `respond` method.
    ///
    /// `type` hints at the expected value (number, date, etc.).
    /// `secrecyLevel` indicates whether input must be masked. `minLength`
    /// and `maxLength` bound the accepted answer. `context` is the opaque
    /// continuation token.
    case field(
        type: InputType,
        secrecyLevel: SecrecyLevel,
        minLength: Int?,
        maxLength: Int?,
        context: InputContext
    )

    private enum Tag: String, CodingKey {
        case confirmation = "Confirmation"
        case selection = "Selection"
        case field = "Field"
    }

    private struct ConfirmationFields: Codable, Sendable {
        var context: ConfirmationContext
        var pollingDelay: TimeInterval?

        private enum CodingKeys: String, CodingKey {
            case context
            case pollingDelay = "pollingDelaySecs"
        }
    }
    private struct SelectionFields: Codable, Sendable {
        var options: [DialogOption]
        var context: InputContext
    }
    private struct FieldFields: Codable, Sendable {
        var type: InputType
        var secrecyLevel: SecrecyLevel
        var minLength: Int?
        var maxLength: Int?
        var context: InputContext

        private enum CodingKeys: String, CodingKey {
            case type, secrecyLevel, minLength, maxLength, context
        }
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: Tag.self)
        guard c.allKeys.count == 1, let tag = c.allKeys.first else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Expected one tag for DialogInput"
                )
            )
        }
        switch tag {
        case .confirmation:
            let f = try c.decode(ConfirmationFields.self, forKey: tag)
            self = .confirmation(context: f.context, pollingDelay: f.pollingDelay)
        case .selection:
            let f = try c.decode(SelectionFields.self, forKey: tag)
            self = .selection(options: f.options, context: f.context)
        case .field:
            let f = try c.decode(FieldFields.self, forKey: tag)
            self = .field(
                type: f.type,
                secrecyLevel: f.secrecyLevel,
                minLength: f.minLength,
                maxLength: f.maxLength,
                context: f.context
            )
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: Tag.self)
        switch self {
        case .confirmation(let ctx, let polling):
            try c.encode(
                ConfirmationFields(context: ctx, pollingDelay: polling),
                forKey: .confirmation
            )
        case .selection(let options, let ctx):
            try c.encode(SelectionFields(options: options, context: ctx), forKey: .selection)
        case .field(let type, let sec, let minLen, let maxLen, let ctx):
            try c.encode(
                FieldFields(
                    type: type,
                    secrecyLevel: sec,
                    minLength: minLen,
                    maxLength: maxLen,
                    context: ctx
                ),
                forKey: .field
            )
        }
    }
}
