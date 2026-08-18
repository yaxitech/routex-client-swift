import Foundation

/// Context of a user dialog. Disambiguates the meaning of a ``Dialog`` so
/// UIs can render the right prompt.
public enum DialogContext: String, Sendable, Codable, Hashable, CaseIterable {
    /// SCA or TAN process.
    ///
    /// Distinguishable by the carried ``DialogInput``:
    /// - ``DialogInput/confirmation(context:pollingDelay:)``: decoupled
    ///   process (e.g. confirmation in a SCA app).
    /// - ``DialogInput/selection(options:context:)``: TAN method selection.
    /// - ``DialogInput/field(type:secrecyLevel:minLength:maxLength:context:)``:
    ///   TAN entry.
    case sca = "Sca"
    /// Account selection.
    ///
    /// A ``DialogInput/selection(options:context:)`` is returned with this
    /// context when an account has to be selected. There may be just a
    /// single option that may be chosen automatically without user
    /// interaction.
    case accounts = "Accounts"
    /// Pending redirect confirmation.
    ///
    /// A ``DialogInput/confirmation(context:pollingDelay:)`` is
    /// returned with this context when a redirect was confirmed but no
    /// result is known yet.
    case redirect = "Redirect"
    /// Pending SCT Inst payment.
    ///
    /// A ``DialogInput/confirmation(context:pollingDelay:)`` is
    /// returned with this context when an SCT Inst payment has been
    /// initialized but has not reached a final status yet.
    case paymentStatus = "PaymentStatus"
    /// Verification of Payee confirmation.
    ///
    /// A ``DialogInput/confirmation(context:pollingDelay:)`` is
    /// returned with this context when an explicit confirmation of the
    /// creditor is required due to a name mismatch. This confirmation has
    /// legal implications, releasing the bank from liabilities in case of
    /// a transfer to an unintended receiver due to incorrect creditor
    /// data.
    case vopConfirmation = "VopConfirmation"
    /// Pending Verification of Payee check.
    ///
    /// A ``DialogInput/confirmation(context:pollingDelay:)`` is
    /// returned with this context when a Verification of Payee check is
    /// still pending.
    case vopCheck = "VopCheck"
}
