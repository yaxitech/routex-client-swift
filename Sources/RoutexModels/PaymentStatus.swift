import Foundation

/// Status reported by the bank for an initiated payment.
public enum PaymentStatus: String, Sendable, Codable, Hashable, CaseIterable {
    /// The payment was received and is getting processed.
    ///
    /// Especially without realtime bookings this is often the final status
    /// reported by the ASPSP.
    case accepted = "Accepted"
    /// The payment was partially accepted, i.e. only some of the
    /// transactions of a bulk payment, or the payment needs further
    /// authorization.
    case partiallyAccepted = "PartiallyAccepted"
    /// Settlement on the debtor's account has been completed.
    case completedDebtor = "CompletedDebtor"
    /// Settlement on the creditor's account has been completed.
    case completedCreditor = "CompletedCreditor"
}
