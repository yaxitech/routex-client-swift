import Foundation
import RoutexModels
import RoutexTickets

/// Shared call inputs for the live test suites.
enum DemoData {
    /// YAXI demo connection used for testing flows without a live bank
    /// integration. See https://docs.yaxi.tech for supported test
    /// `userID` values.
    static let demoConnection = ConnectionID(
        UUID(uuidString: "96386142-60E5-4CA9-ABCF-944EFCE5BC1E")!
    )

    /// IBAN of the YAXI demo account (sender side for transfers; the account
    /// the demo bank knows balances and transactions for).
    static let demoAccountIBAN = "DE02120300000000202051"

    /// Creditor IBAN for collect-payment tests (matches the Kotlin/Lua test
    /// suites' pinned creditor).
    static let collectPaymentCreditorIBAN = "DE79430609671288143100"

    /// Creditor IBAN for transfer tests (matches the Kotlin transfer test).
    static let transferCreditorIBAN = "NL58YAXI1234567890"

    /// Friendly name to attach to creditor account references.
    static let creditorName = "YAXI GmbH"

    /// Sample €1.00 payment payload.
    static let oneEuro = Amount(amount: Decimal(1), currency: "EUR")

    /// Standard collect-payment ticket: €1.00, debtor identification requested
    /// (returns debtorIBAN + debtorName from the bank).
    static func collectPaymentTicket(_ issuer: RoutexTicketIssuer) throws -> CollectPaymentTicket {
        try issuer.collectPayment(
            amount: oneEuro,
            creditorAccount: .iban(collectPaymentCreditorIBAN),
            creditorName: creditorName,
            remittance: "live-test",
            fields: [.debtorIBAN, .debtorName]
        )
    }

    /// Single SEPA credit transfer of €1.00 toward `transferCreditorIBAN`.
    static let transferDetails: [TransferDetails] = [
        TransferDetails(
            amount: oneEuro,
            creditorAccount: .iban(transferCreditorIBAN),
            creditorName: "creditor",
            remittance: "live-test"
        )
    ]

    /// Fixed historical window - matches the pinned start date the Kotlin
    /// online suite uses so the demo's transactions stay in scope.
    static let demoTransactionRange: TransactionsRange =
        .period(from: try! ISODate("2019-01-13"), to: nil)

    /// Bogus URL redirect callback used by `RoutexClient.setRedirectURI(_:)`
    /// and `registerRedirectURI(...)`.
    static let callbackURI = "smoketest://redirect"
}
