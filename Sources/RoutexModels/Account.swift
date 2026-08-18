import Foundation

/// A bank account returned by the `accounts` service.
///
/// Every field is optional; what is populated depends on the connection and
/// the ``AccountField`` set passed to `RoutexClient.accounts(...)`.
public struct Account: Sendable, Hashable, Codable {
    /// ISO 20022 IBAN2007Identifier.
    public let iban: String?
    /// Account number that is not an IBAN, e.g. ISO 20022 BBANIdentifier or
    /// primary account number (PAN) of a card account.
    public let number: String?
    /// ISO 20022 BICFIIdentifier.
    public let bic: String?
    /// National bank code.
    public let bankCode: String?
    /// ISO 4217 Alpha 3 currency code.
    public let currency: String?
    /// Name of account, assigned by ASPSP.
    public let name: String?
    /// Display name of account, assigned by PSU.
    public let displayName: String?
    /// Legal account owner.
    public let ownerName: String?
    /// Product name.
    public let productName: String?
    /// Account status.
    public let status: AccountStatus?
    /// Account type.
    public let type: AccountType?

    /// Build an `Account` with the fields the caller knows. Any field left
    /// unset is omitted from the wire form.
    public init(
        iban: String? = nil,
        number: String? = nil,
        bic: String? = nil,
        bankCode: String? = nil,
        currency: String? = nil,
        name: String? = nil,
        displayName: String? = nil,
        ownerName: String? = nil,
        productName: String? = nil,
        status: AccountStatus? = nil,
        type: AccountType? = nil
    ) {
        self.iban = iban
        self.number = number
        self.bic = bic
        self.bankCode = bankCode
        self.currency = currency
        self.name = name
        self.displayName = displayName
        self.ownerName = ownerName
        self.productName = productName
        self.status = status
        self.type = type
    }
}
