import Foundation

/// One ``Account`` field. Used both to project (request) fields on
/// `RoutexClient.accounts(...)` and to compose ``AccountFilter`` predicates.
public enum AccountField: String, Sendable, Hashable, Codable, CaseIterable {
    case iban = "Iban"
    case number = "Number"
    case bic = "Bic"
    case bankCode = "BankCode"
    case currency = "Currency"
    case name = "Name"
    case displayName = "DisplayName"
    case ownerName = "OwnerName"
    case productName = "ProductName"
    case status = "Status"
    case type = "Type"
}
