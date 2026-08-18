import Foundation

/// One ``Account`` field paired with the value to compare it against.
///
/// `nil` compares against JSON `null`, which the service reads as "the field
/// is absent".
public enum AccountPredicate: Sendable, Hashable {
    /// ISO 20022 IBAN2007Identifier.
    case iban(String?)
    /// Account number that is not an IBAN.
    case number(String?)
    /// ISO 20022 BICFIIdentifier.
    case bic(String?)
    /// National bank code.
    case bankCode(String?)
    /// ISO 4217 Alpha 3 currency code.
    case currency(String?)
    /// Name of the account, assigned by the ASPSP.
    case name(String?)
    /// Display name of the account, assigned by the PSU.
    case displayName(String?)
    /// Legal account owner.
    case ownerName(String?)
    /// Product name.
    case productName(String?)
    /// Account status.
    case status(AccountStatus?)
    /// Account type.
    case type(AccountType?)

    /// The field this predicate compares.
    public var field: AccountField {
        switch self {
        case .iban: return .iban
        case .number: return .number
        case .bic: return .bic
        case .bankCode: return .bankCode
        case .currency: return .currency
        case .name: return .name
        case .displayName: return .displayName
        case .ownerName: return .ownerName
        case .productName: return .productName
        case .status: return .status
        case .type: return .type
        }
    }

    /// Wire form of the compared value, `nil` for JSON `null`.
    var wireValue: String? {
        switch self {
        case .iban(let v), .number(let v), .bic(let v), .bankCode(let v),
            .currency(let v), .name(let v), .displayName(let v),
            .ownerName(let v), .productName(let v):
            return v
        case .status(let v): return v?.rawValue
        case .type(let v): return v?.rawValue
        }
    }

    /// Rebuild the predicate for `field` from a wire value. Throws when the
    /// value is not a member of the field's enum.
    static func from(field: AccountField, wireValue: String?) throws -> AccountPredicate {
        func decode<T: RawRepresentable<String>>(_ type: T.Type) throws -> T? {
            guard let wireValue else { return nil }
            guard let value = T(rawValue: wireValue) else {
                throw AccountPredicateDecodeError.unknownValue(field: field, value: wireValue)
            }
            return value
        }
        switch field {
        case .iban: return .iban(wireValue)
        case .number: return .number(wireValue)
        case .bic: return .bic(wireValue)
        case .bankCode: return .bankCode(wireValue)
        case .currency: return .currency(wireValue)
        case .name: return .name(wireValue)
        case .displayName: return .displayName(wireValue)
        case .ownerName: return .ownerName(wireValue)
        case .productName: return .productName(wireValue)
        case .status: return .status(try decode(AccountStatus.self))
        case .type: return .type(try decode(AccountType.self))
        }
    }
}

/// Raised while decoding an ``AccountPredicate`` whose value is not a member
/// of the field's enum.
public enum AccountPredicateDecodeError: Error, Sendable, Equatable {
    /// The wire value is not a case of the enum the field carries.
    case unknownValue(field: AccountField, value: String)
}
