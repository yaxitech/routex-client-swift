import Foundation

/// Boolean predicate over an ``Account``. Compose with ``and(_:)``,
/// ``or(_:)``, and ``supports(_:)`` to express richer queries.
public indirect enum AccountFilter: Sendable, Hashable {
    /// Matches accounts satisfying the predicate.
    case eq(AccountPredicate)
    /// Matches accounts not satisfying the predicate, so `.notEq(.iban(nil))`
    /// matches accounts that have an IBAN.
    case notEq(AccountPredicate)
    /// Matches accounts where both subfilters match.
    case and(AccountFilter, AccountFilter)
    /// Matches accounts where at least one subfilter matches.
    case or(AccountFilter, AccountFilter)
    /// Matches accounts capable of supporting a YAXI Open Banking service.
    case supports(SupportedService)
}

extension AccountFilter {
    /// Combine with another filter; both must match.
    public func and(_ other: AccountFilter) -> AccountFilter { .and(self, other) }
    /// Combine with an alternative filter; either must match.
    public func or(_ other: AccountFilter) -> AccountFilter { .or(self, other) }
}

extension AccountFilter: Codable {
    private enum Tag: String, CodingKey {
        case eq = "Eq"
        case notEq = "NotEq"
        case and = "And"
        case or = "Or"
        case supports = "Supports"
    }

    public init(from decoder: any Decoder) throws {
        var container = try decoder.container(keyedBy: Tag.self)
        guard container.allKeys.count == 1, let tag = container.allKeys.first else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription:
                        "Expected exactly one tag for AccountFilter; got \(container.allKeys)"
                )
            )
        }
        switch tag {
        case .eq:
            self = .eq(try Self.decodePredicate(&container, forKey: tag))
        case .notEq:
            self = .notEq(try Self.decodePredicate(&container, forKey: tag))
        case .and:
            var inner = try container.nestedUnkeyedContainer(forKey: tag)
            let l = try inner.decode(AccountFilter.self)
            let r = try inner.decode(AccountFilter.self)
            self = .and(l, r)
        case .or:
            var inner = try container.nestedUnkeyedContainer(forKey: tag)
            let l = try inner.decode(AccountFilter.self)
            let r = try inner.decode(AccountFilter.self)
            self = .or(l, r)
        case .supports:
            let s = try container.decode(SupportedService.self, forKey: tag)
            self = .supports(s)
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: Tag.self)
        switch self {
        case .eq(let predicate):
            try Self.encode(predicate, into: &container, forKey: .eq)
        case .notEq(let predicate):
            try Self.encode(predicate, into: &container, forKey: .notEq)
        case .and(let l, let r):
            var inner = container.nestedUnkeyedContainer(forKey: .and)
            try inner.encode(l)
            try inner.encode(r)
        case .or(let l, let r):
            var inner = container.nestedUnkeyedContainer(forKey: .or)
            try inner.encode(l)
            try inner.encode(r)
        case .supports(let s):
            try container.encode(s, forKey: .supports)
        }
    }

    /// Wire form of a predicate: a `[field, value]` pair.
    private static func encode(
        _ predicate: AccountPredicate,
        into container: inout KeyedEncodingContainer<Tag>,
        forKey key: Tag
    ) throws {
        var inner = container.nestedUnkeyedContainer(forKey: key)
        try inner.encode(predicate.field)
        try inner.encode(predicate.wireValue)
    }

    private static func decodePredicate(
        _ container: inout KeyedDecodingContainer<Tag>,
        forKey key: Tag
    ) throws -> AccountPredicate {
        var inner = try container.nestedUnkeyedContainer(forKey: key)
        let field = try inner.decode(AccountField.self)
        let value = try inner.decodeIfPresent(String.self)
        return try AccountPredicate.from(field: field, wireValue: value)
    }
}
