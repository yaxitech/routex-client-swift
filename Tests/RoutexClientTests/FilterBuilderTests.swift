import Foundation
import RoutexModels
import Testing

/// Covers the public predicate builders used to compose `accounts` filters and
/// the `SearchFilter` wire encoding for every case. The live suites only
/// exercise a single search term, so the remaining builders are pinned here.
@Suite("Filter builders")
struct FilterBuilderTests {
    @Test("a predicate names both its field and its wire value")
    func predicateFields() {
        #expect(AccountPredicate.iban("DE").field == .iban)
        #expect(AccountPredicate.status(.available).field == .status)
        #expect(AccountPredicate.type(.current).field == .type)
    }

    @Test("and/or nest the operands left to right")
    func combinators() {
        let composed =
            AccountFilter.eq(.type(.current))
            .and(.supports(.collectPayment))
            .or(.notEq(.iban(nil)))
        #expect(
            composed
                == .or(
                    .and(.eq(.type(.current)), .supports(.collectPayment)),
                    .notEq(.iban(nil))
                )
        )
    }

    @Test("predicates round-trip through the [field, value] wire pair")
    func predicateWire() throws {
        func wire(_ filter: AccountFilter) throws -> String {
            String(decoding: try JSONEncoder().encode(filter), as: UTF8.self)
        }
        #expect(try wire(.eq(.iban("DE02"))) == #"{"Eq":["Iban","DE02"]}"#)
        #expect(try wire(.notEq(.iban(nil))) == #"{"NotEq":["Iban",null]}"#)
        #expect(try wire(.eq(.status(.available))) == #"{"Eq":["Status","Available"]}"#)

        for filter: AccountFilter in [
            .eq(.iban("DE02")), .notEq(.iban(nil)), .eq(.status(.available)),
            .eq(.type(.current)), .and(.eq(.currency("EUR")), .supports(.collectPayment)),
        ] {
            let data = try JSONEncoder().encode(filter)
            #expect(try JSONDecoder().decode(AccountFilter.self, from: data) == filter)
        }
    }

    @Test("ISODate accepts a calendar date and rejects anything else")
    func isoDateValidation() throws {
        #expect(try ISODate("2026-02-28").rawValue == "2026-02-28")
        #expect(try ISODate("2024-02-29").rawValue == "2024-02-29")  // leap year
        // "Int.init(_:)" accepts a leading sign, so signed components must
        // not slip through the length checks.
        for bad in [
            "2026-02-30", "2026-13-01", "2026-1-01", "26-01-01", "2026-01-01T00:00:00", "",
            "2026-+1-01", "+026-01-01",
        ] {
            #expect(throws: ISODateError.invalid(bad)) { try ISODate(bad) }
        }
    }

    @Test("ISODate resolves to an instant in the zone the caller names")
    func isoDateInZone() throws {
        let day = try ISODate("2026-03-15")
        let utc = day.date(in: TimeZone(identifier: "UTC")!)
        #expect(utc == Date(timeIntervalSince1970: 1_773_532_800))
        // A zone one hour ahead starts the day an hour earlier in absolute time.
        let berlin = day.date(in: TimeZone(identifier: "Europe/Berlin")!)
        #expect(utc.timeIntervalSince(berlin) == 3600)
    }

    @Test("a value outside the field's enum fails to decode")
    func predicateRejectsUnknownValue() {
        let data = Data(#"{"Eq":["Status","Nonsense"]}"#.utf8)
        #expect(throws: AccountPredicateDecodeError.unknownValue(field: .status, value: "Nonsense")) {
            try JSONDecoder().decode(AccountFilter.self, from: data)
        }
    }

    @Test("every SearchFilter case encodes under its wire tag")
    func searchFilterWire() throws {
        func wire(_ filter: SearchFilter) throws -> String {
            String(decoding: try JSONEncoder().encode(filter), as: UTF8.self)
        }
        #expect(try wire(.countries([CountryCode("DE")])) == #"{"countries":["DE"]}"#)
        #expect(try wire(.name("x")) == #"{"name":"x"}"#)
        #expect(try wire(.bic("BIC")) == #"{"bic":"BIC"}"#)
        #expect(try wire(.bankCode("10070000")) == #"{"bankCode":"10070000"}"#)
        #expect(try wire(.term("t")) == #"{"term":"t"}"#)
        #expect(try wire(.encryptedIBAN(Data([1, 2, 3]))) == #"{"encryptedIban":"AQID"}"#)
    }
}
