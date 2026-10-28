import Foundation
import RoutexModels
import Testing

@Suite("Standing orders")
struct StandingOrderDecodingTests {

    @Test("decodes a standing order with every field")
    func fullOrder() throws {
        let json = Data(
            """
            {"startDate":"2023-02-01","endDate":"2024-01-01","executionRule":"PrecedingWithinAMonth",
             "frequency":{"months":1},"day":1,"skimmingLimit":{"currency":"EUR","amount":"100"},
             "endToEndId":"E2E","amount":{"currency":"EUR","amount":"1000"},
             "creditor":{"name":"Stefanie Müller-Schmitt","iban":"DE89370400440532013000"},
             "debtor":{"name":"Max Mustermann"},"remittanceInformation":["Miete"],
             "purposeCode":"RINP","additionalInformation":"info"}
            """.utf8
        )
        let order = try JSONDecoder().decode(StandingOrder.self, from: json)
        #expect(order.startDate == (try ISODate("2023-02-01")))
        #expect(order.endDate == (try ISODate("2024-01-01")))
        #expect(order.executionRule == .precedingWithinAMonth)
        #expect(order.frequency == .months(1))
        #expect(order.day == 1)
        #expect(order.skimmingLimit == Amount(amount: 100, currency: "EUR"))
        #expect(order.endToEndID == "E2E")
        #expect(order.amount == Amount(amount: 1000, currency: "EUR"))
        #expect(order.creditor?.iban == "DE89370400440532013000")
        #expect(order.debtor?.name == "Max Mustermann")
        #expect(order.remittanceInformation == ["Miete"])
        #expect(order.purposeCode == "RINP")
        #expect(order.additionalInformation == "info")
    }

    @Test("decodes a sparse standing order")
    func sparseOrder() throws {
        let json = Data(#"{"startDate":"2023-02-01","amount":{"currency":"EUR","amount":"55.08"}}"#.utf8)
        let order = try JSONDecoder().decode(StandingOrder.self, from: json)
        #expect(order.frequency == nil)
        #expect(order.executionRule == nil)
        #expect(order.remittanceInformation.isEmpty)
        #expect(order.amount.amount == Decimal(string: "55.08"))
    }

    @Test(
        "decodes every frequency shape",
        arguments: [
            (#"{"days":14}"#, Frequency.days(14)),
            (#"{"months":3}"#, Frequency.months(3)),
            (#"{"variableMonths":[1,4,7,10]}"#, Frequency.variableMonths([.january, .april, .july, .october])),
        ]
    )
    func frequencies(json: String, expected: Frequency) throws {
        #expect(try JSONDecoder().decode(Frequency.self, from: Data(json.utf8)) == expected)
        let encoded = try JSONEncoder().encode(expected)
        #expect(try JSONDecoder().decode(Frequency.self, from: encoded) == expected)
    }

    @Test("months travel as numbers")
    func monthsAsNumbers() throws {
        let encoded = try JSONEncoder().encode(Frequency.variableMonths([.february, .december]))
        #expect(String(decoding: encoded, as: UTF8.self) == #"{"variableMonths":[2,12]}"#)
    }

    @Test("rejects an out-of-range month and a frequency without exactly one tag")
    func rejectsMalformedFrequency() {
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(Frequency.self, from: Data(#"{"variableMonths":[13]}"#.utf8))
        }
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(Frequency.self, from: Data(#"{"days":1,"months":1}"#.utf8))
        }
    }
}
