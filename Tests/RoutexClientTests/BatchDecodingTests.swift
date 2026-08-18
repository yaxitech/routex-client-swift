import Foundation
import RoutexModels
import Testing

@Suite("Batch transaction details")
struct BatchDecodingTests {

    @Test("decodes an entry carrying only what the bank reported")
    func sparseEntry() throws {
        let json = Data(#"{"paymentId":"P1"}"#.utf8)
        let details = try JSONDecoder().decode(BatchTransactionDetails.self, from: json)
        #expect(details.paymentID == "P1")
        #expect(details.amount == nil)
        #expect(details.reversal == false)
        #expect(details.exchanges.isEmpty)
    }

    @Test("decodes a batch nested in a transaction")
    func nestedInTransaction() throws {
        let json = Data(
            """
            {"status":"Booked","amount":{"amount":"-12.34","currency":"EUR"},
             "batch":{"numberOfTransactions":2,"transactions":[
               {"endToEndId":"E1","amount":{"amount":"-2.34","currency":"EUR"}}]}}
            """.utf8
        )
        let transaction = try JSONDecoder().decode(Transaction.self, from: json)
        let entry = try #require(transaction.batch?.transactions.first)
        #expect(transaction.batch?.numberOfTransactions == 2)
        #expect(entry.endToEndID == "E1")
        #expect(entry.amount?.amount == Decimal(string: "-2.34"))
    }
}
