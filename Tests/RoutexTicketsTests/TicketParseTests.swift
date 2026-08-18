import Foundation
import RoutexModels
import RoutexTickets
import Testing

/// Parse errors surfaced by the typed ticket initializers.
@Suite("Ticket parsing")
struct TicketParseTests {
    @Test("too few segments is a malformed JWT")
    func tooFewSegments() {
        #expect(throws: TicketParseError.malformedJWT) { _ = try AccountsTicket("nodots") }
    }

    @Test("a payload segment that is not base64url is a malformed JWT")
    func invalidBase64Payload() {
        #expect(throws: TicketParseError.malformedJWT) { _ = try AccountsTicket("h.!!!.s") }
    }

    @Test("a payload without the data claim is rejected")
    func missingDataClaim() {
        // "e30" is base64url for "{}".
        #expect(throws: TicketParseError.missingDataClaim) { _ = try AccountsTicket("h.e30.s") }
    }

    @Test("a ticket for another service is rejected")
    func wrongService() throws {
        let issuer = try RoutexTicketIssuer(apiKeyID: "k", apiKeySecret: Data("secret".utf8))
        let balances = try issuer.balances().raw
        #expect(throws: TicketParseError.wrongService(expected: "Accounts", actual: "Balances")) {
            _ = try AccountsTicket(balances)
        }
    }
}
