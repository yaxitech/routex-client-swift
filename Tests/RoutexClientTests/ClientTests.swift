import Foundation
import Testing

import Routex

let client = RoutexClient(url: URL(string: "https://routex-test.yaxi.tech")!)

let demoConnectionId = "connection-96386142-60e5-4ca9-abcf-944efce5bc1e"
let demoAccountIban = "NL58YAXI1234567890"

extension AccountField {
    static func all() -> [Self] {
        return [
            .bankCode,
            .bic,
            .currency,
            .displayName,
            .iban,
            .name,
            .number,
            .ownerName,
            .productName,
            .status,
            .type,
        ]
    }
}

@Test func search() async throws {
    let (ticket: ticket, id: _) = try await issueTicket(service: "Accounts")
    let result = try await client.search(
        ticket: ticket,
        filters: [.term(term: "sparkasse"), .term(term: "stadt")],
        ibanDetection: true)
    #expect(result.allSatisfy { $0.logoId == "sparkasse" })
    #expect(result.count > 70)
}

@Test func info() async throws {
    let (ticket: ticket, id: _) = try await issueTicket(service: "Accounts")
    let connectionId = "connection-9e5b1bab-e7de-4274-85f5-49f75f9527c4"
    let info = try await client.info(ticket: ticket, connectionId: connectionId)
    #expect(info == ConnectionInfo(id: connectionId,
                                   displayName: "GLS Gemeinschaftsbank",
                                   credentials: CredentialsModel(full: true, userId: false, none: false),
                                   userId: "NetKey / Alias",
                                   logoId: "gls"))
}

@Test func accountsWithRedirect() async throws {
    let (ticket: ticket, id: ticketId) = try await issueTicket(service: "Accounts")
    var response = try await client.accounts(
        credentials: Credentials(connectionId: demoConnectionId, userId: "redirect"),
        session: nil,
        ticket: ticket,
        fields: AccountField.all())
    var (url, context) = try await requireRedirectHandle(response) { handle, context in
        let url = try await client.registerRedirectUri(ticket: ticket, handle: handle, redirectUri: "https://yaxi.tech")
        return (url, context)
    }
    
    // Redirect not opened yet: should return a dialog with confirmation
    response = try await client.confirmAccounts(ticket: ticket, context: context)
    context = try await requireDialog(response) { dialog in
        guard case let .confirmation(context: context) = dialog else {
            throw WrongCase(expected: "Confirmation", actual: dialog)
        }
        return context
    }
    
    // Open URL (which will redirect to the URL set above)
    let (_, redirectResponse) = try await URLSession.shared.data(from: url)
    #expect(redirectResponse.url == Url(string: "https://yaxi.tech/"))
    
    // Confirmation should now return result
    response = try await client.confirmAccounts(ticket: ticket, context: context)
    guard case let .result(result: result) = response else {
        throw WrongCase(expected: "Result", actual: response)
    }
    let data = result.result.toData()
    #expect(data.ticketId == ticketId)
    #expect(data.data == [Account(iban: demoAccountIban, currency: "EUR")])
}

@Test func collectPayment() async throws {
    let (ticket: ticket, id: ticketId) = try await issueTicket(
        service: "CollectPayment",
        CollectPaymentData(amount: Amount(currency: "EUR", amount: "123.00"), creditorAccount: AccountIdentifier(iban: "NL89YAXI0000012345"), creditorName: "YAXI Test", remittance: "Test Suite payment"))
    let response = try await client.collectPayment(
        credentials: Credentials(connectionId: demoConnectionId, userId: "result"),
        session: nil,
        ticket: ticket)
    
    guard case let .result(result: result) = response else {
        throw WrongCase(expected: "Result", actual: response)
    }
    let data = result.result.toData()
    #expect(data.ticketId == ticketId)
}
