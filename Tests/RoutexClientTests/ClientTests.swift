import Foundation
import Testing

import Routex

let client = RoutexClient(url: URL(string: ProcessInfo.processInfo.environment["ROUTEX_URL"]!)!)

let demoConnectionId = "connection-96386142-60e5-4ca9-abcf-944efce5bc1e"
let demoAccountIban = "DE02120300000000202051"

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
    #expect(result.count > 20)
}

@Test func info() async throws {
    let (ticket: ticket, id: _) = try await issueTicket(service: "Accounts")
    let connectionId = "connection-9e5b1bab-e7de-4274-85f5-49f75f9527c4"
    let info = try await client.info(ticket: ticket, connectionId: connectionId)
    #expect(info == ConnectionInfo(id: connectionId,
                                   countries: ["DE"],
                                   displayName: "GLS Gemeinschaftsbank",
                                   credentials: CredentialsModel(full: true, userId: false, none: false),
                                   userId: "NetKey / Alias",
                                   password: "PIN",
                                   logoId: "gls"))
}

@Test func accountsWithRedirect() async throws {
    let (ticket: ticket, id: ticketId) = try await issueTicket(service: "Accounts")
    var response = try await client.accounts(
        credentials: Credentials(connectionId: demoConnectionId, userId: "redirect"),
        session: nil,
        recurringConsents: nil,
        ticket: ticket,
        fields: AccountField.all())
    var (url, context) = try await requireRedirectHandle(response) { handle, context in
        let url = try await client.registerRedirectUri(ticket: ticket, handle: handle, redirectUri: "https://yaxi.tech")
        return (url, context)
    }
    
    // Redirect not opened yet: should return a dialog with confirmation
    response = try await client.confirmAccounts(ticket: ticket, context: context)
    context = try await requireDialog(response) { dialog in
        guard case let .confirmation(context: context, pollingDelaySecs: pollingDelay) = dialog else {
            throw WrongCase(expected: "Confirmation", actual: dialog)
        }
        #expect(pollingDelay == 1)
        return context
    }
    
    // Open URL (which will redirect to the URL set above)
    let (_, redirectResponse) = try await URLSession.shared.data(from: url)
    if redirectResponse.url!.host == "redirect.yaxi.tech" {
        // This URL should be opened in the user's browser. This test doesn't
        // want to automate a browser, so it reimplements (badly!) what the
        // page would do. This can break at any time.
        var request = URLRequest(url: Url(string: "https://remux.yaxi.tech/redirect")!)
        request.httpMethod = "POST"
        request.httpBody = Data(redirectResponse.url!.query!.utf8)
        try await URLSession.shared.data(for: request)
    } else {
        #expect(redirectResponse.url == Url(string: "https://yaxi.tech/"))
    }

    // Confirmation should now return result
    response = try await client.confirmAccounts(ticket: ticket, context: context)
    guard case let .result(result: result) = response else {
        throw WrongCase(expected: "Result", actual: response)
    }
    let data = result.result.toData()
    #expect(UUID(uuidString: data.ticketId)! == ticketId)
    #expect(data.data == [Account(iban: demoAccountIban, bic: "BYLADEM1001", currency: "EUR", ownerName: "Dr. Peter Steiger")])
}

@Test func collectPayment() async throws {
    let (ticket: ticket, id: ticketId) = try await issueTicket(
        service: "CollectPayment",
        CollectPaymentData(amount: Amount(currency: "EUR", amount: "123.00"), creditorAccount: AccountIdentifier(iban: "NL89YAXI0000012345"), creditorName: "YAXI Test", remittance: "Test Suite payment"))
    let response = try await client.collectPayment(
        credentials: Credentials(connectionId: demoConnectionId, userId: "result"),
        session: nil,
        recurringConsents: nil,
        ticket: ticket)
    
    guard case let .result(result: result) = response else {
        throw WrongCase(expected: "Result", actual: response)
    }
    let data = result.result.toData()
    #expect(UUID(uuidString: data.ticketId)! == ticketId)
}

@Test func transfer() async throws {
    let (ticket: ticket, id: ticketId) = try await issueTicket(service: "Transfer")
    let response = try await client.transfer(
        credentials: Credentials(connectionId: demoConnectionId, userId: "result"),
        session: nil,
        recurringConsents: nil,
        ticket: ticket,
        product: .defaultSepaCreditTransfer,
        details: [TransferDetails(
            amount: Routex.Amount(
                currency: "EUR",
                amount: Decimal(string: "100.00")!),
            creditorAccount: .iban("NL58YAXI1234567890"),
            creditorName: "John Doe")],
        debtorAccount: AccountReference(
            id: .iban("NL58YAXI1234567890"),
            currency: "EUR"),
        debtorName: "Debtor")

    guard case let .result(result: result) = response else {
        throw WrongCase(expected: "Result", actual: response)
    }
    let data = result.result.toData()
    #expect(UUID(uuidString: data.ticketId)! == ticketId)
}
