import Foundation

/// Ticket authorizing a single `RoutexClient.accounts(...)` call.
public struct AccountsTicket: RoutexTicket {
    public typealias ResultData = AccountsResult
    public let raw: String
    public let id: UUID

    /// Parse a backend-issued JWT for the accounts service. Validates the
    /// `data.service` claim matches `"Accounts"`.
    public init(_ raw: String) throws {
        self.raw = raw
        self.id = try TicketDecoder.parse(raw, expectingService: "Accounts")
    }
}

extension AccountsTicket: ServiceTicket {
    package static let servicePath = "accounts"
}
