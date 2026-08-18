import Foundation
import RoutexCore
import RoutexModels
import RoutexSettlement
import RoutexTransport

/// Swift client for the YAXI Open Banking non-interactive (refresh)
/// services: ``accounts(ticket:connectionData:fields:filter:session:)``,
/// ``balances(ticket:connectionData:accounts:session:)``, and
/// ``transactions(ticket:connectionData:session:)``, plus the discovery
/// endpoints ``info(ticket:connectionID:)`` and
/// ``search(ticket:filters:ibanDetection:limit:details:)``.
///
/// Use this to refresh data for an *already-consented* connection without
/// prompting the user. Versus the interactive `RoutexClient`:
///
/// - A `ConnectionData` envelope replaces the `Credentials` indirection. It
///   comes from a successful interactive flow (`result.connectionData`) and
///   is persisted by the caller.
/// - Each call returns a ``NonInteractiveResponse`` carrying the decoded
///   payload directly: no JWT envelope, no interrupt branches.
/// - Only the read services plus `info`/`search` are exposed; payment and
///   transfer flows are inherently interactive and live on `RoutexClient`.
///
/// The typical caller is a backend scheduling recurring refreshes.
///
/// By default, YAXI assumes calls happen outside any user session, and
/// banks apply strict limits on how often such refreshes may occur; once
/// exceeded, calls fail with `RoutexError.accessExceeded`. When the user
/// is in session instead (viewing your app, triggering a manual refresh),
/// those limits generally do not apply: construct the client with a
/// `UserInSession` so YAXI forwards the user's IP address to the bank.
///
/// ## Shared parameters
///
/// - `session` — opaque `Session` from a previous call in the same flow.
///
/// ## Errors
///
/// Service methods are `async throws` and surface failures as:
///
/// - `RoutexError` — typed server error, see
///   [the catalog](https://docs.yaxi.tech/errors.html).
/// - `RoutexClientError` — client-side issue (sealing, malformed response).
/// - `KeySettlementError` — the automatic TEE key settlement for the
///   ticket failed; thrown by the first service call that needs it.
/// - I/O errors from the underlying `HTTPTransport`.
///
/// Instances are safe to share; create one per `HTTPTransport` and reuse it.
public final class RoutexRefreshClient: Sendable {
    let core: RoutexClientCore
    let userInSession: UserInSession?

    /// Construct a client.
    ///
    /// - Parameters:
    ///   - baseURL: Base URL of the YAXI API. Defaults to the production
    ///     endpoint.
    ///   - transport: HTTP transport. Defaults to a `URLSession`-backed
    ///     transport.
    ///   - userInSession: Indicates a user is in session for every service
    ///     call this client makes, lifting the bank's limit on requests
    ///     without one (see `UserInSession`). `nil` (default) makes calls
    ///     without a user in session.
    public init(
        baseURL: URL = URL(string: "https://api.yaxi.tech")!,
        transport: any HTTPTransport = URLSessionTransport(),
        userInSession: UserInSession? = nil
    ) {
        let factory: SettlementCoreFactory = { _ in
            Settlement(baseURL: baseURL, transport: transport)
        }
        self.core = RoutexClientCore(
            baseURL: baseURL,
            transport: transport,
            settlementFactory: factory
        )
        self.userInSession = userInSession
    }

    init(core: RoutexClientCore, userInSession: UserInSession? = nil) {
        self.core = core
        self.userInSession = userInSession
    }

    /// Authenticated TEE system version learned during settlement of
    /// `ticket`'s key-settlement session. Returns `nil` if no service call
    /// has been issued for that ticket yet.
    public func systemVersion(for ticket: some RoutexTicket) async -> SystemVersionEntry? {
        await core.systemVersion(for: ticket)
    }

    // MARK: - Discovery

    /// Fetch metadata for a single service connection.
    ///
    /// - Parameters:
    ///   - ticket: Any service ticket; the call is authorized by its
    ///     settlement.
    ///   - connectionID: The connection to look up.
    public func info(
        ticket: some RoutexTicket,
        connectionID: ConnectionID
    ) async throws -> ConnectionInfo {
        try await core.info(ticket: ticket, connectionID: connectionID)
    }

    /// Search for service connections (banks and other providers).
    /// Returns connections that match every entry in `filters`.
    ///
    /// - Parameters:
    ///   - ticket: Any service ticket; the call is authorized by its
    ///     settlement.
    ///   - filters: Conjunctive filter set. An empty list matches
    ///     nothing, so pass at least one filter.
    ///   - ibanDetection: When `true`, `SearchFilter.term(_:)` values that
    ///     look like an IBAN also yield connections matching the IBAN's bank
    ///     code, on top of the regular text matches.
    ///   - limit: Maximum number of results; must not be negative. `nil`
    ///     (default) leaves the server-side cap in effect.
    ///   - details: Extra per-connection details to populate.
    /// - Throws: `SearchError.negativeLimit(_:)` when `limit` is negative.
    public func search(
        ticket: some RoutexTicket,
        filters: [SearchFilter],
        ibanDetection: Bool = false,
        limit: Int? = nil,
        details: [ConnectionDetails] = []
    ) async throws -> [ConnectionInfo] {
        try await core.search(
            ticket: ticket,
            filters: filters,
            ibanDetection: ibanDetection,
            limit: limit,
            details: details
        )
    }

    // MARK: - Services

    /// Refresh accounts (and selected fields) for the connection encoded in
    /// `connectionData`.
    ///
    /// - Parameters:
    ///   - ticket: Backend-issued `AccountsTicket` authorizing the call.
    ///   - connectionData: Envelope returned by a successful interactive
    ///     accounts flow on `RoutexClient`.
    ///   - fields: Fields to populate on each returned account.
    ///   - filter: Optional account filter (AND/OR/NOT predicates over
    ///     `AccountPredicate`s).
    ///   - session: Optional `Session` returned by a previous call in the
    ///     same flow.
    /// - SeeAlso: [Accounts service reference](https://docs.yaxi.tech/accounts.html)
    public func accounts(
        ticket: AccountsTicket,
        connectionData: ConnectionData,
        fields: [AccountField],
        filter: AccountFilter? = nil,
        session: Session? = nil
    ) async throws -> NonInteractiveResponse<[Account]> {
        let body = NonInteractiveAccountsBody(
            connectionData: connectionData,
            session: session,
            userInSession: userInSession,
            fields: fields,
            filter: filter
        )
        return try await send(ticket: ticket, path: "accounts/non-interactive", body: body)
    }

    /// Refresh current balances for `accounts` under `connectionData`.
    ///
    /// - Parameters:
    ///   - ticket: Backend-issued `BalancesTicket` authorizing the call.
    ///   - connectionData: Envelope from a successful interactive flow.
    ///   - accounts: Accounts to fetch balances for.
    ///   - session: Optional `Session` returned by a previous call in the
    ///     same flow.
    /// - SeeAlso: [Balances service reference](https://docs.yaxi.tech/balances.html)
    public func balances(
        ticket: BalancesTicket,
        connectionData: ConnectionData,
        accounts: [AccountReference],
        session: Session? = nil
    ) async throws -> NonInteractiveResponse<Balances> {
        let body = NonInteractiveBalancesBody(
            connectionData: connectionData,
            session: session,
            userInSession: userInSession,
            accounts: accounts
        )
        return try await send(ticket: ticket, path: "balances/non-interactive", body: body)
    }

    /// Refresh booked-and-pending transactions for `connectionData`.
    ///
    /// `result` is `nil` when the bank returned no transaction list at all
    /// and an empty array when it returned an empty list.
    ///
    /// - Parameters:
    ///   - ticket: Backend-issued `TransactionsTicket` authorizing the call.
    ///     The account and date range are baked into the ticket.
    ///   - connectionData: Envelope from a successful interactive flow.
    ///   - session: Optional `Session` returned by a previous call in the
    ///     same flow.
    /// - SeeAlso: [Transactions service reference](https://docs.yaxi.tech/transactions.html)
    public func transactions(
        ticket: TransactionsTicket,
        connectionData: ConnectionData,
        session: Session? = nil
    ) async throws -> NonInteractiveResponse<[Transaction]?> {
        let body = NonInteractiveTransactionsBody(
            connectionData: connectionData,
            session: session,
            userInSession: userInSession
        )
        return try await send(ticket: ticket, path: "transactions/non-interactive", body: body)
    }

    private func send<Payload: Sendable & Decodable, Body: Encodable>(
        ticket: some RoutexTicket,
        path: String,
        body: Body
    ) async throws -> NonInteractiveResponse<Payload> {
        let payload = try WireEncoding.encode(body)
        let bytes = try await core.request(ticket: ticket, path: path, body: payload)
        return try WireEncoding.decode(NonInteractiveResponse<Payload>.self, from: bytes)
    }
}
