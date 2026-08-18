import Foundation
import RoutexCore
import RoutexModels
import RoutexSettlement
import RoutexTransport

/// Swift client for the YAXI Open Banking
/// [interactive services](https://docs.yaxi.tech/interrupts.html).
///
/// Each call is authorized by a typed `RoutexTicket` (e.g.
/// `AccountsTicket`) issued by the caller's backend and returns a typed
/// `Response`. A `.result` carries the typed payload as a JWT; the other
/// variants — `.dialog`, `.redirect`, `.redirectHandle` — are interrupts
/// the caller resolves before the flow can complete.
///
/// ## Resolving interrupts
///
/// - `.dialog` — present `dialog.input` to the user, then call the
///   per-service `respond` method (user typed or selected an answer) or
///   `confirm` method (user just confirms) with the input's `context`.
/// - `.redirect` — open `redirect.url`, then call the per-service
///   `confirm` method with `redirect.context`.
/// - `.redirectHandle` — call ``registerRedirectURI(ticket:handle:redirectURI:)``
///   to materialize the URL, open it, then confirm with
///   `redirectHandle.context`. Setting a default redirect URI via
///   ``setRedirectURI(_:)`` turns subsequent interrupts into `.redirect`
///   directly.
///
/// Loop until `.result`.
///
/// ## Handling the result
///
/// - Forward `result.authenticated.jwt` to your backend and verify the
///   signature with your YAXI API secret.
///   `Authenticated.decodeUnverified()` is available for client-only
///   display; never trust it for security-sensitive decisions.
/// - Persist `result.connectionData` and replay it via
///   `Credentials.connectionData` on later calls to skip prompts the
///   original consent already covers.
/// - Pass `result.session` to subsequent calls in the same flow.
///
/// ## Running without credentials
///
/// The accounts, balances, and transactions services also accept
/// `connectionData:` in place of `credentials:`, running against the
/// consent an earlier flow established and assuming the user is in
/// session on the connection. The response is a regular `Response`, so
/// interrupts stay possible; a request the bank will not serve without
/// authenticating the user fails with `RoutexError.interruptError`.
/// `recurringConsents` has no counterpart here, as no consent gets
/// established.
///
/// ## Shared parameters
///
/// - `session` — opaque `Session` from a previous call in the same flow.
/// - `recurringConsents` — when `true`, request a long-lived consent so
///   the returned `ConnectionData` can be replayed on later calls until
///   the consent expires. Default `false` is a one-shot consent.
///
/// ## Errors
///
/// Service methods are `async throws` and surface failures as:
///
/// - `RoutexError` — typed server error, see
///   [the catalog](https://docs.yaxi.tech/errors.html).
/// - `RoutexClientError` — client-side issue (sealing, malformed
///   response). Report incident-grade cases with the ``traceID``.
/// - `KeySettlementError` — the automatic TEE key settlement for the
///   ticket failed (attestation, system version, or handshake); thrown
///   by the first service call that needs it.
/// - `AuthenticatedDecodeError` — thrown by `decodeUnverified()` when
///   the JWT cannot be split into base64url segments; a payload that
///   does not match the expected shape throws `DecodingError`.
/// - I/O errors from the underlying `HTTPTransport`.
///
/// ## Topics
///
/// ### Services
///
/// - ``accounts(ticket:credentials:fields:filter:session:recurringConsents:)``
/// - ``balances(ticket:credentials:accounts:session:recurringConsents:)``
/// - ``transactions(ticket:credentials:session:recurringConsents:)``
/// - ``collectPayment(ticket:credentials:account:session:recurringConsents:)``
/// - ``transfer(ticket:credentials:product:details:debtorAccount:debtorName:requestedExecutionDate:session:recurringConsents:)``
///
/// ### Services without credentials
///
/// - ``accounts(ticket:connectionData:fields:filter:session:)``
/// - ``balances(ticket:connectionData:accounts:session:)``
/// - ``transactions(ticket:connectionData:session:)``
///
/// ### Continuing an interrupt
///
/// - ``confirmAccounts(ticket:context:)``
/// - ``respondAccounts(ticket:context:response:)``
/// - ``confirmBalances(ticket:context:)``
/// - ``respondBalances(ticket:context:response:)``
/// - ``confirmTransactions(ticket:context:)``
/// - ``respondTransactions(ticket:context:response:)``
/// - ``confirmCollectPayment(ticket:context:)``
/// - ``respondCollectPayment(ticket:context:response:)``
/// - ``confirmTransfer(ticket:context:)``
/// - ``respondTransfer(ticket:context:response:)``
/// - ``setRedirectURI(_:)``
/// - ``registerRedirectURI(ticket:handle:redirectURI:)``
///
/// ### Discovery
///
/// - ``info(ticket:connectionID:)``
/// - ``search(ticket:filters:ibanDetection:limit:details:)``
///
/// ### Diagnostics
///
/// - ``traceID``
/// - ``trace(ticket:traceID:)``
/// - ``systemVersion(for:)``
public final class RoutexClient: Sendable {
    let core: RoutexClientCore

    /// Construct a client.
    ///
    /// - Parameters:
    ///   - baseURL: Base URL of the YAXI API. Defaults to the production
    ///     endpoint.
    ///   - transport: HTTP transport. Defaults to a `URLSession`-backed
    ///     transport.
    public init(
        baseURL: URL = URL(string: "https://api.yaxi.tech")!,
        transport: any HTTPTransport = URLSessionTransport()
    ) {
        let factory: SettlementCoreFactory = { _ in
            Settlement(baseURL: baseURL, transport: transport)
        }
        self.core = RoutexClientCore(
            baseURL: baseURL,
            transport: transport,
            settlementFactory: factory
        )
    }

    init(core: RoutexClientCore) {
        self.core = core
    }

    /// Trace identifier returned with the most recent request, if any.
    /// Forward to ``trace(ticket:traceID:)`` with a matching ticket to
    /// retrieve the raw server-side trace; useful when reporting a failed
    /// request to YAXI support.
    public var traceID: TraceID? {
        get async { await core.traceID }
    }

    /// Set the redirect URI for subsequent service requests, or pass
    /// `nil` to clear it.
    ///
    /// When set, the server returns `Response.redirect(_:)`
    /// with the fully-formed landing URL the user can be sent to. When
    /// unset, the server returns
    /// `Response.redirectHandle(_:)` instead and the
    /// caller must call ``registerRedirectURI(ticket:handle:redirectURI:)``
    /// to obtain the URL.
    ///
    /// The string is forwarded to the server verbatim; the server is the
    /// authority on what it accepts.
    public func setRedirectURI(_ uri: String?) async {
        await core.setRedirectURI(uri)
    }

    /// Authenticated TEE system version learned during settlement of
    /// `ticket`'s key-settlement session. Returns `nil` if no service
    /// call has been issued for that ticket yet.
    ///
    /// The value lets a caller verify YAXI's confidential-computing
    /// promises post-hoc by mapping the reported measurement back to an
    /// audited build of the routex service.
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
    ///   - ibanDetection: When `true`, `SearchFilter.term(_:)`
    ///     values that look like an IBAN (e.g. `NL58YAXI1234567890`) also
    ///     yield connections matching the IBAN's bank code, on top of the
    ///     regular text matches.
    ///   - limit: Maximum number of results; must not be negative. `nil`
    ///     (default) leaves the server-side cap in effect.
    ///   - details: Extra per-connection details to populate (e.g.
    ///     `ConnectionDetails.bics`).
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

    /// Retrieve raw trace data for a `traceID` emitted by a prior request.
    ///
    /// Useful when reporting an incident to YAXI support: the trace id is
    /// typically read from ``traceID`` right after a failure, then
    /// exchanged here for the server-side trace text. See the
    /// [diagnostics reference](https://docs.yaxi.tech/diagnostics.html)
    /// for what YAXI records per service call.
    public func trace(
        ticket: some RoutexTicket,
        traceID: TraceID
    ) async throws -> String {
        let sealed = try await core.seal(ticket: ticket, plaintext: traceID.bytes)
        let encoded = sealed.base64URLEncodedString
        let bytes = try await core.request(
            ticket: ticket,
            path: "traces/\(encoded)",
            body: nil
        )
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Finalize a `Response.redirectHandle(_:)` by
    /// registering `redirectURI` as the landing URI for `handle`.
    ///
    /// - Returns: URL the user should be sent to. Open it in a browser,
    ///   deep-link target, or web view; after the user returns, continue
    ///   the flow with the per-service `confirm` method and the redirect
    ///   handle's context.
    public func registerRedirectURI(
        ticket: some RoutexTicket,
        handle: String,
        redirectURI: String
    ) async throws -> URL {
        let body = try WireEncoding.encode(
            RegisterRedirectBody(handle: handle, redirectURI: redirectURI)
        )
        let bytes = try await core.request(
            ticket: ticket,
            path: "redirects",
            body: body
        )
        let envelope: RedirectsResponse
        do {
            envelope = try WireEncoding.decode(RedirectsResponse.self, from: bytes)
        } catch {
            throw RoutexClientError.malformedResponse(
                message: "redirects response: \(error)",
                underlying: nil
            )
        }
        guard let url = URL(string: envelope.redirectURL) else {
            throw RoutexClientError.malformedResponse(
                message: "invalid URL: \(envelope.redirectURL)",
                underlying: nil
            )
        }
        return url
    }

    // MARK: - Service entry points

    /// Invoke the [accounts service](https://docs.yaxi.tech/accounts.html):
    /// list accounts (and selected fields) reachable through `credentials`.
    ///
    /// - Parameters:
    ///   - ticket: Backend-issued `AccountsTicket` authorizing the call.
    ///   - credentials: User credentials envelope (see `Credentials`).
    ///   - fields: Fields to populate on each returned account.
    ///   - filter: Optional account filter (for example by IBAN, currency,
    ///     supported services). Compose AND/OR/NOT predicates from
    ///     `AccountPredicate`s.
    ///   - session: Optional `Session` returned by a previous call in the
    ///     same flow.
    ///   - recurringConsents: When `true`, request a long-lived consent
    ///     so the returned `ConnectionData` can be replayed on later
    ///     calls.
    public func accounts(
        ticket: AccountsTicket,
        credentials: Credentials,
        fields: [AccountField],
        filter: AccountFilter? = nil,
        session: Session? = nil,
        recurringConsents: Bool = false
    ) async throws -> Response<AccountsResult> {
        let body = AccountsRequestBody(
            credentials: credentials,
            session: session,
            recurringConsents: recurringConsents ? true : nil,
            fields: fields,
            filter: filter
        )
        return try await execute(ticket: ticket, path: "accounts/service", body: body)
    }

    /// Invoke the [accounts service](https://docs.yaxi.tech/accounts.html)
    /// against an already-consented connection, without credentials.
    ///
    /// - Parameters:
    ///   - ticket: Backend-issued `AccountsTicket` authorizing the call.
    ///   - connectionData: Envelope from an earlier flow's
    ///     `result.connectionData`.
    ///   - fields: Fields to populate on each returned account.
    ///   - filter: Optional account filter (for example by IBAN, currency,
    ///     supported services). Compose AND/OR/NOT predicates from
    ///     `AccountPredicate`s.
    ///   - session: Optional `Session` returned by a previous call in the
    ///     same flow.
    public func accounts(
        ticket: AccountsTicket,
        connectionData: ConnectionData,
        fields: [AccountField],
        filter: AccountFilter? = nil,
        session: Session? = nil
    ) async throws -> Response<AccountsResult> {
        let body = AccountsConnectionDataBody(
            connectionData: connectionData,
            session: session,
            fields: fields,
            filter: filter
        )
        return try await execute(ticket: ticket, path: "accounts/service", body: body)
    }

    /// Invoke the [balances service](https://docs.yaxi.tech/balances.html):
    /// fetch current balances for `accounts`.
    ///
    /// - Parameters:
    ///   - ticket: Backend-issued `BalancesTicket` authorizing the call.
    ///   - credentials: User credentials envelope (see `Credentials`).
    ///   - accounts: Accounts to fetch balances for.
    ///   - session: Optional `Session` returned by a previous call in the
    ///     same flow.
    ///   - recurringConsents: When `true`, request a long-lived consent
    ///     so the returned `ConnectionData` can be replayed on later
    ///     calls.
    public func balances(
        ticket: BalancesTicket,
        credentials: Credentials,
        accounts: [AccountReference],
        session: Session? = nil,
        recurringConsents: Bool = false
    ) async throws -> Response<BalancesResult> {
        let body = BalancesRequestBody(
            credentials: credentials,
            session: session,
            recurringConsents: recurringConsents ? true : nil,
            accounts: accounts
        )
        return try await execute(ticket: ticket, path: "balances/service", body: body)
    }

    /// Invoke the [balances service](https://docs.yaxi.tech/balances.html)
    /// against an already-consented connection, without credentials.
    ///
    /// - Parameters:
    ///   - ticket: Backend-issued `BalancesTicket` authorizing the call.
    ///   - connectionData: Envelope from an earlier flow's
    ///     `result.connectionData`.
    ///   - accounts: Accounts to fetch balances for.
    ///   - session: Optional `Session` returned by a previous call in the
    ///     same flow.
    public func balances(
        ticket: BalancesTicket,
        connectionData: ConnectionData,
        accounts: [AccountReference],
        session: Session? = nil
    ) async throws -> Response<BalancesResult> {
        let body = BalancesConnectionDataBody(
            connectionData: connectionData,
            session: session,
            accounts: accounts
        )
        return try await execute(ticket: ticket, path: "balances/service", body: body)
    }

    /// Invoke the
    /// [transactions service](https://docs.yaxi.tech/transactions.html):
    /// fetch the booked-and-pending transaction list authorized by
    /// `credentials`.
    ///
    /// - Parameters:
    ///   - ticket: Backend-issued `TransactionsTicket` authorizing the
    ///     call. The account and date range are baked into the ticket.
    ///   - credentials: User credentials envelope (see `Credentials`).
    ///   - session: Optional `Session` returned by a previous call in the
    ///     same flow.
    ///   - recurringConsents: When `true`, request a long-lived consent
    ///     so the returned `ConnectionData` can be replayed on later
    ///     calls.
    public func transactions(
        ticket: TransactionsTicket,
        credentials: Credentials,
        session: Session? = nil,
        recurringConsents: Bool = false
    ) async throws -> Response<TransactionsResult> {
        let body = TransactionsRequestBody(
            credentials: credentials,
            session: session,
            recurringConsents: recurringConsents ? true : nil
        )
        return try await execute(ticket: ticket, path: "transactions/service", body: body)
    }

    /// Invoke the
    /// [transactions service](https://docs.yaxi.tech/transactions.html)
    /// against an already-consented connection, without credentials.
    ///
    /// - Parameters:
    ///   - ticket: Backend-issued `TransactionsTicket` authorizing the
    ///     call. The account and date range are baked into the ticket.
    ///   - connectionData: Envelope from an earlier flow's
    ///     `result.connectionData`.
    ///   - session: Optional `Session` returned by a previous call in the
    ///     same flow.
    public func transactions(
        ticket: TransactionsTicket,
        connectionData: ConnectionData,
        session: Session? = nil
    ) async throws -> Response<TransactionsResult> {
        let body = TransactionsConnectionDataBody(
            connectionData: connectionData,
            session: session
        )
        return try await execute(ticket: ticket, path: "transactions/service", body: body)
    }

    /// Invoke the
    /// [collect-payment service](https://docs.yaxi.tech/collect-payment.html):
    /// identify the debtor and prepare a payment-initiation flow.
    ///
    /// - Parameters:
    ///   - ticket: Backend-issued `CollectPaymentTicket` authorizing the
    ///     call. The amount, creditor, and remittance are baked into the
    ///     ticket.
    ///   - credentials: User credentials envelope (see `Credentials`).
    ///   - account: Optional debtor account to collect from. Pick a
    ///     `DebtorAccountIdentifier` variant: `.iban` for a plaintext
    ///     IBAN, or `.encryptedIBAN` for a ciphertext your backend
    ///     produced with its API secret following the
    ///     [Opaque Data](https://docs.yaxi.tech/opaque-data.html) protocol
    ///     so the frontend never sees the underlying IBAN. Providing
    ///     `account` reduces the chance of an account-selection prompt;
    ///     omitting it may surface one (bank-dependent).
    ///   - session: Optional `Session` returned by a previous call in the
    ///     same flow.
    ///   - recurringConsents: When `true`, request a long-lived consent
    ///     so the returned `ConnectionData` can be replayed on later
    ///     calls.
    public func collectPayment(
        ticket: CollectPaymentTicket,
        credentials: Credentials,
        account: DebtorAccountReference? = nil,
        session: Session? = nil,
        recurringConsents: Bool = false
    ) async throws -> Response<CollectPaymentResult> {
        let body = CollectPaymentRequestBody(
            credentials: credentials,
            session: session,
            recurringConsents: recurringConsents ? true : nil,
            account: account
        )
        return try await execute(ticket: ticket, path: "collect-payment/service", body: body)
    }

    /// Invoke the [transfer service](https://docs.yaxi.tech/transfer.html):
    /// initiate a credit transfer for `product` with the given `details`.
    ///
    /// - Parameters:
    ///   - ticket: Backend-issued `TransferTicket` authorizing the call.
    ///   - credentials: User credentials envelope (see `Credentials`).
    ///   - product: The payment product (e.g. SEPA credit transfer).
    ///   - details: Transfer line items (creditor, amount, remittance
    ///     information).
    ///   - debtorAccount: Optional debtor account; the bank prompts the
    ///     user when omitted.
    ///   - debtorName: Optional debtor name to display in the
    ///     confirmation flow.
    ///   - requestedExecutionDate: Optional future execution date;
    ///     same-day execution is requested when omitted.
    ///   - session: Optional `Session` returned by a previous call in the
    ///     same flow.
    ///   - recurringConsents: When `true`, request a long-lived consent
    ///     so the returned `ConnectionData` can be replayed on later
    ///     calls.
    public func transfer(
        ticket: TransferTicket,
        credentials: Credentials,
        product: PaymentProduct,
        details: [TransferDetails],
        debtorAccount: DebtorAccountReference? = nil,
        debtorName: String? = nil,
        requestedExecutionDate: ISODateTimeOrDate? = nil,
        session: Session? = nil,
        recurringConsents: Bool = false
    ) async throws -> Response<TransferResult> {
        let body = TransferRequestBody(
            credentials: credentials,
            session: session,
            recurringConsents: recurringConsents ? true : nil,
            product: product,
            debtorAccount: debtorAccount,
            debtorName: debtorName,
            requestedExecutionDate: requestedExecutionDate,
            details: details
        )
        return try await execute(ticket: ticket, path: "transfer/service", body: body)
    }

    // MARK: - Per-service interrupt continuations

    /// Continue an `accounts` flow paused on a confirmation
    /// `Response.dialog(_:)`, `Response.redirect(_:)`, or
    /// `Response.redirectHandle(_:)`.
    ///
    /// - Parameters:
    ///   - ticket: The same `AccountsTicket` that returned the prior
    ///     response.
    ///   - context: `ConfirmationContext` taken from the
    ///     `Response.dialog(_:)`, `Response.redirect(_:)`, or
    ///     `Response.redirectHandle(_:)` returned by the prior call.
    public func confirmAccounts(
        ticket: AccountsTicket,
        context: ConfirmationContext
    ) async throws -> Response<AccountsResult> {
        try await resume(ticket: ticket, context: context)
    }

    /// Continue an `accounts` flow by submitting the user's answer to a
    /// `Response.dialog(_:)`.
    ///
    /// - Parameters:
    ///   - ticket: The same `AccountsTicket` that returned the dialog.
    ///   - context: `InputContext` taken from the dialog's input on the
    ///     prior `Response.dialog(_:)`.
    ///   - response: The user's answer; see `DialogInput` for the format
    ///     expected by each input variant.
    public func respondAccounts(
        ticket: AccountsTicket,
        context: InputContext,
        response: String
    ) async throws -> Response<AccountsResult> {
        try await resume(ticket: ticket, context: context, response: response)
    }

    /// Continue a `balances` flow paused on a confirmation
    /// `Response.dialog(_:)`, `Response.redirect(_:)`, or
    /// `Response.redirectHandle(_:)`.
    ///
    /// - Parameters:
    ///   - ticket: The same `BalancesTicket` that returned the prior
    ///     response.
    ///   - context: `ConfirmationContext` taken from the
    ///     `Response.dialog(_:)`, `Response.redirect(_:)`, or
    ///     `Response.redirectHandle(_:)` returned by the prior call.
    public func confirmBalances(
        ticket: BalancesTicket,
        context: ConfirmationContext
    ) async throws -> Response<BalancesResult> {
        try await resume(ticket: ticket, context: context)
    }

    /// Continue a `balances` flow by submitting the user's answer to a
    /// `Response.dialog(_:)`.
    ///
    /// - Parameters:
    ///   - ticket: The same `BalancesTicket` that returned the dialog.
    ///   - context: `InputContext` taken from the dialog's input on the
    ///     prior `Response.dialog(_:)`.
    ///   - response: The user's answer; see `DialogInput` for the format
    ///     expected by each input variant.
    public func respondBalances(
        ticket: BalancesTicket,
        context: InputContext,
        response: String
    ) async throws -> Response<BalancesResult> {
        try await resume(ticket: ticket, context: context, response: response)
    }

    /// Continue a `transactions` flow paused on a confirmation
    /// `Response.dialog(_:)`, `Response.redirect(_:)`, or
    /// `Response.redirectHandle(_:)`.
    ///
    /// - Parameters:
    ///   - ticket: The same `TransactionsTicket` that returned the prior
    ///     response.
    ///   - context: `ConfirmationContext` taken from the
    ///     `Response.dialog(_:)`, `Response.redirect(_:)`, or
    ///     `Response.redirectHandle(_:)` returned by the prior call.
    public func confirmTransactions(
        ticket: TransactionsTicket,
        context: ConfirmationContext
    ) async throws -> Response<TransactionsResult> {
        try await resume(ticket: ticket, context: context)
    }

    /// Continue a `transactions` flow by submitting the user's answer to
    /// a `Response.dialog(_:)`.
    ///
    /// - Parameters:
    ///   - ticket: The same `TransactionsTicket` that returned the
    ///     dialog.
    ///   - context: `InputContext` taken from the dialog's input on the
    ///     prior `Response.dialog(_:)`.
    ///   - response: The user's answer; see `DialogInput` for the format
    ///     expected by each input variant.
    public func respondTransactions(
        ticket: TransactionsTicket,
        context: InputContext,
        response: String
    ) async throws -> Response<TransactionsResult> {
        try await resume(ticket: ticket, context: context, response: response)
    }

    /// Continue a `collectPayment` flow paused on a confirmation
    /// `Response.dialog(_:)`, `Response.redirect(_:)`, or
    /// `Response.redirectHandle(_:)`.
    ///
    /// - Parameters:
    ///   - ticket: The same `CollectPaymentTicket` that returned the
    ///     prior response.
    ///   - context: `ConfirmationContext` taken from the
    ///     `Response.dialog(_:)`, `Response.redirect(_:)`, or
    ///     `Response.redirectHandle(_:)` returned by the prior call.
    public func confirmCollectPayment(
        ticket: CollectPaymentTicket,
        context: ConfirmationContext
    ) async throws -> Response<CollectPaymentResult> {
        try await resume(ticket: ticket, context: context)
    }

    /// Continue a `collectPayment` flow by submitting the user's answer
    /// to a `Response.dialog(_:)`.
    ///
    /// - Parameters:
    ///   - ticket: The same `CollectPaymentTicket` that returned the
    ///     dialog.
    ///   - context: `InputContext` taken from the dialog's input on the
    ///     prior `Response.dialog(_:)`.
    ///   - response: The user's answer; see `DialogInput` for the format
    ///     expected by each input variant.
    public func respondCollectPayment(
        ticket: CollectPaymentTicket,
        context: InputContext,
        response: String
    ) async throws -> Response<CollectPaymentResult> {
        try await resume(ticket: ticket, context: context, response: response)
    }

    /// Continue a `transfer` flow paused on a confirmation
    /// `Response.dialog(_:)`, `Response.redirect(_:)`, or
    /// `Response.redirectHandle(_:)`.
    ///
    /// - Parameters:
    ///   - ticket: The same `TransferTicket` that returned the prior
    ///     response.
    ///   - context: `ConfirmationContext` taken from the
    ///     `Response.dialog(_:)`, `Response.redirect(_:)`, or
    ///     `Response.redirectHandle(_:)` returned by the prior call.
    public func confirmTransfer(
        ticket: TransferTicket,
        context: ConfirmationContext
    ) async throws -> Response<TransferResult> {
        try await resume(ticket: ticket, context: context)
    }

    /// Continue a `transfer` flow by submitting the user's answer to a
    /// `Response.dialog(_:)`.
    ///
    /// - Parameters:
    ///   - ticket: The same `TransferTicket` that returned the dialog.
    ///   - context: `InputContext` taken from the dialog's input on the
    ///     prior `Response.dialog(_:)`.
    ///   - response: The user's answer; see `DialogInput` for the format
    ///     expected by each input variant.
    public func respondTransfer(
        ticket: TransferTicket,
        context: InputContext,
        response: String
    ) async throws -> Response<TransferResult> {
        try await resume(ticket: ticket, context: context, response: response)
    }

    // MARK: - Internal request execution

    /// Confirm overload: dispatches on `ConfirmationContext` to the
    /// `<service>/confirmation` endpoint. Counterpart of the respond
    /// overload below; the two will collapse into a single public
    /// `resume(...)` once the cross-language clients agree on a shared
    /// shape.
    fileprivate func resume<T: ServiceTicket>(
        ticket: T,
        context: ConfirmationContext
    ) async throws -> Response<T.ResultData> {
        let body = ConfirmBody(context: context)
        return try await execute(
            ticket: ticket,
            path: "\(T.servicePath)/confirmation",
            body: body
        )
    }

    /// Respond overload: dispatches on `InputContext` + `response` to the
    /// `<service>/response` endpoint.
    fileprivate func resume<T: ServiceTicket>(
        ticket: T,
        context: InputContext,
        response: String
    ) async throws -> Response<T.ResultData> {
        let body = RespondBody(context: context, response: response)
        return try await execute(
            ticket: ticket,
            path: "\(T.servicePath)/response",
            body: body
        )
    }

    private func execute<T: RoutexTicket, B: Encodable>(
        ticket: T,
        path: String,
        body: B
    ) async throws -> Response<T.ResultData> {
        let payload = try WireEncoding.encode(body)
        let bytes = try await core.request(ticket: ticket, path: path, body: payload)
        return try WireEncoding.decode(Response<T.ResultData>.self, from: bytes)
    }
}

extension Data {
    fileprivate var base64URLEncodedString: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
