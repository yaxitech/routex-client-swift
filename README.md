# routex-client-swift

Swift client library for [YAXI's](https://yaxi.tech) Open Banking services.

Runs on Apple platforms (iOS 15, macOS 12, Mac Catalyst 15, tvOS 15, watchOS 8 or newer) and on Linux.
Service methods are `async` functions and the package builds with Swift 6 strict concurrency.

A companion `RoutexRefresh` product drives non-interactive refreshes against a connection that already went through an interactive consent.

See the [documentation](https://docs.yaxi.tech) for the full API reference, and the [generated Swift API reference](https://yaxitech.github.io/routex-client-swift/documentation/) for the symbol-level docs of this package.
Upgrading from the 0.4.1 UniFFI client? See [MIGRATION.md](MIGRATION.md).

## Installation

Requires Swift 6.1 or newer.

```swift
dependencies: [
    .package(url: "https://github.com/yaxitech/routex-client-swift", from: "0.5.0")
],
targets: [
    .target(
        name: "MyApp",
        dependencies: [
            .product(name: "RoutexClient", package: "routex-client-swift")
        ]
    )
]
```

## Usage

```swift
import RoutexClient

// Pass baseURL: URL(string: "https://integration.yaxi.tech")! for the integration environment
let client = RoutexClient()

// ticket: an AccountsTicket built from the raw string your backend issued (see docs)

// Search for a bank
let connections = try await client.search(
    ticket: ticket,
    filters: [.term("sparkasse")],
    ibanDetection: true,
    limit: 20
)

// Fetch accounts
var response = try await client.accounts(
    ticket: ticket,
    credentials: Credentials(connectionID: connectionID, userID: "user"),
    fields: [.iban, .currency, .ownerName]
)

// Handle interrupts (dialogs, redirects)
switch response {
case .dialog(let dialog):
    switch dialog.input {
    case .confirmation(let context, _):
        // Decoupled SCA or polling: confirm to proceed
        response = try await client.confirmAccounts(ticket: ticket, context: context)
    case .field(_, _, _, _, let context):
        // Text input required (e.g. TAN entry)
        response = try await client.respondAccounts(
            ticket: ticket, context: context, response: userInput)
    case .selection(_, let context):
        // Pick one option (e.g. TAN method)
        response = try await client.respondAccounts(
            ticket: ticket, context: context, response: selectedKey)
    }
case .redirect(let redirect):
    // Send the user to redirect.url (browser or web view), then confirm
    response = try await client.confirmAccounts(ticket: ticket, context: redirect.context)
case .redirectHandle(let handle):
    // Register a redirect URI to obtain the URL to send the user to
    let url = try await client.registerRedirectURI(
        ticket: ticket, handle: handle.handle, redirectURI: "myapp://callback")
    // Send the user to url, then confirm
    response = try await client.confirmAccounts(ticket: ticket, context: handle.context)
case .result:
    break
}

// Extract the result
if case .result(let result) = response {
    // result.authenticated.jwt: authenticated data as a signed JSON Web Token.
    //   Verify the signature in a trusted environment before acting on the data.
    // result.session: short-lived, pass to consecutive service calls to speed up authentication
    // result.connectionData: persist alongside credentials to reuse the consent on
    //   subsequent calls (via Credentials.connectionData), to run accounts, balances, or
    //   transactions without credentials (pass it as connectionData:), or for
    //   non-interactive refreshes via RoutexRefreshClient. Pass recurringConsents: true
    //   on the service call to request a long-lived consent that skips the interrupt
    //   loop until it expires.
}
```

Subsequent interrupts are resolved by repeating the same `switch` block until a `Response.result` is returned.
Service methods throw [`RoutexError`](https://docs.yaxi.tech/errors.html) on a typed server error; the full per-service reference lives in the [documentation](https://docs.yaxi.tech).

[`Tests/RoutexLiveTests/`](Tests/RoutexLiveTests/) holds runnable end-to-end examples for every service.

## License

Apache-2.0
