# Migrating from 0.4.1 to 0.5.0

Version 0.4.1 wrapped a Rust core through UniFFI, shipped as a binary `RoutexClientFFI.xcframework`.
This release is a pure-Swift rewrite with no binary and no UniFFI, and it builds on Linux as well as Apple platforms.

The services, the settlement and attestation guarantees, and the interrupt model are unchanged.
Migration is mechanical: new imports, idiomatic names, typed tickets, and a single generic response type.

## Highlights

- **Pure Swift.** Drop the `RoutexClientFFI.xcframework` binary (the Rust core, ~6.6 MB per architecture); the package is source-only and also builds on Linux.
- **Typed tickets.** The single opaque `Ticket` becomes per-service types (`AccountsTicket`, `CollectPaymentTicket`, etc.), built from the raw ticket string your backend issues.
- **One generic response.** The per-service `AccountsResponse`, `BalancesResponse`, etc. collapse into `Response<SomeResult>` with the same four cases.
- **Safer results.** The old `toData()` decoded a result's payload without verifying its signature; the replacement `decodeUnverified()` makes that explicit. Forward `authenticated.jwt` to your backend for a verified read.

## Breaking changes

### Package and imports

`import Routex` becomes `import RoutexClient`, which re-exports `RoutexModels` (the request and result types), so a single import is enough.
In your manifest, drop the `RoutexClientFFI` binary target and depend on the `RoutexClient` product.
Only a backend that issues tickets needs the `RoutexTickets` product.

Code that spelled types out as `Routex.Account` cannot simply say `RoutexClient.Account`: the client class is itself named `RoutexClient`, so the qualified form resolves to the class and fails.
Drop the qualifier (`Account`) or name the module that owns the type (`RoutexModels.Account`).

### Client construction

The `url:` label is now `baseURL:`; the no-argument `RoutexClient()` still targets production.

```swift
// 0.4.1
let client = RoutexClient(url: URL(string: "https://integration.yaxi.tech")!)
// now
let client = RoutexClient(baseURL: URL(string: "https://integration.yaxi.tech")!)
```

### Tickets

The single opaque `Ticket` is replaced by per-service typed tickets: `AccountsTicket`, `BalancesTicket`, `CollectPaymentTicket`, `TransactionsTicket`, `TransferTicket`.
A frontend builds one from the raw ticket string it receives from your backend:

```swift
let ticket = try AccountsTicket(rawTicketString)
```

Backends written in Swift can issue tickets with the new `RoutexTicketIssuer` (in the `RoutexTickets` module).

There is no longer a single `Ticket` type, so code that was generic over "any ticket" now takes `some RoutexTicket`, and you recover the raw string with `ticket.raw`.
Turning a helper generic this way also means it can no longer declare a nested type, so any local `struct` or `class` inside it has to move out to file scope.

The service-independent endpoints — `search`, `systemVersion(for:)`, `trace(ticket:traceID:)`, `registerRedirectURI` — take `some RoutexTicket` as well, so any of the typed tickets is accepted.

### Service calls

`ticket` is now the first argument, and the optional `session` and `recurringConsents` move to the end as defaulted parameters.
Each method returns `Response<SomeResult>` instead of a per-service response (the concrete result types are `AccountsResult`, `BalancesResult`, etc.).

```swift
// 0.4.1
let resp = try await client.accounts(
    credentials: creds, session: nil, recurringConsents: nil,
    ticket: ticket, fields: fields, filter: nil)
// now
let resp = try await client.accounts(
    ticket: ticket, credentials: creds, fields: fields)
```

### Handling interrupts

Each interrupt case now carries a single struct instead of flattened values.

```swift
// 0.4.1
switch resp {
case .dialog(let context, let message, let image, let input): ...
case .redirect(let url, let context): ...
case .redirectHandle(let handle, let context): ...
case .result(let r, let session, let connectionData): ...
}
// now
switch resp {
case .dialog(let dialog):                 // dialog.context, dialog.message, dialog.image, dialog.input
case .redirect(let redirect):             // redirect.url, redirect.context
case .redirectHandle(let handle):         // handle.handle, handle.context
case .result(let result):                 // result.authenticated, result.session, result.connectionData
}
```

### Reading a result

The result wrapper's `toData()` and `jwt()` methods are gone.
Forward `authenticated.jwt` to a backend that holds the HMAC key for a verified read, or call `authenticated.decodeUnverified()`, which decodes the payload without verifying its signature (the old `toData()` did so silently).
`decodeUnverified()` now `throws` where `toData()` did not, so the `try` propagates through any decoding helper, and the per-service authenticated result types collapse into a generic `Authenticated<SomeResult>` reached via `result.authenticated`.
Like `toData()` before it, `decodeUnverified()` hands back the `SomeResult` envelope — `ticketID`, `timestamp`, and the service payload under `.data` — so reaching the balances or transactions themselves is still one step further.
It decodes on every call (as `toData()` did), so bind the envelope once when you need more than one of its fields.

```swift
// 0.4.1
if case .result(let r, _, _) = resp { let balances = r.toData().data }   // decoded unverified, silently
// now
if case .result(let result) = resp {
    let balances = try result.authenticated.decodeUnverified().data      // no signature verification
}
```

### Removed and changed methods

- `settleKey(ticket:)` is removed; settlement runs automatically on the first service call, and a failed attestation throws `KeySettlementError` there.
- The throwing `systemVersion(ticketId:) -> String?` becomes the non-throwing `systemVersion(for:) -> SystemVersionEntry?` (`await client.systemVersion(for: ticket)`); both are `async`.
- `traceId() -> Data?` and `trace(ticket:traceId:)` become the `async` `traceID` property (`await client.traceID`) and `trace(ticket:traceID:)`, carrying a `TraceID` value (read its bytes with `.bytes`).

### Idiomatic renames

Acronyms are now uppercased per the Swift API Design Guidelines.
Apply the same `id -> ID`, `uri -> URI`, `url -> URL`, and `bic -> BIC` casing wherever these appear (e.g., `logoId -> logoID`, `endToEndId -> endToEndID`, `creditorAgentBic -> creditorAgentBIC`).
Some are more than casing; see _Identifiers and value types_.

| 0.4.1                                | now                                  |
| ------------------------------------ | ------------------------------------ |
| `connectionId`, `ConnectionId`       | `connectionID`, `ConnectionID`       |
| `userId`                             | `userID`                             |
| `ConnectionInfo.userId` / `password` | `userIDLabel` / `passwordLabel`      |
| `redirectUri`, `registerRedirectUri` | `redirectURI`, `registerRedirectURI` |
| `Url`                                | Foundation `URL`                     |
| `Details` (search)                   | `ConnectionDetails`                  |
| `DateTime`                           | `ISODateTimeOrDate`                  |

### Identifiers and value types

- **`ConnectionID`** is a value type, not a `String`. `Credentials.connectionID` and `ConnectionInfo.id` carry one; build it with `try ConnectionID(_:)` (accepts `connection-<uuid>` or a bare UUID) and read it back with `.description` (wire form) or `.uuid`. The throwing initializer makes helpers that rebuild credentials from stored strings `throws`.
- **`Session`, `ConnectionData`, `ConfirmationContext`, `InputContext`, `TraceID`** are opaque byte wrappers, not `Data`: build with `init(_ bytes: Data)`, read `.bytes`, persist `value.bytes.base64EncodedString()`.
- **`Amount`** initializes as `Amount(amount:currency:)` (argument order changed).
- **`RoutexResult.ticketID`** is a `UUID`, not a `String`; compare it against a `UUID` or read `.uuidString`.
- **Temporal values** split by shape: an instant is a `Date` (`Balance.dateTime`, `RoutexResult.timestamp`), a date without a time of day is an `ISODate` (`Transaction.bookingDate` / `valueDate` / `transactionDate`, `TransactionsRange.period(from:to:)`).
  `transfer(requestedExecutionDate:)` takes `ISODateTimeOrDate?`, which is any of the three ISO 8601 shapes routex accepts there (e.g., `.date(try ISODate("2026-01-01"))`).
  `ISODate(_:)` validates its argument and throws, so building one from a formatted `Date` propagates through the caller.
  `ISODate` keeps the wire string verbatim in `rawValue`, since Foundation has no calendar-date type.
- **`AccountFilter`** replaces the per-field convenience cases with `eq` / `notEq(AccountPredicate)`, `and`, `or`, and `supports`.
  An `AccountPredicate` names the field and carries its value, so `.ibanNotEq(value: nil)` becomes `.notEq(.iban(nil))`.
  The array-taking `All` / `Any` become the binary `and` / `or`; chain them for more than two subfilters.
- **`search(limit:)`** takes an `Int?`, not a `UInt32?`, following the standard library's use of `Int` for counts and caps.
  A negative limit throws `SearchError.negativeLimit(_:)`.
- **Dialog input numerics**: `DialogInput.field` bounds its answer with `minLength` / `maxLength` as `Int?`, and the confirmation's `pollingDelaySecs: UInt32?` becomes `pollingDelay: TimeInterval?`.
- **`SearchFilter`** cases lost their argument labels (`.term("...")`, not `.term(term:)`) and `.countries` takes `[CountryCode]` (`CountryCode(_:)`), not `[String]`.
  The `Types` filter (and with it the `ConnectionType` enum) is gone without replacement.
- **Result models are immutable.** Their properties are `let`, so code that mutated a returned value in place has to build a new one instead.

### Errors

Service methods stay `async throws`, but the single 0.4.1 `RoutexClientError` is split in two:

1. `RoutexError` for errors the service returns, and
2. `RoutexClientError` for client-side failures: `sealingFailed(message:underlying:)`, `unsealingFailed(message:underlying:)`, and `malformedResponse(message:underlying:)`.

Transport failures are a third type, `HTTPError`, which lives in `RoutexTransport`; `RoutexClient` re-exports it, so catching it needs no extra import.
Settlement failures are a fourth: the automatic key settlement throws `KeySettlementError`, which lives in `RoutexSettlement` and is re-exported as well.

Cases are now camelCase; most map one to one:

| 0.4.1 `RoutexClientError`                              | now                                                                                                                                          |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `InvalidCredentials`, `Unauthorized`                   | `RoutexError.invalidCredentials`, `.unauthorized`                                                                                            |
| `ConsentExpired`                                       | `RoutexError.unauthorized` (folded)                                                                                                          |
| `ServiceBlocked(userMessage:code:)`                    | `RoutexError.serviceBlocked(code:userMessage:)` (order changed)                                                                              |
| `AccessExceeded`, `PeriodOutOfBounds`                  | `RoutexError.accessExceeded`, `.periodOutOfBounds`                                                                                           |
| `UnsupportedProduct`, `PaymentFailed`, `ProviderError` | `RoutexError.*` (same payloads)                                                                                                              |
| `UnexpectedError`, `UnexpectedValue`, `TicketError`    | `RoutexError.*`                                                                                                                              |
| `NotFound`, `InterruptError`, `Canceled`               | `RoutexError.*`                                                                                                                              |
| `RequestError`                                         | removed; transport failures throw `HTTPError` (`.transportFailure(underlying:)` / `.noResponse`)                                             |
| `ResponseError`                                        | removed; an unrecognized error body is `RoutexError.unrecognizedResponse`, a malformed success body is `RoutexClientError.malformedResponse` |
| `InvalidRedirectUri`                                   | removed; `setRedirectURI(_:)` is `async` and takes `nil` to clear, and neither it nor `registerRedirectURI` validates the URI                |

Two changes the compiler will not flag:

- `RoutexError` and `RoutexClientError` may gain cases in a later release. An exhaustive `switch` compiles today but breaks on upgrade, so add a `default` clause.
- A `catch ... as RoutexClientError` that handled service errors in 0.4.1 now silently misses them, since service errors are `RoutexError`; widen such clauses to catch both.
