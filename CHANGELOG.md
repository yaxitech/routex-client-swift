# Changelog

## [0.5.0] - 2026-08-18

Native Swift rewrite, replacing the UniFFI binding over the Rust core.
The rewrite reshapes every existing type and method; [MIGRATION.md](MIGRATION.md) lists those changes in full and is the guide to upgrading from 0.4.1.
What follows is what the release adds and removes on top of them.

### Added

- `RoutexRefresh`, a non-interactive refresh client (`RoutexRefreshClient`) that drives the accounts, balances, and transactions services plus the discovery endpoints against a connection that already went through an interactive consent.
- `RoutexTickets` with `RoutexTicketIssuer`, which issues signed and typed JWT tickets that authorize service calls.
- `ConnectionInfo.bankCodes`, the national bank codes.
  Request it by passing `ConnectionDetails.bankCodes` to `search`.
- Reference accounts that have no IBAN in the balances and transactions services via `AccountIdentifier.number(_:)` (e.g., an ISO 20022 BBAN).
- `CollectPaymentField.encryptedDebtorName` to request the debtor name in encrypted form (`PaymentInitiation.encryptedDebtorName`), mirroring `encryptedDebtorIBAN`.
- `Balance.dateTime`, the moment a balance is valid.
- `userInSession` option on the `RoutexRefreshClient` initializer (`UserInSession.onThisConnection` or `.at(_:)`) to signal an in-session user.
- Run the accounts, balances, and transactions services without credentials by passing `connectionData:` instead of `credentials:`, against the consent an earlier interactive flow established.
  The response stays a `Response`, so interrupts remain possible; `RoutexError.interruptError` signals that the bank needs the user.
- `AccountPredicate`, pairing an account field with the value to compare it against, so `AccountFilter.eq` / `.notEq` cannot be given a value the field does not accept.
- `ISODate`, a calendar date the API carries without a time of day, validated on construction and resolvable to a `Date` in a caller-named time zone.
- `SearchFilter.encryptedIBAN(_:)` to search by an IBAN your backend encrypted.
- `ConnectionInfo.labels`, the labels categorizing a connection (e.g. `"beta"`, `"fints"`).
- `RoutexTransport` with the `HTTPTransport` protocol and the default `URLSessionTransport`.
  Both clients take a custom transport via `transport:`, e.g., to record traffic in tests or to inject middleware; 0.4.1 hardcoded its HTTP stack.

### Security

- Reject attestation reports whose guest policy allows migration to another host.
