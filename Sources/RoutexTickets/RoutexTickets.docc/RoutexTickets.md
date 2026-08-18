# ``RoutexTickets``

Typed ticket issuer for the YAXI Open Banking services.

## Overview

Issuing a ticket requires the API key secret, so the issuer belongs in a trusted
backend in the vast majority of deployments. Frontend issuance is possible and a
handful of legitimate use cases exist, but only consider it if you understand the
security implications of co-locating the API key secret with untrusted code; a
leaked secret lets third parties issue tickets at your cost.

Backends create a ``RoutexTicketIssuer`` once from their API key id and secret and
call one method per service:

```swift
let issuer = try RoutexTicketIssuer(
    apiKeyID: "api-key-2eeba71f-...",
    base64Secret: ProcessInfo.processInfo.environment["YAXI_API_KEY_SECRET"]!)
let ticket = try issuer.accounts()
```

Add `RoutexTickets` only where you issue tickets. A frontend that merely calls
`RoutexClient` does not need it; the tickets it consumes are issued elsewhere and
handed to it as opaque strings.

## Topics

### Issuing tickets

- ``RoutexTicketIssuer``

### Service inputs

- ``TransactionsRange``
- ``CollectPaymentField``

### Errors

- ``RoutexTicketIssuerError``
