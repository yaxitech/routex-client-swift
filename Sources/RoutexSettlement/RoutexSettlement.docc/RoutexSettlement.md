# ``RoutexSettlement``

Attested key settlement for the YAXI Open Banking services.

## Overview

`RoutexSettlement` establishes an end-to-end-encrypted session with the YAXI TEE: it runs the AMD SEV-SNP attestation handshake, verifies the attestation report and its VCEK certificate chain, and derives the per-session key that seals requests and unseals responses.

Most consumers reach this transitively through `RoutexClient` and never construct it directly.
Building your own client on top of the settlement layer is discouraged; only do so if you fully understand the attestation and sealing guarantees you take responsibility for.
Reach for ``Settlement`` only in that case: ``Settlement/settle(extraHeaders:)`` runs the handshake once, then ``Settlement/seal(_:)`` and ``Settlement/unseal(_:)`` protect each request and response for the established session.

## Topics

### Establishing a session

- ``Settlement``
- ``SettleResult``

### Errors

- ``KeySettlementError``
