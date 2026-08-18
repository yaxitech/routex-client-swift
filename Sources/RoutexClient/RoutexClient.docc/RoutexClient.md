# ``RoutexClient``

Interactive client for the YAXI Open Banking services.

## Overview

``RoutexClient/RoutexClient`` drives the interactive account-information and payment services: each call is authorized by a backend-issued ticket, returns a typed `Response`, and pauses on dialogs and redirects until the user resolves them.

The module re-exports `RoutexModels`, `RoutexSettlement`, and `RoutexTransport`, so this one import is enough for a frontend.
