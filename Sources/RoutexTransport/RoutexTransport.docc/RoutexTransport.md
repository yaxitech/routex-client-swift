# ``RoutexTransport``

Pluggable HTTP transport for the YAXI Open Banking services.

## Overview

``HTTPTransport`` is the seam between the clients and an HTTP stack; the default ``URLSessionTransport`` is backed by `URLSession`.

Provide a custom implementation to integrate a different stack, record traffic in tests, or inject middleware.
