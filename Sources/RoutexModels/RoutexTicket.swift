import Foundation

/// Ticket to use a service.
///
/// Issued by a trusted backend for use in the (untrusted) frontend. The
/// underlying [JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519) carries:
/// - an identifier of the service that is intended to be used,
/// - an arbitrary ticket identifier for verifying results later, and
/// - any critical input data for the service.
///
/// The ``ResultData`` associated type binds the ticket to the typed
/// response shape, so that the per-service `confirm`/`respond` methods
/// on `RoutexClient` can return a typed ``Response`` from a single
/// generic implementation.
///
/// See [Getting started](https://docs.yaxi.tech/getting-started.html) for
/// how a backend issues these.
public protocol RoutexTicket: Sendable, Hashable {
    /// Concrete result payload for this service.
    associatedtype ResultData: Sendable, Decodable, Hashable
    /// Raw JWT string as issued by the backend.
    var raw: String { get }
    /// Ticket identifier carried in the `data.id` claim.
    var id: UUID { get }
}
