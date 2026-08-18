import Foundation

/// A ``RoutexTicket`` for a service reachable under a URL path.
///
/// Package-visible, so only the ticket types shipped here can conform.
package protocol ServiceTicket: RoutexTicket {
    static var servicePath: String { get }
}
