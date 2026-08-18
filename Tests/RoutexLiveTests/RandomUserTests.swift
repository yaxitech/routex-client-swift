import Foundation
import RoutexClient
import RoutexModels
import Testing

/// Drives the `userID=random` flow against two services to demonstrate that
/// interrupt handling is service-agnostic: the same ``InterruptHandler``
/// resolves dialogs and redirects whether the call is `accounts` or
/// `collectPayment`. The driver pattern below is what an integrator
/// would reach for in their own app.
@Suite("Live: userID=random multi-step driver", .enabled(if: LiveEnvironment.isAvailable))
struct RandomUserTests {
    @Test func accountsReachesResult() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try env.issuer.accounts()

        let initial = try await client.accounts(
            ticket: ticket,
            credentials: Credentials(
                connectionID: DemoData.demoConnection,
                userID: "random"
            ),
            fields: AccountField.allCases
        )
        let final = try await driveInterrupts(
            initial,
            ticket: ticket,
            on: client,
            callbackURI: DemoData.callbackURI,
            handler: cannedHandler(),
            confirm: { try await client.confirmAccounts(ticket: $0, context: $1) },
            respond: { try await client.respondAccounts(ticket: $0, context: $1, response: $2) }
        )
        guard case .result(let result) = final else {
            Issue.record("expected .result, got \(final)")
            return
        }
        let decoded = try result.authenticated.decodeUnverified()
        #expect(!decoded.data.isEmpty)
    }

    @Test func collectPaymentReachesResult() async throws {
        let env = try #require(LiveEnvironment.load())
        let client = env.makeClient()
        let ticket = try DemoData.collectPaymentTicket(env.issuer)

        let initial = try await client.collectPayment(
            ticket: ticket,
            credentials: Credentials(
                connectionID: DemoData.demoConnection,
                userID: "random"
            )
        )
        let final = try await driveInterrupts(
            initial,
            ticket: ticket,
            on: client,
            callbackURI: DemoData.callbackURI,
            handler: cannedHandler(),
            confirm: { try await client.confirmCollectPayment(ticket: $0, context: $1) },
            respond: {
                try await client.respondCollectPayment(ticket: $0, context: $1, response: $2)
            }
        )
        guard case .result(let result) = final else {
            Issue.record("expected .result, got \(final)")
            return
        }
        _ = try result.authenticated.decodeUnverified()
    }

    /// Canned answers an integrator's app would supply by prompting the user.
    private func cannedHandler() -> InterruptHandler {
        let follower = RedirectFollower()
        return InterruptHandler(
            onField: { dialog in "133742" },
            onSelection: { dialog, options in
                let first = try #require(options.first, "selection dialog had no options")
                return first.key
            },
            onRedirect: { url in
                _ = try await follower.follow(url, terminate: "smoketest")
            }
        )
    }
}

// MARK: - Interrupt driver
//
// An integrator would write a function much like the one below: the
// runtime walks every interrupt the bank emits, polling Confirmation
// dialogs in the background and asking the integrator's UI to render
// the rest. Tests replace the UI with canned answers via
// `InterruptHandler`.

/// Integrator-supplied UI hooks for the three interrupt classes that
/// need user input. `Confirmation` dialogs are polled automatically and
/// never reach the handler.
struct InterruptHandler: Sendable {
    /// Render `dialog` (message, image, field type / secrecy / min / max)
    /// and return the user's typed answer.
    let onField: @Sendable (Dialog) async throws -> String

    /// Render `dialog` (message, image) along with `options` and return
    /// the chosen option's `key`.
    let onSelection: @Sendable (Dialog, [DialogOption]) async throws -> String

    /// Send the user to `url` and resolve when they're back. The driver
    /// already registered a redirect URI when the response was a
    /// `RedirectHandle`, so callers see one entry point either way.
    let onRedirect: @Sendable (URL) async throws -> Void
}

/// Walk a `Response<T.ResultData>` until it becomes `.result`.
///
/// - Confirmation interrupts are auto-polled, sleeping `pollingDelay`
///   between attempts when the bank asks us to.
/// - Field, Selection, Redirect, and RedirectHandle interrupts dispatch
///   through `handler`.
/// - Returns the raw `.result` response so the caller decides when to
///   call `decodeUnverified()`.
///
/// `maxSteps` caps the total number of interrupt round-trips (including
/// each Confirmation poll) so a misbehaving flow eventually gives up.
func driveInterrupts<T: RoutexTicket>(
    _ initial: Response<T.ResultData>,
    ticket: T,
    on client: RoutexClient,
    callbackURI: String,
    handler: InterruptHandler,
    maxSteps: Int = 10,
    confirm: @Sendable (T, ConfirmationContext) async throws -> Response<T.ResultData>,
    respond: @Sendable (T, InputContext, String) async throws -> Response<T.ResultData>
) async throws -> Response<T.ResultData> {
    var current = initial
    for _ in 0..<maxSteps {
        switch current {
        case .result:
            return current
        case .dialog(let dialog):
            switch dialog.input {
            case .confirmation(let context, let polling):
                if let polling, polling > 0 {
                    try await Task.sleep(nanoseconds: UInt64(polling * 1_000_000_000))
                }
                current = try await confirm(ticket, context)
            case .field(_, _, _, _, let context):
                let answer = try await handler.onField(dialog)
                current = try await respond(ticket, context, answer)
            case .selection(let options, let context):
                let key = try await handler.onSelection(dialog, options)
                current = try await respond(ticket, context, key)
            }
        case .redirect(let r):
            try await handler.onRedirect(r.url)
            current = try await confirm(ticket, r.context)
        case .redirectHandle(let h):
            let url = try await client.registerRedirectURI(
                ticket: ticket,
                handle: h.handle,
                redirectURI: callbackURI
            )
            try await handler.onRedirect(url)
            current = try await confirm(ticket, h.context)
        }
    }
    // Last iteration may have produced a `.result` we haven't returned yet.
    guard case .result = current else {
        throw DriverError.tooManyInterrupts(steps: maxSteps)
    }
    return current
}

enum DriverError: Error, Sendable, CustomStringConvertible {
    case tooManyInterrupts(steps: Int)
    var description: String {
        switch self {
        case .tooManyInterrupts(let n): return "tooManyInterrupts(\(n))"
        }
    }
}
