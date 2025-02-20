import Testing

import Routex

struct WrongCase<T: Sendable>: Error {
    var expected: String
    var actual: T
}

func expectRedirectHandle(
    _ response: AccountsResponse,
    sourceLocation: SourceLocation = #_sourceLocation,
    _ f: (String, ConfirmationContext) async throws -> ()
) async throws {
    switch (response) {
    case .redirectHandle(handle: let handle, context: let context):
        return try await f(handle, context)
    default:
        Issue.record("Expected RedirectHandle, got \(response) instead", sourceLocation: sourceLocation)
    }
}

func requireDialog<R>(
    _ response: AccountsResponse,
    sourceLocation: SourceLocation = #_sourceLocation,
    _ f: (DialogInput) async throws -> R
) async throws -> R {
    switch (response) {
    case .dialog(context: _, message: _, image: _, input: let input):
        return try await f(input)
    default:
        Issue.record("Expected Dialog, got \(response)", sourceLocation: sourceLocation)
        throw WrongCase(expected: "Dialog", actual: response)
    }
}

func requireRedirectHandle<R>(
    _ response: AccountsResponse,
    sourceLocation: SourceLocation = #_sourceLocation,
    _ f: (String, ConfirmationContext) async throws -> R
) async throws -> R {
    switch (response) {
    case .redirectHandle(handle: let handle, context: let context):
        return try await f(handle, context)
    default:
        Issue.record("Expected RedirectHandle, got \(response) instead", sourceLocation: sourceLocation)
        throw WrongCase(expected: "RedirectHandle", actual: response)
    }
}
