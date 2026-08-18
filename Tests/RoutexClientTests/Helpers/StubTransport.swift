import Foundation

@testable import RoutexClient
@testable import RoutexTransport

/// A canned `HTTPTransport` for unit tests. Returns the next entry from
/// `responses` for each request and records what was sent.
actor StubTransportState {
    var responseQueue: [HTTPResponse]
    var recordedRequests: [HTTPRequest] = []

    init(_ responses: [HTTPResponse]) { self.responseQueue = responses }

    func next(_ request: HTTPRequest) throws -> HTTPResponse {
        recordedRequests.append(request)
        guard !responseQueue.isEmpty else {
            throw HTTPError.transportFailure(
                underlying: NSError(
                    domain: "test",
                    code: 0,
                    userInfo: [NSLocalizedDescriptionKey: "no more canned responses"]
                )
            )
        }
        return responseQueue.removeFirst()
    }
}

struct StubTransport: HTTPTransport {
    let state: StubTransportState

    init(_ responses: [HTTPResponse]) {
        self.state = StubTransportState(responses)
    }

    func execute(_ request: HTTPRequest) async throws -> HTTPResponse {
        try await state.next(request)
    }

    func recorded() async -> [HTTPRequest] {
        await state.recordedRequests
    }
}
