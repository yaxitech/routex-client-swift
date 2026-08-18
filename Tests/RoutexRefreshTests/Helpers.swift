import Foundation
import RoutexCore
import RoutexModels
import RoutexSettlement
import RoutexTransport

/// No-op settlement: payloads pass straight through, so a recorded request
/// body is the plaintext JSON the client produced.
struct PassthroughSettlement: SettlementCore {
    func ensureSettled(extraHeaders: [String: String]) async throws {}
    func seal(_ plaintext: Data) async throws -> Data { plaintext }
    func unseal(_ ciphertext: Data) async throws -> Data { ciphertext }
    var sessionID: String? { get async { "test-session" } }
    var systemVersion: SystemVersionEntry? { get async { nil } }
}

actor StubTransportState {
    var responseQueue: [HTTPResponse]
    var recordedRequests: [HTTPRequest] = []

    init(_ responses: [HTTPResponse]) { self.responseQueue = responses }

    func next(_ request: HTTPRequest) throws -> HTTPResponse {
        recordedRequests.append(request)
        guard !responseQueue.isEmpty else {
            throw HTTPError.transportFailure(
                underlying: NSError(domain: "test", code: 0)
            )
        }
        return responseQueue.removeFirst()
    }
}

struct StubTransport: HTTPTransport {
    let state: StubTransportState
    init(_ responses: [HTTPResponse]) { self.state = StubTransportState(responses) }
    func execute(_ request: HTTPRequest) async throws -> HTTPResponse {
        try await state.next(request)
    }
    func recorded() async -> [HTTPRequest] { await state.recordedRequests }
}

func sampleTicket(service: String, id: UUID = UUID()) -> String {
    let header = #"{"alg":"HS256","typ":"JWT","kid":"test"}"#
    let payload = #"{"data":{"service":"\#(service)","id":"\#(id.uuidString)"},"exp":99999999999}"#
    return "\(Data(header.utf8).base64URL).\(Data(payload.utf8).base64URL).fakesig"
}

extension Data {
    var base64URL: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
