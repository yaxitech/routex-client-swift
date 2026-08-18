// Shared `Codable` glue for the opaque byte-wrapper types
// (``Session``, ``ConnectionData``, ``ConfirmationContext``,
// ``InputContext``, ``TraceID``). On the wire these are base64-encoded
// strings inside a single-value JSON container.

import Foundation

protocol Base64BytesCoding: Codable {
    var bytes: Data { get }
    init(_ bytes: Data)
}

extension Base64BytesCoding {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let s = try container.decode(String.self)
        guard let data = Data(base64Encoded: s) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "expected base64 string"
            )
        }
        self.init(data)
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(bytes.base64EncodedString())
    }
}
