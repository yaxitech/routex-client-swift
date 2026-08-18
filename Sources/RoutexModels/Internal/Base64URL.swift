// Base64URL (RFC 4648 §5) decoding for JWT segments. Internal helper
// shared by ``Authenticated/decodeUnverified()`` and the per-service
// ticket parsers, which map a failure to their own error type.

import Foundation

enum Base64URL {
    static func decode(_ encoded: String) -> Data? {
        var padded = encoded.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let pad = (4 - padded.count % 4) % 4
        padded.append(String(repeating: "=", count: pad))
        return Data(base64Encoded: padded)
    }
}
