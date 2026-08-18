// The standard HMAC construction (RFC 2104: key padded to block size,
// ipad/opad XOR) over BLAKE2b - distinct from BLAKE2b's built-in keyed mode.

import Foundation

/// HMAC over BLAKE2b.
@_spi(Interop) public enum HMACBlake2b {
    /// Authentication code for `message` under `key`, `outputLength` bytes
    /// long (1...64, BLAKE2b-512 by default).
    public static func mac(key: Data, message: Data, outputLength: Int = 64) -> Data {
        let blockSize = Blake2b.blockSize

        // RFC 2104 section 2: derive a `blockSize`-byte K'. Oversized keys are
        // hashed down first. `Data`'s indices are not offsets, hence `Array`.
        let material =
            key.count > blockSize
            ? Array(Blake2b.hash(key, outputLength: outputLength)) : Array(key)
        var keyPrime = [UInt8](repeating: 0, count: blockSize)
        keyPrime.replaceSubrange(0..<material.count, with: material)

        // Inner and outer key pads.
        let ipadKey = keyPrime.map { $0 ^ 0x36 }
        let opadKey = keyPrime.map { $0 ^ 0x5c }

        // inner = H(ipadKey || message)
        var inner = Blake2b(outputLength: outputLength)
        inner.update(ipadKey)
        inner.update(message)
        let innerDigest = inner.finalize()

        // outer = H(opadKey || inner)
        var outer = Blake2b(outputLength: outputLength)
        outer.update(opadKey)
        outer.update(innerDigest)
        return Data(outer.finalize())
    }
}
