// HKDF-BLAKE2b-512 (RFC 5869) using HMAC-BLAKE2b-512 as the PRF.
//
// Two-step HKDF:
//   PRK = HMAC-BLAKE2b-512(salt, IKM)
//   T(i) = HMAC-BLAKE2b-512(PRK, T(i-1) || info || i)
//   OKM  = T(1) || T(2) || ... truncated to L bytes
//
// The routex settlement protocol uses HKDF with an empty salt and a 32-byte OKM,
// so a single expand round is always sufficient there. The implementation
// supports up to 255 * hashLen bytes of output as required by RFC 5869.

import Foundation

/// HKDF (RFC 5869) with HMAC-BLAKE2b-512 as the PRF.
@_spi(Interop) public enum HKDFBlake2b512 {
    /// Maximum output length in bytes (255 * 64).
    public static let maxOutputLength: Int = 255 * 64

    /// Derive `length` bytes of keying material.
    public static func deriveKey(ikm: Data, salt: Data, info: Data, length: Int) -> Data {
        precondition(length > 0, "HKDF length must be > 0")
        precondition(
            length <= maxOutputLength,
            "HKDF-BLAKE2b-512 cannot produce more than 16320 bytes (255 * hashLen)"
        )

        // Extract phase. RFC 5869 section 2.2: when salt is empty, treat it as a string
        // of HashLen zeros - HMAC's K' construction already does that for us
        // because an empty key pads up to the block size.
        let prk = HMACBlake2b.mac(key: salt, message: ikm, outputLength: 64)

        // Expand phase.
        var output = Data()
        output.reserveCapacity(length)
        var t = Data()
        var counter: UInt8 = 1
        while output.count < length {
            var block = Data()
            block.reserveCapacity(t.count + info.count + 1)
            block.append(t)
            block.append(info)
            block.append(counter)
            t = HMACBlake2b.mac(key: prk, message: block, outputLength: 64)
            output.append(t)
            counter &+= 1
        }
        return output.prefix(length)
    }
}
