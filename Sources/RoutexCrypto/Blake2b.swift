import Foundation

// Hand-rolled: swift-crypto exposes no BLAKE2, and the BLAKE2b-256 in its
// vendored BoringSSL is fixed at 32 bytes, too narrow for ChaChaBox's 12-byte
// nonce and 64-byte HKDF digests.

/// BLAKE2b (RFC 7693) with variable-length output and an optional key.
///
/// Produces digests of 1 to 64 bytes, optionally keyed with up to 64 bytes
/// (the function's built-in keyed mode). Hash incrementally with `update`
/// and ``finalize()``, or in one shot with ``hash(_:outputLength:key:)``.
/// Salt, personalization, and tree mode are not supported.
@_spi(Interop) public struct Blake2b: Sendable {
    /// Block size in bytes.
    public static let blockSize = 128

    /// Maximum digest length in bytes.
    public static let maxDigestLength = 64

    /// Maximum key length in bytes.
    public static let maxKeyLength = 64

    // MARK: - State

    private var h: [UInt64]  // Chained state (eight u64 words, 512 bits).
    private var buf: [UInt8]  // Pending input, sized to one block.
    private var bufLen: Int  // Bytes valid in `buf`.
    private var totalLen: UInt64  // Total bytes processed so far.
    private let outputLength: Int

    // MARK: - Constants

    /// RFC 7693 section 2.6: SHA-512 IV reused as BLAKE2b IV.
    private static let iv: [UInt64] = [
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    ]

    /// RFC 7693 section 2.7: per-round message permutation table (12 rounds).
    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ]

    // MARK: - Initialization

    /// Create a hashing state.
    ///
    /// - Parameters:
    ///   - outputLength: Digest length in bytes, 1...64.
    ///   - key: Optional key, at most 64 bytes.
    public init(outputLength: Int, key: [UInt8] = []) {
        precondition(
            (1...Blake2b.maxDigestLength).contains(outputLength),
            "BLAKE2b output length must be between 1 and 64 bytes"
        )
        precondition(
            key.count <= Blake2b.maxKeyLength,
            "BLAKE2b key must be at most 64 bytes"
        )

        self.outputLength = outputLength
        self.h = Self.iv

        // RFC 7693 section 2.5: parameter block XOR'd into h[0]:
        //   digest_length (low byte), key_length (next byte), fanout=1, depth=1.
        // This is the sequential-mode parameterization; salt/personal/tree are zero.
        self.h[0] ^= 0x01010000 ^ UInt64(key.count) << 8 ^ UInt64(outputLength)

        self.buf = [UInt8](repeating: 0, count: Self.blockSize)
        self.bufLen = 0
        self.totalLen = 0

        // RFC 7693 section 3.3: keyed mode pads the key to one block and processes it
        // before the message.
        if !key.isEmpty {
            for i in 0..<key.count { self.buf[i] = key[i] }
            self.bufLen = Self.blockSize
        }
    }

    // MARK: - Streaming API

    /// Absorb `data` into the hash state. Accepts any byte sequence
    /// (e.g., `[UInt8]` or `Data`).
    public mutating func update(_ data: some Sequence<UInt8>) {
        for byte in data {
            // Flush a full buffer so the trailing block stays available for
            // `finalize`'s final-block flag.
            if bufLen == Self.blockSize {
                totalLen &+= UInt64(Self.blockSize)
                compress(last: false)
                bufLen = 0
            }
            buf[bufLen] = byte
            bufLen += 1
        }
    }

    /// Finish hashing and return the digest. The state must not be reused.
    public mutating func finalize() -> [UInt8] {
        // Pad the trailing block with zeros and mark it last.
        for i in bufLen..<Self.blockSize { buf[i] = 0 }
        totalLen &+= UInt64(bufLen)
        compress(last: true)

        var out = [UInt8](repeating: 0, count: outputLength)
        for i in 0..<outputLength {
            out[i] = UInt8((h[i / 8] >> ((i % 8) * 8)) & 0xff)
        }
        return out
    }

    // MARK: - Compression function (RFC 7693 section 3.2)

    private mutating func compress(last: Bool) {
        // Decode buf as 16 little-endian 64-bit words.
        var m = [UInt64](repeating: 0, count: 16)
        for i in 0..<16 {
            let off = i * 8
            var word: UInt64 = 0
            for byte in 0..<8 {
                word |= UInt64(buf[off + byte]) << (byte * 8)
            }
            m[i] = word
        }

        // Working vector v.
        var v = [UInt64](repeating: 0, count: 16)
        for i in 0..<8 {
            v[i] = h[i]
            v[i + 8] = Self.iv[i]
        }
        v[12] ^= totalLen
        // Inputs > 2^64 bytes are not supported, so v[13] stays zero.
        if last { v[14] = ~v[14] }

        // Twelve mixing rounds.
        for round in 0..<12 {
            let s = Self.sigma[round]
            mix(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            mix(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            mix(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            mix(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            mix(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            mix(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            mix(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            mix(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for i in 0..<8 { h[i] ^= v[i] ^ v[i + 8] }
    }

    @inline(__always)
    private func mix(
        _ v: inout [UInt64],
        _ a: Int,
        _ b: Int,
        _ c: Int,
        _ d: Int,
        _ x: UInt64,
        _ y: UInt64
    ) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = (v[d] ^ v[a]).rotR(32)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotR(24)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = (v[d] ^ v[a]).rotR(16)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotR(63)
    }
}

extension UInt64 {
    @inline(__always)
    fileprivate func rotR(_ n: Int) -> UInt64 {
        (self >> n) | (self << (64 - n))
    }
}

// MARK: - One-shot helpers

extension Blake2b {
    /// One-shot digest of `data`, `outputLength` bytes long.
    public static func hash(_ data: Data, outputLength: Int = 64, key: Data = Data()) -> Data {
        var b = Blake2b(outputLength: outputLength, key: Array(key))
        b.update(data)
        return Data(b.finalize())
    }
}
