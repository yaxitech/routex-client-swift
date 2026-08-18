// Read-only random-access view over a `Data` buffer with helpers for the
// little-endian fixed-width integers that AMD SEV-SNP attestation reports
// encode their fields with.
//
// All accessors throw on out-of-bounds reads rather than crashing, so a
// malformed input can be rejected without taking down the process.

import Foundation

struct ByteReader {
    let data: Data

    init(_ data: Data) { self.data = data }

    /// Read `length` bytes starting at `offset`.
    func bytes(at offset: Int, length: Int) throws -> Data {
        guard offset >= 0, length >= 0,
            offset.addingReportingOverflow(length).overflow == false,
            offset + length <= data.count
        else {
            throw ByteReaderError.outOfBounds(offset: offset, length: length, total: data.count)
        }
        let start = data.startIndex + offset
        return data[start..<(start + length)]
    }

    /// Read a single byte at `offset`.
    func u8(at offset: Int) throws -> UInt8 {
        try bytes(at: offset, length: 1).first!
    }

    /// Read a little-endian `UInt32`.
    func u32LE(at offset: Int) throws -> UInt32 {
        let b = try bytes(at: offset, length: 4)
        return UInt32(b[b.startIndex])
            | UInt32(b[b.startIndex + 1]) << 8
            | UInt32(b[b.startIndex + 2]) << 16
            | UInt32(b[b.startIndex + 3]) << 24
    }

    /// Read a little-endian `UInt64`.
    func u64LE(at offset: Int) throws -> UInt64 {
        let b = try bytes(at: offset, length: 8)
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(b[b.startIndex + i]) << (i * 8) }
        return v
    }
}

enum ByteReaderError: Error, Sendable, Equatable {
    case outOfBounds(offset: Int, length: Int, total: Int)
}
