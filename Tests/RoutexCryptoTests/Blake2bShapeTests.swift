import Foundation
@_spi(Interop) import RoutexCrypto
import Testing

/// Behavior tests beyond the KAT vectors: variable digest lengths, streaming
/// equivalence, and the HMAC/HKDF wrappers.
@Suite("Blake2b: shape and streaming")
struct Blake2bShapeTests {
    /// Empty-input digests at lengths 1...64 (independent Python values). A short
    /// digest is not a prefix of the 64-byte one: the length feeds the parameter block.
    @Test("Variable digest lengths produce the expected empty-input digests")
    func emptyAcrossLengths() {
        let cases: [(Int, String)] = [
            (1, "2e"),
            (16, "cae66941d9efbd404e4d88758ea67670"),
            (20, "3345524abf6bbe1809449224b5972c41790b6cf2"),
            (32, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"),
            (
                48,
                "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100"
            ),
            (
                63,
                "4ded8c5fc8b12f3273f877ca585a44ad6503249a2b345d6d9c0e67d85bcb700db4178c0303e93b8f4ad758b8e2c9fd8b3d0c28e585f1928334bb77d36782e8"
            ),
            (
                64,
                "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
            ),
        ]
        for (n, expectedHex) in cases {
            let digest = Blake2b.hash(Data(), outputLength: n).hexString
            #expect(digest == expectedHex, Comment(rawValue: "len=\(n)"))
        }
    }

    @Test("Streaming update equals one-shot hash")
    func streamingEqualsOneShot() {
        let payload = Data((0..<512).map { UInt8($0 & 0xff) })
        let oneShot = Blake2b.hash(payload, outputLength: 64)

        var b = Blake2b(outputLength: 64)
        b.update(payload.prefix(7))
        b.update(payload[7..<200])
        b.update(payload[200..<350])
        b.update(payload[350..<512])
        #expect(Data(b.finalize()) == oneShot)
    }

    @Test("Byte-at-a-time updates match one-shot at block boundaries")
    func blockBoundaries() {
        // Guards the buffer-flush edge: a full block left buffered, then finalize().
        for n in [128, 256, 257] {
            let payload = Data((0..<n).map { UInt8($0 & 0xff) })
            let oneShot = Blake2b.hash(payload, outputLength: 64)
            var b = Blake2b(outputLength: 64)
            for byte in payload { b.update([byte]) }
            #expect(Data(b.finalize()) == oneShot, Comment(rawValue: "len=\(n)"))
        }
    }

    // MARK: - HMAC

    /// HMAC-BLAKE2b-512 vectors from Python's hmac.new with blake2b.
    @Test(
        "HMAC-Blake2b-512 matches Python hmac.new vectors",
        arguments: [
            (
                Data(), Data(),
                "198cd2006f66ff83fbbd913f78aca2251caf4f19fe9475aade8cf2091b99a68466775177424f58286886cbae8229644cec747237d4b721735485e17372fdf59c"
            ),
            (
                Data("key".utf8), Data("message".utf8),
                "04e9ada930688cde75eec939782eed653073dd621d7643f813702976257cf037d325b50eedd417c01b6ad1f978fbe2980a93d27d854044e8626df6fa279d6680"
            ),
            (
                Data((0..<32).map(UInt8.init)), Data("hello world".utf8),
                "d77f8a24a607e559c6cc6a2f986b530b38b82035eaf80a3981bc3dc755953b8d24580adf8da1a6e609114bb3bd6729c0460720b748f6ff3d3c938c8d0d9ddbd8"
            ),
            (
                Data((0..<200).map { UInt8(($0 * 7) % 256) }),
                Data(repeating: UInt8(ascii: "A"), count: 256),
                "2e1667503b9375e7ab084596efe02dd4a901f497be9a2c66b755d3ecc0810c53b09ab1d44c6d95df6f9a911c85fbbfa503f591aacd59a699067180b76f3ecc38"
            ),
        ] as [(Data, Data, String)]
    )
    func hmacVectors(_ key: Data, _ message: Data, _ expected: String) {
        #expect(HMACBlake2b.mac(key: key, message: message).hexString == expected)
    }

    @Test("HMAC-Blake2b-512 keys off the bytes, not the slice indices")
    func hmacSlicedKey() {
        let backing = Data(repeating: 0x00, count: 8) + Data(repeating: 0x5a, count: 16)
        let slice = backing.dropFirst(8)
        #expect(slice.startIndex != 0)
        #expect(
            HMACBlake2b.mac(key: slice, message: Data([1, 2, 3]))
                == HMACBlake2b.mac(key: Data(Array(slice)), message: Data([1, 2, 3]))
        )
    }

    @Test("HMAC-Blake2b-512 reduces an oversized key to its digest")
    func hmacOversizedKey() {
        let bigKey = Data(repeating: 0xab, count: 200)  // > blockSize
        let direct = HMACBlake2b.mac(key: bigKey, message: Data())
        let viaHash = HMACBlake2b.mac(
            key: Blake2b.hash(bigKey, outputLength: 64),
            message: Data()
        )
        #expect(direct == viaHash)
    }

    // MARK: - HKDF

    /// HKDF-BLAKE2b-512 vectors (independent Python reference) pinning the
    /// empty-salt case, the routex info layout, and the multi-block expand path.
    @Test("HKDF-Blake2b-512 vectors")
    func hkdfVectors() {
        // Empty salt and info.
        let a = HKDFBlake2b512.deriveKey(
            ikm: Data(repeating: 0x42, count: 32),
            salt: Data(),
            info: Data(),
            length: 32
        )
        #expect(a.hexString == "5df4637a64001a2fc818239382eff2485523d3fa808ba15ace4a36365f40f218")

        // routex info layout: eph_pk(0x01..) || my_pk(0x02..).
        let info = Data(repeating: 0x01, count: 32) + Data(repeating: 0x02, count: 32)
        let b = HKDFBlake2b512.deriveKey(
            ikm: Data(repeating: 0x42, count: 32),
            salt: Data(),
            info: info,
            length: 32
        )
        #expect(b.hexString == "792f7e0df678d7c2f434e48d86c65cf8e5e900bf711b37595ce7f39b5c2ec236")

        // 128-byte OKM: multi-block expand.
        let c = HKDFBlake2b512.deriveKey(
            ikm: Data("IKM".utf8),
            salt: Data("salt".utf8),
            info: Data("info".utf8),
            length: 128
        )
        #expect(
            c.hexString
                == "1b7d9f22ce1871fb4f191cea434d8aeee60353288fcc4cff6ee7ee16681ec6432aefc339bf6dd3aba099b64d025c4ff141fe9e3d08ddaabac58aa78ed3a620a8d543d8fc25f3809c1ca40679781415265945ea9f57faf7e898f4fa42c76c27cacbec97014202b47de78f83aecfcb62b12caa3f5e30ac6b9e10269dacce1141cf"
        )
    }

    @Test("digest length 12 matches the reference (the ChaChaBox nonce length)")
    func blake2b96() {
        #expect(Blake2b.hash(Data(), outputLength: 12).hexString == "b8e1dda3ac0aa3820ad2990b")
        // routex nonce input layout: eph_pk(0x01..) || recipient_pk(0x02..).
        let info = Data(repeating: 0x01, count: 32) + Data(repeating: 0x02, count: 32)
        #expect(Blake2b.hash(info, outputLength: 12).hexString == "a8d5c122afc32252264a5fc2")
    }

    @Test("HKDF-Blake2b-512 longer output extends shorter")
    func hkdfLongOutputConsistency() {
        // RFC 5869 section 2.3: OKM(L+k) starts with OKM(L).
        let ikm = Data(repeating: 0x55, count: 16)
        let salt = Data("salty".utf8)
        let info = Data("ctx".utf8)
        let short = HKDFBlake2b512.deriveKey(ikm: ikm, salt: salt, info: info, length: 32)
        let long = HKDFBlake2b512.deriveKey(ikm: ikm, salt: salt, info: info, length: 128)
        #expect(long.prefix(32) == short)
    }
}
