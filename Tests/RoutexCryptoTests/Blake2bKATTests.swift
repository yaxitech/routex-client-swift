import Foundation
@_spi(Interop) import RoutexCrypto
import Testing

/// Unkeyed BLAKE2b-512 vectors, the add-on the keyed reference file lacks, from
/// the Python-generated ``Blake2bKATCorpus`` (lengths 0...32 plus block-boundary
/// cases), with the RFC 7693 "abc" and empty-input anchors.
@Suite("Blake2b: unkeyed KAT vectors")
struct Blake2bKATTests {
    /// KAT input of length `n`: `0x00 0x01 0x02 ... 0x(n-1)`.
    static func katInput(_ n: Int) -> Data { Data((0..<n).map { UInt8($0) }) }

    @Test("RFC 7693 appendix A.1: hash of \"abc\"")
    func rfcAbc() {
        let abc = Data("abc".utf8)
        let digest = Blake2b.hash(abc, outputLength: 64).hexString
        #expect(
            digest
                == ("ba80a53f981c4d0d6a2797b69f12f6e9"
                    + "4c212f14685ac4b74b12bb6fdbffa2d1"
                    + "7d87c5392aab792dc252d5de4533cc95"
                    + "18d38aa8dbf1925ab92386edd4009923")
        )
    }

    @Test("Empty input, 64-byte digest")
    func emptyDigest() {
        let digest = Blake2b.hash(Data(), outputLength: 64).hexString
        #expect(
            digest
                == ("786a02f742015903c6c6fd852552d272"
                    + "912f4740e15847618a86e217f71f5419"
                    + "d25e1031afee585313896444934eb04b"
                    + "903a685b1448b755d56f701afe9be2ce")
        )
    }

    @Test("Unkeyed inputs of length 0...32 across compression boundaries", arguments: 0...32)
    func unkeyed_short(length: Int) {
        let expected = Blake2bKATCorpus.unkeyedKAT[length]!
        let digest = Blake2b.hash(Self.katInput(length), outputLength: 64).hexString
        #expect(digest == expected, Comment(rawValue: "len=\(length)"))
    }

    @Test(
        "Unkeyed inputs that span multiple blocks",
        arguments: [33, 64, 65, 127, 128, 129, 192, 255]
    )
    func unkeyed_long(length: Int) {
        let expected = Blake2bKATCorpus.unkeyedKAT[length]!
        let digest = Blake2b.hash(Self.katInput(length), outputLength: 64).hexString
        #expect(digest == expected, Comment(rawValue: "len=\(length)"))
    }
}
