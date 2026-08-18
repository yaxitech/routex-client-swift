import Foundation
@_spi(Interop) import RoutexCrypto
import Testing

/// Keyed BLAKE2b-512 Known Answer Tests parsed from the vendored BLAKE2
/// reference vectors (`Resources/blake2b-kat.txt`): the canonical 64-byte key
/// over inputs `00 01 ... (n-1)` for n = 0...255.
@Suite("Blake2b: reference KAT file")
struct Blake2bReferenceKATTests {
    struct Vector: Sendable {
        let index: Int
        let input: Data
        let key: Data
        let hash: Data
    }

    static let vectors: [Vector] = load()

    /// Parse the `in:`/`key:`/`hash:` triples from the vendored reference file.
    static func load() -> [Vector] {
        guard let url = Bundle.module.url(forResource: "blake2b-kat", withExtension: "txt"),
            let text = try? String(contentsOf: url, encoding: .utf8)
        else {
            return []
        }

        var vectors: [Vector] = []
        var input: Data?
        var key: Data?
        for rawLine in text.split(whereSeparator: { $0.isNewline }) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if let hex = field(line, "in:") {
                input = Data(hex: hex)
            } else if let hex = field(line, "key:") {
                key = Data(hex: hex)
            } else if let hex = field(line, "hash:") {
                if let input, let key, let hash = Data(hex: hex) {
                    vectors.append(Vector(index: vectors.count, input: input, key: key, hash: hash))
                }
                input = nil
                key = nil
            }
        }
        return vectors
    }

    private static func field(_ line: String, _ label: String) -> String? {
        guard line.hasPrefix(label) else { return nil }
        return String(line.dropFirst(label.count)).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    @Test("Vendored reference file yields all 256 keyed vectors")
    func corpusComplete() {
        #expect(Self.vectors.count == 256)
    }

    @Test("Keyed BLAKE2b-512 matches every reference vector")
    func matchesEveryVector() {
        for vector in Self.vectors {
            let digest = Blake2b.hash(vector.input, outputLength: 64, key: vector.key)
            #expect(
                digest == vector.hash,
                Comment(rawValue: "vector #\(vector.index), input length \(vector.input.count)")
            )
        }
    }
}
