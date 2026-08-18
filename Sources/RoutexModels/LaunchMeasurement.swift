import Foundation

/// Launch measurement of a TEE image.
///
/// One wire encoding is supported today (`v1`). The enum is left open so
/// future formats (e.g. a pre-VMSA + VMSA pair) can be added as additional
/// cases without a source-breaking change.
public enum LaunchMeasurement: Sendable, Hashable {
    /// 48-byte SHA-384 digest. Encoded as a bare base64 string.
    case v1(Data)
}

extension LaunchMeasurement: Codable {
    public init(from decoder: any Decoder) throws {
        // V1: bare base64 string.
        let single = try decoder.singleValueContainer()
        let s = try single.decode(String.self)
        guard let d = Data(base64Encoded: s) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "LaunchMeasurement v1 must be base64"
                )
            )
        }
        self = .v1(d)
    }

    public func encode(to encoder: any Encoder) throws {
        switch self {
        case .v1(let d):
            var c = encoder.singleValueContainer()
            try c.encode(d.base64EncodedString())
        }
    }
}
