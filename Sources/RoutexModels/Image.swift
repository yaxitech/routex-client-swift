import Foundation

/// Image data for a ``Dialog``, e.g. a photo TAN graphic.
public struct Image: Sendable, Hashable, Codable {
    /// MIME type of ``data`` (e.g. `"image/png"`, `"image/gif"`).
    public let mimeType: String
    /// Binary image bytes in the format defined by ``mimeType``.
    public let data: Data
    /// HHD\_UC data block.
    ///
    /// In cases where the ASPSP provides HHD\_UC data for optical coupling
    /// with a HandHeld-Device for the generation of an OTP, especially for
    /// an HHD\_OPT animated graphic, the raw HHD\_UC data stream is
    /// provided here. ``data`` provides a pre-rendered animated GIF to be
    /// presented with a width of 62.5 mm.
    public let hhdUCData: Data?

    /// Build an `Image`.
    public init(mimeType: String, data: Data, hhdUCData: Data? = nil) {
        self.mimeType = mimeType
        self.data = data
        self.hhdUCData = hhdUCData
    }

    private enum CodingKeys: String, CodingKey {
        case mimeType, data
        case hhdUCData = "hhdUcData"
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.mimeType = try c.decode(String.self, forKey: .mimeType)
        let s = try c.decode(String.self, forKey: .data)
        guard let d = Data(base64Encoded: s) else {
            throw DecodingError.dataCorruptedError(
                forKey: .data,
                in: c,
                debugDescription: "Image.data must be base64"
            )
        }
        self.data = d
        if let hs = try c.decodeIfPresent(String.self, forKey: .hhdUCData) {
            guard let hd = Data(base64Encoded: hs) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .hhdUCData,
                    in: c,
                    debugDescription: "Image.hhdUcData must be base64"
                )
            }
            self.hhdUCData = hd
        } else {
            self.hhdUCData = nil
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(mimeType, forKey: .mimeType)
        try c.encode(data.base64EncodedString(), forKey: .data)
        if let h = hhdUCData {
            try c.encode(h.base64EncodedString(), forKey: .hhdUCData)
        }
    }
}
