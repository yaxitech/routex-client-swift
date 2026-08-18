// Built-in Ed25519 verifying keys for the `SystemVersionEntry` returned by
// the TEE during key settlement. Indexed by `keyID`.

import Foundation

enum YaxiSystemVersionKeys {
    static let `default`: [String: Data] = [
        "AhrUXsV/XAvIE24RQ/Vt/zXoLodvjXoWD2fhLGuRM7U=":
            Data([
                101, 188, 76, 33, 245, 155, 42, 79,
                214, 181, 125, 49, 68, 133, 87, 232,
                123, 91, 209, 21, 239, 36, 195, 215,
                82, 140, 160, 195, 236, 111, 180, 226,
            ]),
        "D30zRYe8Ug9732b4Pe2BAwWAXn/T5Nss2HJOp3kLC1w=":
            Data([
                8, 203, 107, 97, 17, 140, 16, 240,
                29, 197, 104, 26, 179, 115, 86, 2,
                210, 73, 107, 211, 46, 34, 89, 174,
                117, 193, 126, 215, 12, 133, 106, 37,
            ]),
    ]
}
