// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "routex-client-swift",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .macCatalyst(.v15),
        .tvOS(.v15),
        .watchOS(.v8),
    ],
    products: [
        .library(name: "RoutexClient", targets: ["RoutexClient"]),
        .library(name: "RoutexCrypto", targets: ["RoutexCrypto"]),
        .library(name: "RoutexRefresh", targets: ["RoutexRefresh"]),
        .library(name: "RoutexModels", targets: ["RoutexModels"]),
        .library(name: "RoutexTransport", targets: ["RoutexTransport"]),
        .library(name: "RoutexSettlement", targets: ["RoutexSettlement"]),
        .library(name: "RoutexTickets", targets: ["RoutexTickets"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto", from: "4.5.0"),
        .package(url: "https://github.com/apple/swift-asn1", from: "1.7.0"),
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.5.0"),
    ],
    targets: [
        .target(name: "RoutexModels"),
        .target(name: "RoutexTransport"),
        .target(
            name: "RoutexCrypto",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
        .target(
            name: "RoutexSettlement",
            dependencies: [
                "RoutexCrypto",
                "RoutexModels",
                "RoutexTransport",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
        .target(
            name: "RoutexCore",
            dependencies: [
                "RoutexModels",
                "RoutexTransport",
                "RoutexSettlement",
            ]
        ),
        .target(
            name: "RoutexClient",
            dependencies: [
                "RoutexCore",
                "RoutexModels",
                "RoutexTransport",
                "RoutexSettlement",
            ]
        ),
        .target(
            name: "RoutexRefresh",
            dependencies: [
                "RoutexCore",
                "RoutexModels",
                "RoutexTransport",
                "RoutexSettlement",
            ]
        ),
        .target(
            name: "RoutexTickets",
            dependencies: [
                "RoutexModels",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "RoutexTicketsTests",
            dependencies: [
                "RoutexModels",
                "RoutexTickets",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "RoutexCryptoTests",
            dependencies: ["RoutexCrypto"],
            resources: [.copy("Resources/blake2b-kat.txt")]
        ),
        .testTarget(
            name: "RoutexSettlementTests",
            dependencies: [
                "RoutexCrypto",
                "RoutexModels",
                "RoutexSettlement",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(name: "RoutexClientTests", dependencies: ["RoutexClient", "RoutexCore"]),
        .testTarget(
            name: "RoutexRefreshTests",
            dependencies: ["RoutexRefresh", "RoutexCore", "RoutexModels"]
        ),
        .testTarget(
            name: "RoutexLiveTests",
            dependencies: [
                "RoutexClient",
                "RoutexCrypto",
                "RoutexRefresh",
                "RoutexCore",
                "RoutexModels",
                "RoutexSettlement",
                "RoutexTransport",
                "RoutexTickets",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
