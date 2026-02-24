// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "routex-client-swift",

  platforms: [
    .iOS(.v15),
    .macOS(.v12),
  ],

  products: [
    .library(
      name: "RoutexClient",
      targets: ["Routex", "RoutexClientFFI"])
  ],

  dependencies: [
    // N.B. only used in tests to issue JWTs, not a recommendation
    .package(url: "https://github.com/vapor/jwt-kit", "5.0.0"..<"5.3.0")
  ],

  targets: [
    .target(name: "Routex", dependencies: ["RoutexClientFFI"]),
    .binaryTarget(name: "RoutexClientFFI", path: "./RoutexClientFFI.xcframework"),
    .testTarget(name: "RoutexClientTests", dependencies: ["Routex", .product(name: "JWTKit", package: "jwt-kit")]),
  ]
)
