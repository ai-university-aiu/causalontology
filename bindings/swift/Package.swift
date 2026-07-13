// swift-tools-version:5.9
// Package manifest for causalontology-swift, the Swift binding of the
// Causalontology standard. One dependency only: swift-crypto, Apple's
// Linux-compatible crypto package, used for SHA-256 and Ed25519
// (Curve25519.Signing). Everything else is hand-written from the
// specification, ported faithfully from the Python binding.

import PackageDescription

let package = Package(
    name: "Causalontology",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "Causalontology",
            targets: ["Causalontology"]
        ),
        .executable(
            name: "conformance",
            targets: ["conformance"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")
    ],
    targets: [
        .target(
            name: "Causalontology",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ]
        ),
        .executableTarget(
            name: "conformance",
            dependencies: [
                "Causalontology",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
    ]
)
