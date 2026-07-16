// swift-tools-version:5.9
// Causalontology - Swift Package Manager consumption of this repository:
//   .package(url: "https://github.com/ai-university-aiu/causalontology", from: "2.0.0")
// The library sources live under bindings/swift/; this root manifest exposes
// the library product only (the conformance runner stays inside bindings/swift).
import PackageDescription

let package = Package(
    name: "Causalontology",
    products: [
        .library(name: "Causalontology", targets: ["Causalontology"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "Causalontology",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")],
            path: "bindings/swift/Sources/Causalontology"),
    ]
)
