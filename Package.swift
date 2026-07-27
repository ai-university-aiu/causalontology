// swift-tools-version:5.9
// Causalontology - Swift Package Manager consumption of this repository:
//   .package(url: "https://github.com/ai-university-aiu/causalontology", from: "4.0.3")
// v4.0.3 is the tag the tag-based channels point at. This line read
// `from: "2.0.0"` throughout the 4.0.0 release: SwiftPM reads `from:` as
// ">= 2.0.0, < 3.0.0", so anyone who copied it out of this file would have
// been pinned to the 2.0.0 line while README.md and PUBLISHING.md both told
// them 4.0.3. The three now agree.
// The library sources live under bindings/swift/; this root manifest exposes
// the library product only (the conformance runner stays inside bindings/swift).
import PackageDescription

let package = Package(
    name: "Causalontology",
    products: [
        .library(name: "Causalontology", targets: ["Causalontology"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.5.1"),
    ],
    targets: [
        .target(
            name: "Causalontology",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")],
            path: "bindings/swift/Sources/Causalontology"),
    ]
)
