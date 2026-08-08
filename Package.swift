// swift-tools-version: 5.9
// █ dcj · dotcomjack.com · MIT
import PackageDescription

let package = Package(
    name: "GruxKit",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "GruxKit", targets: ["GruxKit"])
    ],
    targets: [
        .target(name: "GruxKit"),
        .testTarget(name: "GruxKitTests", dependencies: ["GruxKit"])
    ]
)
