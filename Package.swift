// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Grux",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "Grux", targets: ["Grux"])
    ],
    targets: [
        .target(name: "Grux"),
        .testTarget(name: "GruxTests", dependencies: ["Grux"])
    ]
)
