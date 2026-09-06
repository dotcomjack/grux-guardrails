// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "GruxGuardrails",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "GruxGuardrails", targets: ["GruxGuardrails"])
    ],
    targets: [
        .target(name: "GruxGuardrails"),
        .testTarget(name: "GruxTests", dependencies: ["GruxGuardrails"])
    ]
)
