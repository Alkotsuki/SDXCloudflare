// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SDXCloudflare",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "SDXCloudflare", targets: ["SDXCloudflare"]),
    ],
    targets: [
        .target(name: "SDXCloudflare"),
        .testTarget(name: "SDXCloudflareTests", dependencies: ["SDXCloudflare"]),
    ]
)
