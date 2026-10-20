// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SDXCloudflare",
    platforms: [
        .iOS(.v16)
    ],
    products: [
        .library(name: "SDXCloudflare", targets: ["SDXCloudflare"]),
    ],
    dependencies: [
        .package(url: "https://github.com/firebase/firebase-ios-sdk.git", from: "13.0.0"),
    ],
    targets: [
        .target(
            name: "SDXCloudflare",
            dependencies: [.product(name: "FirebaseAppCheck", package: "firebase-ios-sdk")]
        ),
        .testTarget(name: "SDXCloudflareTests", dependencies: ["SDXCloudflare"]),
    ]
)
