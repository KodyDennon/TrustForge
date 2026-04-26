// swift-tools-version:5.9
//
// TrustForge Swift adapters: shared SDK + framework modules.

import PackageDescription

let package = Package(
    name: "TrustForge",
    platforms: [
        .macOS(.v12),
        .iOS(.v15),
        .tvOS(.v15),
        .watchOS(.v8)
    ],
    products: [
        .library(name: "TrustForgeSDK", targets: ["TrustForgeSDK"]),
        .library(name: "TrustForgeVapor", targets: ["TrustForgeVapor"]),
        .library(name: "TrustForgePerfect", targets: ["TrustForgePerfect"])
    ],
    dependencies: [],
    targets: [
        // The SDK has no external deps so the test target can run on bare swift.
        .target(
            name: "TrustForgeSDK",
            path: "Sources/TrustForgeSDK"
        ),
        // Vapor / Perfect adapters intentionally do NOT depend on Vapor or Perfect
        // SwiftPM packages: that would force a heavyweight dep tree on every build.
        // Instead they declare protocol-shaped interfaces that match Vapor's
        // `Middleware` and Perfect's `HTTPRequestFilter`, with bridge types
        // exported for adapter users to plug into their app.
        .target(
            name: "TrustForgeVapor",
            dependencies: ["TrustForgeSDK"],
            path: "Sources/TrustForgeVapor"
        ),
        .target(
            name: "TrustForgePerfect",
            dependencies: ["TrustForgeSDK"],
            path: "Sources/TrustForgePerfect"
        ),
        .testTarget(
            name: "TrustForgeSDKTests",
            dependencies: ["TrustForgeSDK"],
            path: "Tests/TrustForgeSDKTests"
        ),
        .testTarget(
            name: "TrustForgeVaporTests",
            dependencies: ["TrustForgeVapor"],
            path: "Tests/TrustForgeVaporTests"
        ),
        .testTarget(
            name: "TrustForgePerfectTests",
            dependencies: ["TrustForgePerfect"],
            path: "Tests/TrustForgePerfectTests"
        )
    ]
)
