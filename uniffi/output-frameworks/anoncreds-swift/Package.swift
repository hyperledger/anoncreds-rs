// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "AnoncredsSwift",
    platforms: [
        .iOS(.v13),
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "AnoncredsSwift",
            type: .dynamic,
            targets: ["AnoncredsSwift"]
        ),
    ],
    targets: [
        .target(
            name: "AnoncredsSwift",
            dependencies: ["anoncredsFFI"],
            path: "AnoncredsSwift/Sources/Swift"
        ),
        .target(
            name: "anoncredsFFI",
            dependencies: ["libanoncreds"],
            path: "AnoncredsSwift/Sources/C"),
        .binaryTarget(
            name: "libanoncreds",
            path: "./libanoncreds.xcframework.zip"
        )
    ]
)
