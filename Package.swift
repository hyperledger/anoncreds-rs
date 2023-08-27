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
            path: "uniffi/output-frameworks/anoncreds-swift/AnoncredsSwift/Sources/Swift"
        ),
        .target(
            name: "anoncredsFFI",
            dependencies: ["libanoncreds"],
            path: "uniffi/output-frameworks/anoncreds-swift/AnoncredsSwift/Sources/C"),
        // LOCAL
//        .binaryTarget(
//            name: "libanoncreds",
//            path: "./uniffi/output-frameworks/anoncreds-swift/libanoncreds.xcframework.zip"
//        )
        // RELEASE
        .binaryTarget(
            name: "libanoncreds",
            url: "https://github.com/input-output-hk/anoncreds-rs/releases/download/0.1.0/libanoncreds.xcframework.zip",
            checksum: "d4f909adbdd2912ed9fc869aa4b8eba679fb68cf7a0d18887af150f72f08115b"
        )
    ]
)
