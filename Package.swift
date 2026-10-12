// swift-tools-version: 6.4

import PackageDescription

let package = Package(
    name: "swift-jovian",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "Jovian", targets: ["Jovian"]),
        .executable(name: "jovian", targets: ["JovianCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.8.2"),
        .package(url: "https://github.com/apple/swift-asn1", from: "1.1.0"),
        .package(url: "https://github.com/apple/swift-certificates", from: "1.21.0"),
        .package(url: "https://github.com/apple/swift-collections", from: "1.7.1"),
        .package(url: "https://github.com/apple/swift-crypto", from: "5.0.0"),
        .package(url: "https://github.com/apple/swift-log", from: "1.15.1"),
        .package(url: "https://github.com/apple/swift-nio", from: "2.103.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl", from: "2.37.5"),
    ],
    targets: [
        .systemLibrary(name: "CZlib"),
        .target(
            name: "Jovian",
            dependencies: [
                "CZlib",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "DequeModule", package: "swift-collections"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "X509", package: "swift-certificates"),
            ]),
        .executableTarget(
            name: "JovianCLI",
            dependencies: [
                "Jovian", .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
            ]),
        .testTarget(
            name: "JovianTests",
            dependencies: [
                "Jovian",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "X509", package: "swift-certificates"),
            ]),
        .testTarget(name: "JovianCLITests", dependencies: ["JovianCLI"]),
    ]
)
