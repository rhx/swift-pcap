// swift-tools-version: 5.6

import PackageDescription

let package = Package(
    name: "swift-pcap",
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "swift-pcap",
            targets: ["swift-pcap"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
    ],
    targets: [
        .systemLibrary(
            name: "CLibPCap",
            providers: [
                .brew(["libpcap"]),
                .apt(["libpcap-dev"])
            ]),
        .target(
            name: "swift-pcap",
            dependencies: ["CLibPCap"]),
        .testTarget(
            name: "swift-pcapTests",
            dependencies: ["swift-pcap"]),
    ]
)
