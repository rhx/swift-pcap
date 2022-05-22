import XCTest
@testable import PCAP

final class PCAPTests: XCTestCase {
    func testDevices() throws {
        let list = try PCAPDevice.findAllDevices()
        XCTAssertNotNil(list.interfaces)
    }
}
