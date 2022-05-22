import XCTest
@testable import swift_pcap

final class swift_pcapTests: XCTestCase {
    func testDevices() throws {
        let list = try PCAPDevice.findAllDevices()
        XCTAssertNotNil(list.interfaces)
    }
}
