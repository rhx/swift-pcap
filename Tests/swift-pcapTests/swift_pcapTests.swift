import XCTest
@testable import swift_pcap

final class swift_pcapTests: XCTestCase {
    func testExample() throws {
        XCTAssertThrowsError(try PCAPDevice())
    }
}
