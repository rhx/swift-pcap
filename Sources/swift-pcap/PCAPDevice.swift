//
//  PCAPDevice.swift
//
//  Copyright (c) 2022 Rene Hexel, all rights reserved.
//  Created by Rene Hexel on 21/5/2022.
//
import CLibPCap

/// Representation of the underlying Packet capturing device
public final class PCAPDevice {
    /// The underlying `libpcap` handle
    public var handle: UnsafeMutablePointer<pcap_t>! = nil
    /// A buffer holding the last error that occurred
    @usableFromInline
    var errorBuffer = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE)+1)

    /// Open a device for live capturing
    /// - Parameters:
    ///   - device: Name of the interface to open, capturing on all interfaces if`nil`
    ///   - snapshotLength: The size of the snapshot to use
    ///   - isPromiscuous: Put the interface into promiscuous mode if `true`
    ///   - timeout: The packet buffer timeout in milliseconds
    @inlinable
    public init(liveDevice device: UnsafePointer<CChar>? = nil, snapshotLength: Int = 1500, isPromiscuous: Bool = true, timeout: Int = 500) throws {
        guard let ptr = errorBuffer.withUnsafeMutableBufferPointer({ (buffer: inout UnsafeMutableBufferPointer<CChar>) -> UnsafeMutablePointer<pcap_t>? in
            pcap_open_live(device, CInt(snapshotLength), isPromiscuous ? 1 : 0, CInt(timeout), buffer.baseAddress)
        }) else {
            throw PCAPError(rawValue: String(cString: errorBuffer))
        }
        handle = ptr
    }

    deinit {
        guard let handle = handle else { return }
        pcap_close(handle)
    }
}
