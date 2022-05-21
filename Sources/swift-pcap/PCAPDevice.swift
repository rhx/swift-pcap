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
    /// The underlying error
    @inlinable
    public var error: PCAPError { PCAPError(pcap_geterr(handle)) }

    /// Open a device for live capturing
    /// - Parameters:
    ///   - device: Name of the interface to open, capturing on all interfaces if`nil`
    ///   - snapshotLength: The size of the snapshot to use
    ///   - isPromiscuous: Put the interface into promiscuous mode if `true`
    ///   - timeout: The packet buffer timeout in milliseconds
    @inlinable
    public init(liveDevice device: UnsafePointer<CChar>? = nil, snapshotLength: Int = 1500, isPromiscuous: Bool = true, timeout: Int = 500) throws {
        handle = try withUnsafeTemporaryAllocation(of: CChar.self, capacity: Int(PCAP_ERRBUF_SIZE)+1) { buffer in
            guard let ptr = pcap_open_live(device, CInt(snapshotLength), isPromiscuous ? 1 : 0, CInt(timeout), buffer.baseAddress) else {
                throw PCAPError(buffer.baseAddress)
            }
            return ptr
        }
    }

    /// Open a saved capture file for offline processing
    /// - Parameters:
    ///  - file: Name of the file to open
    @inlinable
    public init(file: UnsafePointer<CChar>? = nil) throws {
        handle = try withUnsafeTemporaryAllocation(of: CChar.self, capacity: Int(PCAP_ERRBUF_SIZE)+1) { buffer in
            guard let ptr = pcap_open_offline(file, buffer.baseAddress) else {
                throw PCAPError(buffer.baseAddress)
            }
            return ptr
        }
    }

    /// Compile a filter expression
    /// - Parameters:
    ///  - expression: The filter expression to compile
    ///  - doOptimize: Optimize the filter expression if `true`
    ///  - netmask: The netmask to use for the filter expression
    /// - Returns: The compiled program or `nil` if unsuccessful
    @inlinable
    public func compile(filterExpression expression: UnsafePointer<CChar>? = nil, doOptimize: Bool = true, netmask: bpf_u_int32 = PCAP_NETMASK_UNKNOWN) -> BPFProgram? {
        var filter = bpf_program()
        guard pcap_compile(handle, &filter, expression, doOptimize ? 1 : 0, netmask) == 0 else {
            return nil
        }
        return BPFProgram(filter)
    }

    /// Set the filter to be used
    /// - Parameters:
    ///  - filter: The filter to use
    @inlinable
    public func setFilter(_ filter: BPFProgram) {
        pcap_setfilter(handle, &filter.bpfProgram)
    }

    /// Print the last error to `stderr`
    /// - Parameter prefix: The text to prefix the error message with
    @inlinable
    public func printError(prefix: String = "pcap error") {
        pcap_perror(handle, prefix)
    }

    deinit {
        guard let handle = handle else { return }
        pcap_close(handle)
    }

    /// Find all devices
    @inlinable public static func findAllDevices() throws -> InterfaceList {
        let list = InterfaceList()
        var errorBuffer = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE)+1)
        guard pcap_findalldevs(&list.interfaces, &errorBuffer) == 0 else {
            throw PCAPError(errorBuffer)
        }
        return list
    }
}
