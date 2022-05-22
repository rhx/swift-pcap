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
    /// Discription of the last error that ocurred
    @inlinable
    public var error: PCAPError { PCAPError(pcap_geterr(handle)) }
    /// The current processing statistics
    @inlinable
    public var statistics: Statistics? {
        var statistics = Statistics()
        guard pcap_stats(handle, &statistics.stats) == 0 else { return nil }
        return statistics
    }
    /// The current snapshot length
    @inlinable
    public var snapshotLength: Int {
        get { Int(pcap_snapshot(handle)) }
        set { pcap_set_snaplen(handle, Int32(newValue)) }
    }

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

    deinit {
        guard let handle = handle else { return }
        pcap_close(handle)
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


    /// Loop through the packets in the capture file
    /// - Parameters:
    ///  - count: The number of packets to process, `-1` for no limit
    ///  - callback: The callback to call for each packet
    /// - Returns: `0` if the count was reached, `-1` if an error occurred, or `-2` if the loop was interrupted
    /// - Note: This function does not return when live read timeouts occur
    @usableFromInline
    func loop(count: Int32, holder: HandlerClosureHolder, cHandler: @escaping pcap_handler) -> Status {
        let userData = Unmanaged.passRetained(holder).toOpaque().assumingMemoryBound(to: u_char.self)
        let value = pcap_loop(handle, count, cHandler, UnsafeMutablePointer(mutating: userData))
        switch value {
        case 0:  return .completed
        case -1: return .error(error)
        case -2: return .interrupted
        default: return .partial(completed: Int(value))
        }
    }

    /// Loop through the packets in the capture file
    /// - Parameters:
    ///  - count: The number of packets to process, `nil` for no limit
    ///  - callback: The callback to call for each packet
    /// - Returns: The number of packets processed
    /// - Note: This function does not return when live read timeouts occur
    @inlinable
    public func loop(count: Int? = nil, callback: @escaping Handler) -> Status {
        loop(count: Int32(count ?? -1), holder: HandlerClosureHolder(callback)) {
            guard let holder = $0.map({ Unmanaged<HandlerClosureHolder>.fromOpaque($0).takeUnretainedValue() }),
                  let header = $1.map(PacketHeader.init) else { return }
            holder.callback(header, UnsafeBufferPointer(start: $2, count: header.count))
        }
    }

    /// Dispatch callback for each packet
    /// - Parameters:
    ///  - count: The number of packets to process, `-1` for no limit
    ///  - callback: The callback to call for each packet
    /// - Returns: The number of packets processed
    @usableFromInline
    func dispatch(count: Int32, holder: HandlerClosureHolder, cHandler: @escaping pcap_handler) -> Status {
        let userData = Unmanaged.passRetained(holder).toOpaque().assumingMemoryBound(to: u_char.self)
        let value = pcap_dispatch(handle, count, cHandler, UnsafeMutablePointer(mutating: userData))
        switch value {
        case 0:  return .completed
        case -1: return .error(error)
        case -2: return .interrupted
        default: return .partial(completed: Int(value))
        }
    }

    /// Dispatch callback for each packet
    /// - Parameters:
    ///  - count: The number of packets to process, `nil` for no limit
    ///  - callback: The callback to call for each packet
    /// - Returns: The number of packets processed
    @inlinable
    public func dispatch(count: Int? = nil, callback: @escaping Handler) -> Status {
        dispatch(count: Int32(count ??  -1), holder: HandlerClosureHolder(callback)) {
            guard let holder = $0.map({ Unmanaged<HandlerClosureHolder>.fromOpaque($0).takeUnretainedValue() }),
                  let header = $1.map(PacketHeader.init) else { return }
            holder.callback(header, UnsafeBufferPointer(start: $2, count: header.count))
        }
    }

    /// Break out of a `loop` or `dispatch` call
    @inlinable
    public func breakLoop() {
        pcap_breakloop(handle)
    }

    /// Get the next packet
    @inlinable
    public func next() -> (header: PacketHeader, content: UnsafeBufferPointer<UInt8>)? {
        var header = PacketHeader()
        guard let data = pcap_next(handle, &header.pcapHeader) else { return nil }
        return (header, UnsafeBufferPointer(start: data, count: header.count))
    }

    /// Send a packet
    /// - Parameters:
    ///  - packet: The packet to inject
    /// - Returns: The number of bytes sent, or `nil` if unsuccessful
    @inlinable
    public func inject(packet: UnsafeRawBufferPointer) -> Int? {
        let n = pcap_inject(handle, packet.baseAddress, size_t(packet.count))
        return n >= 0 ? Int(n) : nil
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
