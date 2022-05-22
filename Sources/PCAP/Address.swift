//
//  Address.swift
//  
//  Copyright (c) 2022 Rene Hexel, all rights reserved.
//  Created by Rene Hexel on 22/5/2022.
//
import CLibPCap

/// Representation of a network interface
public struct Address: CustomStringConvertible {
    /// A pointer to the underlying PCAP address type
    public let pcapAddress: UnsafeMutablePointer<pcap_addr_t>

    /// Designated initialiser
    /// - Parameter address: The address pointer to wrap
    @inlinable
    public init(_ address: UnsafeMutablePointer<pcap_addr_t>) {
        pcapAddress = address
    }

    /// A textual description of the address
    @inlinable
    public var description: String {
        pcapAddress.pointee.addr.flatMap { addr in
            withUnsafeTemporaryAllocation(of: CChar.self, capacity: 80) {
                inet_ntop(CInt(addr.pointee.sa_family), UnsafeRawPointer(addr), $0.baseAddress, socklen_t($0.count)).map { String(cString: $0) }
            }
        } ?? ""
    }

    /// A textual description of the netmask
    @inlinable
    public var netmask: String {
        pcapAddress.pointee.netmask.flatMap { mask in
            withUnsafeTemporaryAllocation(of: CChar.self, capacity: 80) {
                inet_ntop(CInt(mask.pointee.sa_family), UnsafeRawPointer(mask), $0.baseAddress, socklen_t($0.count)).map { String(cString: $0) }
            }
        } ?? ""
    }

    /// A textual description of the broadcast address
    @inlinable
    public var broadcastAddress: String {
        pcapAddress.pointee.broadaddr.flatMap { addr in
            withUnsafeTemporaryAllocation(of: CChar.self, capacity: 80) {
                inet_ntop(CInt(addr.pointee.sa_family), UnsafeRawPointer(addr), $0.baseAddress, socklen_t($0.count)).map { String(cString: $0) }
            }
        } ?? ""
    }

    /// A textual description of the destination address
    @inlinable
    public var destinationAddress: String {
        pcapAddress.pointee.dstaddr.flatMap { addr in
            withUnsafeTemporaryAllocation(of: CChar.self, capacity: 80) {
                inet_ntop(CInt(addr.pointee.sa_family), UnsafeRawPointer(addr), $0.baseAddress, socklen_t($0.count)).map { String(cString: $0) }
            }
        } ?? ""
    }
}
