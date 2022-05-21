//
//  PacketHeader.swift
//
//  Copyright (c) 2022 Rene Hexel, all rights reserved.
//  Created by Rene Hexel on 22/5/2022.
//
import CLibPCap

/// Representation of a packet header interface
public struct PacketHeader: CustomStringConvertible {
    /// A pointer to the underlying PCAP address type
    public let pcapHeader: UnsafeMutablePointer<pcap_pkthdr>

    /// Designated initialiser
    /// - Parameter header: The header pointer to wrap
    @inlinable
    public init(_ header: UnsafeMutablePointer<pcap_pkthdr>) {
        pcapHeader = header
    }

    /// A textual description of the address
    @inlinable
    public var description: String {
        pcapHeader.withMemoryRebound(to: CChar.self, capacity: MemoryLayout<pcap_pkthdr>.size) {
            String(cString: $0 + MemoryLayout<pcap_pkthdr>.offset(of: \.comment)!)
        }
    }

    /// Length of the portion present
    @inlinable
    public var count: Int {
        Int(pcapHeader.pointee.caplen)
    }

    /// Size of this packet (off-wire)
    @inlinable
    public var size: Int {
        Int(pcapHeader.pointee.len)
    }

    /// Time stamp
    @inlinable
    public var timeStamp: timeval {
        pcapHeader.pointee.ts
    }
}
