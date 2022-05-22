//
//  PacketHeader.swift
//
//  Copyright (c) 2022 Rene Hexel, all rights reserved.
//  Created by Rene Hexel on 22/5/2022.
//
import CLibPCap

/// Representation of a packet header interface
public struct PacketHeader: CustomStringConvertible {
    /// The underlying PCAP header
    public var pcapHeader = pcap_pkthdr()

    /// Designated initialiser
    @inlinable
    public init() {}

    /// Copying initialiser
    /// - Parameter header: Pointer to the header to copy
    @inlinable
    public init(_ header: UnsafePointer<pcap_pkthdr>) {
        pcapHeader = header.pointee
    }

    /// A textual description of the address
    @inlinable
    public var description: String {
        var hdr = pcapHeader
        return withUnsafePointer(to: &hdr) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout<pcap_pkthdr>.size) {
                String(cString: $0 + MemoryLayout<pcap_pkthdr>.offset(of: \.comment)!)
            }
        }
    }

    /// Length of the portion present
    @inlinable
    public var count: Int {
        Int(pcapHeader.caplen)
    }

    /// Size of this packet (off-wire)
    @inlinable
    public var size: Int {
        Int(pcapHeader.len)
    }

    /// Time stamp
    @inlinable
    public var timeStamp: timeval {
        pcapHeader.ts
    }
}
