//
//  Interface.swift
//  
//  Copyright (c) 2022 Rene Hexel, all rights reserved.
//  Created by Rene Hexel on 22/5/2022.
//
import CLibPCap

/// Representation of a network interface
public struct Interface: CustomStringConvertible {
    /// Interface flags
    public struct Flags: OptionSet {
        /// The underlying flags as a bit set
        public let rawValue: UInt32
        /// Designated initialiser
        @inlinable
        public init(rawValue: UInt32 = 0) {
            self.rawValue = rawValue
        }
        /// Signed value initialiser
        @inlinable
        public init(_ signed: Int32) {
            rawValue = .init(bitPattern: signed)
        }
        /// Interface is a loopback interface
        public static let loopback = Flags(PCAP_IF_LOOPBACK)
        /// Interface is up
        public static let up = Flags(PCAP_IF_UP)
        /// Interface is running
        public static let running = Flags(PCAP_IF_RUNNING)
        /// Interface is a wireless interface
        public static let wireless = Flags(PCAP_IF_WIRELESS)
    }
    /// A pointer to the underlying PCAP interface type
    public var pcapInterface: UnsafeMutablePointer<pcap_if_t>

    /// Designated initialiser
    /// - Parameter interface: The interface pointer to wrap
    @inlinable
    public init(_ interface: UnsafeMutablePointer<pcap_if_t>) {
        pcapInterface = interface
    }

    /// Interface flags
    @inlinable
    public var flags: Flags {
        Flags(rawValue: pcapInterface.pointee.flags)
    }

    /// A textual description of the interface
    /// - Note: The description can be empty
    @inlinable
    public var description: String {
        pcapInterface.pointee.description.map {
            String(cString: $0)
        } ?? ""
    }

    /// The name of the interface
    @inlinable
    public var name: String {
        pcapInterface.pointee.name.map {
            String(cString: $0)
        } ?? ""
    }

    /// The next interface in the list
    @inlinable
    public var next: Interface? {
        pcapInterface.pointee.next.map(Interface.init)
    }
}
