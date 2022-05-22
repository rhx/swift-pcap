//
//  AddressList.swift
//
//  Copyright (c) 2022 Rene Hexel, all rights reserved.
//  Created by Rene Hexel on 22/5/2022.
//
import CLibPCap

/// A class representing a list of interfaces
public struct AddressList: Sequence {
    /// Address sequence iterator
    public struct Iterator: IteratorProtocol {
        /// Pointer to the current element
        @usableFromInline var ptr: UnsafeMutablePointer<pcap_addr_t>?
        /// Return the next element in the sequence
        /// - Returns: Pointer to the next element
        @inlinable public mutating func next() -> Address? {
            defer { ptr = ptr?.pointee.next }
            return ptr.map(Address.init)
        }
        /// Designated initialiser
        @usableFromInline
        init(_ addresses: UnsafeMutablePointer<pcap_addr_t>?) {
            ptr = addresses
        }
    }
    /// The underlying list of addesses
    @usableFromInline
    var addresses: UnsafeMutablePointer<pcap_addr_t>?

    /// Designated initialiser for an interface list
    /// - Parameter pcapAddresses: Pointer to the underlying array of PCAP addresses
    @inlinable
    public init(_ pcapAddresses: UnsafeMutablePointer<pcap_addr_t>? = nil) {
        addresses = pcapAddresses
    }

    /// Create a sequence iterator
    /// - Returns: The iterator to use for enumerating the list
    @inlinable
    public func makeIterator() -> Iterator {
        Iterator(addresses)
    }
}
