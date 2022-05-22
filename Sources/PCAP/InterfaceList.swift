//
//  InterfaceList.swift
//
//  Copyright (c) 2022 Rene Hexel, all rights reserved.
//  Created by Rene Hexel on 22/5/2022.
//
import CLibPCap

/// A class representing a list of interfaces
public final class InterfaceList: Sequence {
    /// Interface sequence iterator
    public struct Iterator: IteratorProtocol {
        /// Pointer to the current element
        @usableFromInline var ptr: UnsafeMutablePointer<pcap_if_t>?
        /// Return the next element in the sequence
        /// - Returns: Pointer to the next element
        @inlinable public mutating func next() -> Interface? {
            defer { ptr = ptr?.pointee.next }
            return ptr.map(Interface.init)
        }
        /// Designated initialiser
        @usableFromInline
        init(_ interfaces: UnsafeMutablePointer<pcap_if_t>?) {
            ptr = interfaces
        }
    }
    /// The underlying list of interfaces
    @usableFromInline
    var interfaces: UnsafeMutablePointer<pcap_if_t>?

    /// Designated initialiser for an interface list
    /// - Parameter pcapInterfaces: Pointer to the underlying array of PCAP interfaces
    @inlinable
    public init(_ pcapInterfaces: UnsafeMutablePointer<pcap_if_t>? = nil) {
        interfaces = pcapInterfaces
    }

    /// Create a sequence iterator
    /// - Returns: The iterator to use for enumerating the list
    @inlinable
    public func makeIterator() -> Iterator {
        Iterator(interfaces)
    }

    deinit {
        guard let interfaces = interfaces else { return }
        pcap_freealldevs(interfaces)
    }
}
