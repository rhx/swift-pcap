//
//  Statistics.swift
//  
//  Copyright (c) 2022 Rene Hexel, all rights reserved.
//  Created by Rene Hexel on 22/5/2022.
//
import CLibPCap

public extension PCAPDevice {
    /// Package capturing statistics
    struct Statistics {
        /// The underlying structure filled by `pcap_stats()`
        public var stats = pcap_stat()
        /// The number or packages received
        @inlinable
        public var received: Int { Int(stats.ps_recv) }
        /// The number of packages dropped
        @inlinable
        public var dropped: Int { Int(stats.ps_drop) }
        /// The number of packages dropped by the interface
        /// - Note: This is the number of packets dropped by the interface, not the number of packets dropped by the operating system
        /// - Note: This is only supported on some platforms
        @inlinable
        public var ifDropped: Int { Int(stats.ps_ifdrop) }

        /// Designated initialiser
        @usableFromInline init() {}
    }
}
