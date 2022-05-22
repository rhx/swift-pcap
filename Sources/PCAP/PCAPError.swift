//
//  PCAPError.swift
//  
//  Copyright (c) 2022 Rene Hexel, all rights reserved.
//  Created by Rene Hexel on 21/5/2022.
//
import Foundation
import CLibPCap

/// An PCAP Error
public struct PCAPError: Error, RawRepresentable, CustomStringConvertible {
    /// A description of the error
    public var description: String = ""
    /// Raw error description
    public var rawValue: String { description }

    /// Construct an error from the given string
    /// - Parameter rawValue: Raw error description
    @inlinable
    public init(rawValue: String) {
        description = rawValue
    }

    /// Construct an error from the given character pointer
    @inlinable
    public init(_ pointer: UnsafePointer<CChar>?) {
        description = pointer.map { String(cString: $0) } ?? "no error"
    }

    /// Construct an error from the given code
    @inlinable
    public init(code: CInt) {
        switch code {
        case PCAP_WARNING:                       description = "pcap warning"
        case PCAP_WARNING_PROMISC_NOTSUP:        description = "promiscuous mode not supported"
        case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:    description = "timestamp type not supported"
        case PCAP_ERROR:                         description = "pcap error"
        case PCAP_ERROR_BREAK:                   description = "loop terminated"
        case PCAP_ERROR_ACTIVATED:               description = "capturing already activated"
        case PCAP_ERROR_NOT_ACTIVATED:           description = "capturing not activated"
        case PCAP_ERROR_NO_SUCH_DEVICE:          description = "no such device"
        case PCAP_ERROR_NOT_RFMON:               description = "not in monitoring mode"
        case PCAP_ERROR_RFMON_NOTSUP:            description = "monitoring mode not supported"
        case PCAP_ERROR_PERM_DENIED:             description = "permission denied"
        case PCAP_ERROR_IFACE_NOT_UP:            description = "interface is inactive"
        case PCAP_ERROR_CANTSET_TSTAMP_TYPE:     description = "timestamp type cannot be set"
        case PCAP_ERROR_TSTAMP_PRECISION_NOTSUP: description = "timestamp precision not supported"
        case PCAP_ERROR_PROMISC_PERM_DENIED:     description = "promiscuous mode permission denied"
        default:
            description = "unknown error"
        }
    }
}
