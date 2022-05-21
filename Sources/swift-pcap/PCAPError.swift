//
//  PCAPError.swift
//  
//  Copyright (c) 2022 Rene Hexel, all rights reserved.
//  Created by Rene Hexel on 21/5/2022.
//
import Foundation

/// An PCAP Error
public struct PCAPError: Error, RawRepresentable, CustomStringConvertible {
    /// A description of the error
    public var description: String = ""
    /// Raw error description
    public var rawValue: String { description }

    /// Construct an error from the given string
    /// - Parameter rawValue: Raw error description
    public init(rawValue: String) {
        description = rawValue
    }
}
