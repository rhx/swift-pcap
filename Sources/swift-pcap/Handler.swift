//
//  Handler.swift
//  
//  Copyright (c) 2022 Rene Hexel, all rights reserved.
//  Created by Rene Hexel on 22/5/2022.
//
import CLibPCap

public typealias Handler = (PacketHeader, UnsafeBufferPointer<UInt8>) -> Void

/// Internal class that wraps a packet handler callback closure
@usableFromInline
final class HandlerClosureHolder {
    /// The callback held by this class
    @usableFromInline
    let callback: Handler

    /// Initialiser storing the callback closure
    @usableFromInline
    init(_ closure: @escaping Handler) {
        callback = closure
    }
}
