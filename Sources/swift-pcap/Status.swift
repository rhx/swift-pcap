//
//  Status.swift
//  
//  Copyright (c) 2022 Rene Hexel, all rights reserved.
//  Created by Rene Hexel on 22/5/2022.
//
public extension PCAPDevice {
    /// Return status of `dispatch` or `loop`
    enum Status {
        /// Processing completed successfully
        case completed
        /// Processing was interrupted
        case interrupted
        /// Dispatch was interrupted, with the given number of packets processed
        case partial(completed: Int)
        /// An error ocurred
        case error(PCAPError)
    }
}
