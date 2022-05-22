//
//  BPFProgram.swift
//  
//  Copyright (c) 2022 Rene Hexel, all rights reserved.
//  Created by Rene Hexel on 22/5/2022.
//
import CLibPCap

/// A class representing a BPF packet filter program
public final class BPFProgram {
    /// The underlying BPF program
    public var bpfProgram: bpf_program

    /// Initialise with a compiled program
    /// - Note: the program passed in must already have been compiled
    @inlinable
    public init(_ program: bpf_program) {
        bpfProgram = program
    }

    deinit {
        pcap_freecode(&bpfProgram)
    }
}
