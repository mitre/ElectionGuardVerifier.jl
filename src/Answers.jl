# ElectionGuard Answers

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
    Answers

This module provides data structures and operations used to report
verification answers.  At the top-level, there is a verification
record.  It identifies the specification version, the election, and
contains a list of verification answers.  A verification answer is the
result of checking all or part of a verification step as defined in an
ElectionGuard specification.

A verification answer contains a verification step number, a string
listing items that failed while verifying the step, the step title, a
comment, the number of records checked, and the number of records that
failed.  A failing step that has no items is marked using item "X".

In the verification routies, each verification item check returns an
integer.  The integer is zero if the check passes, otherwise it is an
integer with one bit set.  The bit is used to identify the item being
checked.  The bit patterns are exported as constants A, B, C, D, E, F,
G, H, I, J, and K.  The bit patterns for multiple checks are combined
using bitwise or.
"""
module Answers

export Answer, answer, verification_record, bits2items, bitor
export A, B, C, D, E, F, G, H, I, J, K

import Base.show

using Dates

using ..Datatypes

"Step answer - do not use as a constructor"
struct Answer
    step::Int64                 # Verification step number
    items::String               # Item letters or the empty string
    section::String             # Verification section title
    comment::String             # Comment or the empty string
    count::Int64                # Number of items checked
    failed::Int64               # Number of items checked that failed
end

"Construct a step answer"
function answer(step::Int64, items::String, section::String,
                comment::String, count::Int64, failed::Int64)::Answer
    if items == "" && failed != 0
        items = "X"
    end
    Answer(step, items, section, comment, count, failed)
end

"A verification record"
struct Verification_record
    spec_version::String        # ElectionGuard spec version
    election_scope_id::String   # Election scope id from manifest
    start_date::String          # Election start date from manifest
    end_date::String            # Election end date from manifest
    verifier::String            # Name of verifier
    run_date::String            # Date of verifier run
    verified::Bool              # Did election record verify?
    answers::Vector{Answer}     # Answers
end

"Show an answer"
function show(io::IO, ans::Answer)
    if ans.step < 10
        print(io, " ")
    end
    print(io, ans.step)
    print(io, ans.items)
    print(io, ". ")
    if ans.comment != ""
        print(io, ans.comment)
    else
        print(io, ans.section)
        if ans.failed == 0
            print(io, " succeeded.")
        else
            print(io, " failed.")
        end
    end
    if ans.count != 1 && ans.failed != 0
        println(io, "")
        print(io, "    ")
        print(io, ans.failed)
        print(io, " records failed out of ")
        print(io, ans.count)
        print(io, " total.")
    end
end

"Construct a verification record"
function verification_record(er::Election_record,
                             anss::Vector{Answer})::Verification_record
    manifest = er.manifest
    verified = all(a -> a.failed == 0, anss)
    Verification_record(manifest["spec_version"],
                        manifest["election_scope_id"],
                        manifest["start_date"],
                        manifest["end_date"],
                        "MITRE ElectionGuard Verifier",
                        string(now(Dates.UTC)),
                        verified,
                        anss)
end

#=
Methods used to support operations on items represented by bit
patterns.
=#

"Convert a bit pattern to items"
function bits2items(bits::Int64)::String
    items = ""
    letter = 'A'
    while bits != 0
        if bits & 1 !=  0
            items *= letter
        end
        bits = bits >>> 1
        letter += 1
    end
    items
end

"Bitwise or the result of applying a function to each value in an iteration"
function bitor(f, itr)::Int64
    acc = 0
    for x in itr
        acc |= f(x)
    end
    acc
end

"Item bit pattern for A"
const A = 1 << 0

"Item bit pattern for B"
const B = 1 << 1

"Item bit pattern for C"
const C = 1 << 2

"Item bit pattern for D"
const D = 1 << 3

"Item bit pattern for E"
const E = 1 << 4

"Item bit pattern for F"
const F = 1 << 5

"Item bit pattern for G"
const G = 1 << 6

"Item bit pattern for H"
const H = 1 << 7

"Item bit pattern for I"
const I = 1 << 8

"Item bit pattern for J"
const J = 1 << 9

"Item bit pattern for K"
const K = 1 << 10

end
