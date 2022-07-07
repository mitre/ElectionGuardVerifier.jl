# 6A. Check Confirmation Codes

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
    Confirmation_codes

Ensure each confirmation code is computed correctly

The code uses mapreduce to apply a check to each ballot and then
combines all of the results to produce an answer.
"""
module Confirmation_codes

using ..Datatypes
using ..Answers
using ..Utils
using ..Parallel_mapreduce
using ..Hash

export verify_confirmation_codes

"6A. Verify confirmation codes"
function verify_confirmation_codes(er::Election_record)::Answer
    q = er.constants.q
    accum = pmapreduce(ballot -> verify_a_confirmation_code(q, ballot),
                       combine, er.submitted_ballots)
    comment = accum.comment
    if comment == ""
        comment = "Confirmtion codes are correct."
    end
    answer(6, bits2items(accum.acc), "Validation of confirmation codes",
           comment, accum.count, accum.failed)
end

"Accumulated value for mapreduce"
struct Accum
    comment::String             # Answer comment
    acc::Int64                  # Accumulated bit items
    count::Int64                # Records checked
    failed::Int64               # Failed checks
end

"Combine accumulated values."
function combine(accum1::Accum, accum2::Accum)::Accum
    # Ensure comment is nonempty if one input comment is nonempty.
    if accum1.comment == ""
        comment = accum2.comment
    else
        comment = accum1.comment
    end
    Accum(comment,
          accum1.acc | accum2.acc,
          accum1.count + accum2.count,
          accum1.failed + accum2.failed)
end

function verify_a_confirmation_code(q::BigInt, ballot::Submitted_ballot)::Accum
    enc_votes = Vector{Ciphertext}()
    for contest in ballot.contests
        for sel in contest.ballot_selections
            push!(enc_votes, sel.ciphertext)
        end
    end

    if ballot.code == eg_hash(q, enc_votes...)
        acc = 0
        comment = ""
        failed = 0
    else
        acc = A
        id = ballot.object_id
        comment = "Invalid confirmation code for $id."
        failed = 1
    end
    Accum(comment, acc, 1, failed)
end

end
