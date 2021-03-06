# 5. Adherence to vote limits

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
    Vote_limits

Ensure each contest in each ballot meets vote limits.

The code uses mapreduce to apply a check to each ballot and then
combines all of the results to produce an answer.
"""
module Vote_limits

using ..Datatypes
using ..Answers
using ..Utils
using ..Parallel_mapreduce
using ..Hash

export verify_vote_limits

"5. Adherence to Vote Limits"
function verify_vote_limits(er::Election_record)::Answer
    contests = er.manifest.contests
    accum = pmapreduce(ballot -> verify_a_vote_limit(er, contests, ballot),
                       combine, er.submitted_ballots)
    comment = accum.comment
    if comment == ""
        comment = "Vote limits are adhered to."
    end
    answer(5, bits2items(accum.acc), "Adherence to vote limits",
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

function verify_a_vote_limit(er::Election_record,
                             contests::Dict{String, Manifest_contest},
                             ballot::Submitted_ballot)::Accum
    acc = 0                     # Accumulated bit items
    comment = ""                # Answer check
    failed = false
    for contest in ballot.contests
        bits = are_vote_limits_correct(er, contests, contest)
        if bits != 0
            name = ballot.object_id
            id = contest.object_id
            comment =
                "Contest $id in ballot $name fails to adhere to vote limits."
            acc |= bits
            failed = true
        end
    end
    Accum(comment, acc, 1, failed ? 1 : 0)
end

function are_vote_limits_correct(er::Election_record,
                                 contests::Dict{String, Manifest_contest},
                                 contest::Contest)::Int64
    if haskey(contests, contest.object_id)
        votes_allowed = contests[contest.object_id].votes_allowed
        are_vote_limits_correct_a(votes_allowed, contest) |
            are_vote_limits_correct_b(er, contest) |
            are_vote_limits_correct_c(er, contest) |
            are_vote_limits_correct_d(er, contest) |
            are_vote_limits_correct_e(er, contest) |
            are_vote_limits_correct_f(er, contest) |
            are_vote_limits_correct_g(er, votes_allowed, contest)
    else
        A | G
    end
end

function are_vote_limits_correct_a(votes_allowed::Int64,
                                   contest::Contest)::Int64
    placeholder_positions(contest) == votes_allowed ? 0 : A
end

function placeholder_positions(contest::Contest)::Int64
    ans = 0
    for sel in contest.ballot_selections
        if sel.is_placeholder_selection
            ans += 1
        end
    end
    ans
end

function are_vote_limits_correct_b(er::Election_record,
                                   contest::Contest)::Int64
    c = er.constants
    votes = one_ct
    for sel in contest.ballot_selections
        votes = prod_ct(votes, sel.ciphertext, c.p)
    end
    same(votes, contest.ciphertext_accumulation) ? 0 : B
end

function are_vote_limits_correct_c(er::Election_record,
                                   contest::Contest)::Int64
    within(contest.proof.response, er.constants.q) ? 0 : C
end

function are_vote_limits_correct_d(er::Election_record,
                                   contest::Contest)::Int64
    c = er.constants
    p = contest.proof
    within_mod(p.pad, c.q, c.p) && within_mod(p.data, c.q, c.p) ? 0 : D
end

function are_vote_limits_correct_e(er::Election_record,
                                   contest::Contest)::Int64
    c = er.constants
    p = contest.proof
    p.challenge ==
        eg_hash(c.q,
                er.context.crypto_extended_base_hash,
                contest.ciphertext_accumulation.pad,
                contest.ciphertext_accumulation.data,
                p.pad,
                p.data) ? 0 : E
end

function are_vote_limits_correct_f(er::Election_record,
                                   contest::Contest)::Int64
    c = er.constants
    p = contest.proof
    powermod(c.g, p.response, c.p) ==
        mulpowmod(p.pad,
                  contest.ciphertext_accumulation.pad,
                  p.challenge,
                  c.p) ? 0 : F
end

function are_vote_limits_correct_g(er::Election_record,
                                   votes_allowed::Int64,
                                   contest::Contest)::Int64
    c = er.constants
    p = contest.proof
    mulpowmod(powermod(c.g, votes_allowed * p.challenge, c.p),
              er.context.elgamal_public_key,
              p.response,
              c.p) ==
                  mulpowmod(p.data,
                            contest.ciphertext_accumulation.data,
                            p.challenge,
                            c.p) ? 0 : G
end

end
