# 5. Adherence to vote limits

# Ensure each contest in each ballot meets vote limits.

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Vote_limits

using ..Datatypes
using ..Answers
using ..Utils
using ..Hash

export verify_vote_limits

"5. Adherence to Vote Limits"
function verify_vote_limits(er::Election_record)::Answer
    acc = 0                     # Accumulated bit items
    comment = "Vote limits are adhered to."
    count = 0                   # Records checked
    failed = 0
    contests = er.manifest["contests"]
    for ballot in er.submitted_ballots
        count += 1
        failed_yet = false      # Ensure at most one failure
        for contest in ballot.contests
            bits = are_vote_limits_correct(er, contests, contest)
            if bits != 0
                name = ballot.object_id
                id = contest.object_id
                comment =
                    "Contest $id in ballot $name fails to adhere to vote limits."
                acc |= bits
                if !failed_yet
                    failed += 1
                    failed_yet = true
                end
            end
        end
    end
    answer(5, bits2items(acc), "Adherence to vote limits",
           comment, count, failed)
end

function are_vote_limits_correct(er::Election_record,
                                 contests::Vector{Any},
                                 contest::Contest)::Int64
    votes_allowed = get_votes_allow(contests, contest)
    are_vote_limits_correct_a(votes_allowed, contest) |
        are_vote_limits_correct_b(er, contest) |
        are_vote_limits_correct_c(er, contest) |
        are_vote_limits_correct_d(er, contest) |
        are_vote_limits_correct_e(er, contest) |
        are_vote_limits_correct_f(er, contest) |
        are_vote_limits_correct_g(er, votes_allowed, contest)
end

const DEFAULT_VOTES_ALLOWED = 1000000

function get_votes_allow(contests::Vector{Any}, contest::Contest)::Int64
    for c in contests
        if c["object_id"] == contest.object_id
            va = c["votes_allowed"]
            if va == nothing
                return DEFAULT_VOTES_ALLOWED
            else
                return va
            end
        end
    end
    -1
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
