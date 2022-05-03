# 5. Adherence to vote limits

# Ensure each contest in each ballot meets vote limits.

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Vote_limits

using ..Datatypes
using ..Utils
using ..Hash

export check_vote_limits

"5. Adherence to vote limits"
function check_vote_limits(er::Election_record)::Bool
    ans = true
    contests = er.manifest["contests"]
    for ballot in er.submitted_ballots
        for contest in ballot.contests
            if !are_vote_limits_correct(er, contests, contest)
                if ans
                    name = ballot.object_id
                    println(" 5. Ballot $name fails to adhere to vote limits.")
                    id = contest.object_id
                    println("    The failing contest is $id.")
                end
                ans = false
            end
        end
    end
    if ans
        println(" 5. Vote limits are adhered to.")
    end
    ans
end

function are_vote_limits_correct(er::Election_record,
                                 contests::Vector{Any},
                                 contest::Contest)::Bool
    votes_allowed = get_votes_allow(contests, contest)
    are_vote_limits_correct_a(votes_allowed, contest) &&
        are_vote_limits_correct_b(er, contest) &&
        are_vote_limits_correct_c(er, contest) &&
        are_vote_limits_correct_d(er, contest) &&
        are_vote_limits_correct_e(er, contest) &&
        are_vote_limits_correct_f(er, contest) &&
        are_vote_limits_correct_g(er, votes_allowed, contest)
end

function get_votes_allow(contests::Vector{Any}, contest::Contest)::Int64
    for c in contests
        if c["object_id"] == contest.object_id
            return c["votes_allowed"]
        end
    end
    -1
end

function are_vote_limits_correct_a(votes_allowed::Int64,
                                   contest::Contest)::Bool
    placeholder_positions(contest) == votes_allowed
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
                                   contest::Contest)::Bool
    c = er.constants
    votes = one_ct
    for sel in contest.ballot_selections
        votes = prod_ct(votes, sel.ciphertext, c.p)
    end
    same(votes, contest.ciphertext_accumulation)
end

function are_vote_limits_correct_c(er::Election_record,
                                   contest::Contest)::Bool
    within(contest.proof.response, er.constants.q)
end

function are_vote_limits_correct_d(er::Election_record,
                                   contest::Contest)::Bool
    c = er.constants
    p = contest.proof
    within_mod(p.pad, c.q, c.p) && within_mod(p.data, c.q, c.p)
end

function are_vote_limits_correct_e(er::Election_record,
                                   contest::Contest)::Bool
    c = er.constants
    p = contest.proof
    p.challenge ==
        #! Spec conflict
        # Incorrect hash was specified.
        # This is the correct one.
        eg_hash(c.q,
                er.context.crypto_extended_base_hash,
                contest.ciphertext_accumulation.pad,
                contest.ciphertext_accumulation.data,
                p.pad,
                p.data)
end

function are_vote_limits_correct_f(er::Election_record,
                                   contest::Contest)::Bool
    c = er.constants
    p = contest.proof
    powermod(c.g, p.response, c.p) ==
        mulpowmod(p.pad,
                  contest.ciphertext_accumulation.pad,
                  p.challenge,
                  c.p)
end

function are_vote_limits_correct_g(er::Election_record,
                                   votes_allowed::Int64,
                                   contest::Contest)::Bool
    c = er.constants
    p = contest.proof
    mulpowmod(powermod(c.g, votes_allowed * p.challenge, c.p),
              er.context.elgamal_public_key,
              p.response,
              c.p) ==
                  mulpowmod(p.data,
                            contest.ciphertext_accumulation.data,
                            p.challenge,
                            c.p)
end

end
