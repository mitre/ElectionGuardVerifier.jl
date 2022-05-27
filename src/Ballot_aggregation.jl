# 7. Correctness of Ballot Aggregation

# Ensure the tally is the sum of the individual votes.

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Ballot_aggregation

using ..Datatypes
using ..Answers
using ..Utils

export verify_ballot_aggregation

"7. Correctness of Ballot Aggregation"
function verify_ballot_aggregation(er::Election_record)::Answer
    count = 0                   # Records checked
    failed = 0
    # for each contest
    for (_, c) in er.tally.contests
        # for each selection in contest
        for (_, sel) in c.selections
            count += 1
            sum = sum_votes(er, c.object_id, sel.object_id)
            if !same(sum, sel.message)
                failed += 1
            end
        end
    end
    if failed == 0
        comment = "Tally aggregation is correct."
    else
        name = er.tally.object_id
        comment = "Tally $name ballot aggregation is incorrect."
    end
    answer(7, "", "Correctness of ballot aggregation",
           comment, count, failed)
end

# Sum votes for each ballot.
function sum_votes(er::Election_record,
                   contest::String,
                   selection::String,
                   )::Union{Ciphertext, Nothing}
    votes = one_ct
    for ballot in er.submitted_ballots
        # Omit ballot if it is spoiled.
        if !isspoiled(ballot.object_id, contest,
                      selection, er.spoiled_ballots)
            vote = encrypted_vote(contest, selection, ballot)
            votes = incr_votes(votes, vote, er.constants.p )
        end
    end
    votes
end

# Is ballot with given object_id spoiled?
function isspoiled(object_id::String,
                   contest::String,
                   selection::String,
                   ballots::Vector{Tally})::Bool
    for ballot in ballots
        if object_id == ballot.object_id
            if haskey(ballot.contests, contest)
                c = ballot.contests[contest]
                if haskey(c.selections, selection)
                    return true
                end
            end
        end
    end
    false
end

# Add in one vote.  When the vote is nothing, ignore vote
function incr_votes(votes::Ciphertext,
                    vote::Union{Ciphertext, Nothing},
                    p::BigInt)::Ciphertext
    if vote == nothing
        votes
    else
        prod_ct(votes, vote, p)
    end
end

# Return the encrypted vote or nothing if it is missing.
function encrypted_vote(contest::String,
                        selection::String,
                        ballot::Submitted_ballot
                        )::Union{Ciphertext, Nothing}
    # Find contest
    for c in ballot.contests
        if c.object_id == contest
            # Find selection
            for sel in c.ballot_selections
                if sel.object_id == selection
                    # ensure vote is not a placeholder selection
                    if sel.is_placeholder_selection
                        return nothing
                    else
                        return sel.ciphertext
                    end
                end
            end
            # No selection found
            return nothing
        end
    end
    # No contest found
    nothing
end

end
