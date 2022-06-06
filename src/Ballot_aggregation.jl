# 7. Correctness of Ballot Aggregation

#=
Ensure the tally is the sum of the individual votes.

The code uses mapreduce to extract votes from each ballot contest
selection and then combines all of the results to produce an answer.
=#

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Ballot_aggregation

using ..Datatypes
using ..Answers
using ..Utils
using ..Parallel_mapreduce

export verify_ballot_aggregation

"7. Correctness of Ballot Aggregation"
function verify_ballot_aggregation(er::Election_record)::Answer
    acc = 0                     # Accumulated bit items
    count = 0                   # Records checked
    failed = 0
    # for each contest
    for (_, c) in er.tally.contests
        # for each selection in contest
        for (_, sel) in c.selections
            count += 1
            sum = sum_votes(er, c.object_id, sel.object_id)
            mismatch = false
            if sum.pad != sel.message.pad
                mismatch = true
                acc |= A
            end
            if sum.data != sel.message.data
                mismatch = true
                acc |= B
            end
            if mismatch
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
    answer(7, bits2items(acc), "Correctness of ballot aggregation",
           comment, count, failed)
end

# Sum votes for each ballot.
function sum_votes(er::Election_record,
                   contest::String,
                   selection::String,
                   )::Ciphertext
    pmapreduce(ballot -> vote(er, contest, selection, ballot),
               (v1, v2) -> prod_ct(v1, v2, er.constants.p),
              er.submitted_ballots)
end

function vote(er::Election_record,
              contest::String,
              selection::String,
              ballot::Submitted_ballot)::Ciphertext
    if isspoiled(ballot.object_id, contest,
                 selection, er.spoiled_ballots)
        one_ct
    else
        encrypted_vote(contest, selection, ballot)
    end
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

# Return the encrypted vote or one if it is missing.
function encrypted_vote(contest::String,
                        selection::String,
                        ballot::Submitted_ballot
                        )::Ciphertext
    # Find contest
    for c in ballot.contests
        if c.object_id == contest
            # Find selection
            for sel in c.ballot_selections
                if sel.object_id == selection
                    # ensure vote is not a placeholder selection
                    if sel.is_placeholder_selection
                        return one_ct
                    else
                        return sel.ciphertext
                    end
                end
            end
            # No selection found
            return one_ct
        end
    end
    # No contest found
    one_ct
end

end
