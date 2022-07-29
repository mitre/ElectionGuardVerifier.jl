# 16. Well-formed spoiled ballots

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
    Well_formed_spoiled_ballots

Ensure each contest in each ballot meets vote limits.

The code uses mapreduce to apply a check to each ballot and then
combines all of the results to produce an answer.
"""
module Well_formed_spoiled_ballots

using ..Datatypes
using ..Answers

export verify_well_formed_spoiled_ballots

"16. Validation of correctness of spoiled ballots"
function verify_well_formed_spoiled_ballots(er::Election_record)::Answer
    contests = er.manifest.contests
    acc = 0                     # Accumulated bit items
    comment = "Spoiled ballots are well-formed."
    count = 0                   # Records checked
    failed = 0

    for ballot in er.spoiled_ballots
        count += 1
        bits = check_selection(ballot)
        bits |= check_sum(contests, ballot)
        if bits != 0
            failed += 1
            acc |= bits
            id = ballot.object_id
            comment = "Spoiled ballot $id is not well-formed."
        end
    end
    answer(16, bits2items(acc), "Validation of correctness of spoiled ballots",
           comment, count, failed)
end

function check_selection(ballot::Tally)::Int64
    for (_, contest) in ballot.contests
        for (_, sel) in contest.selections
            tally = sel.tally
            if tally != 0 && tally != 1
                return A
            end
        end
    end
    0
end

function check_sum(contests::Dict{String, Manifest_contest},
                   ballot::Tally)::Int64
    for (_, contest) in ballot.contests
        votes = 0
        for (_, sel) in contest.selections
            votes += sel.tally
        end
        votes_allowed = contests[contest.object_id].votes_allowed
        if votes > votes_allowed
            return B
        end
    end
    0
end

end
