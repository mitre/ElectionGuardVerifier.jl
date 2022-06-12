# 5. Check for Duplicate Ballots

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
    Duplicate_ballots

Ensure there are no duplicate ballots.  Two ballots are duplicates
if their crypto_hash's are the same.
"""
module Duplicate_ballots

using ..Datatypes
using ..Answers

export check_duplicate_ballots

"5. Check for Duplicate Ballots"
function check_duplicate_ballots(er::Election_record)::Answer
    comment = "No duplicate ballots found."
    count = 0                   # Records checked
    failed = 0
    seen = Dict{BigInt, String}()
    for ballot in er.submitted_ballots
        count += 1
        if haskey(seen, ballot.crypto_hash)
            # Found duplicate ballot
            failed += 1
            old = seen[ballot.crypto_hash]
            new = ballot.object_id
            comment = "Duplicate ballots detected $old and $new."
        else
            seen[ballot.crypto_hash] = ballot.object_id
        end
    end
    answer(5, failed == 0 ? "" : "H",
           "Check for duplicate ballots",
           comment, count, failed)
end

end
