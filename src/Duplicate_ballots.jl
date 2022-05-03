# 5. Check for Duplicate Ballots

# Ensure there are no duplicate ballots.  Two ballots are duplicates
# if their crypto_hash's are the same.

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Duplicate_ballots

using ..Datatypes

export check_duplicate_ballots

"5. Check for Duplicate Ballots"
function check_duplicate_ballots(er::Election_record)::Bool
    ans = true
    seen = Dict{BigInt, String}()
    for ballot in er.submitted_ballots
        if haskey(seen, ballot.crypto_hash)
            # Found duplicate ballot
            old = seen[ballot.crypto_hash]
            new = ballot.object_id
            println(" 5. Duplicate ballots detected")
            println("    $old")
            println("    $new")
            ans = false
        else
            seen[ballot.crypto_hash] = ballot.object_id
        end
    end
    ans
end

end
