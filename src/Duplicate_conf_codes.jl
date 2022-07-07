# 6B. Check for Duplicate Confirmation Codes

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
    Duplicate_conf_code

Ensure there are no duplicate confirmation codes in submitted ballots.
"""
module Duplicate_conf_codes

using ..Datatypes
using ..Answers

export verify_duplicate_conf_codes

"6B. Verify for Duplicate Confirmation Codes"
function verify_duplicate_conf_codes(er::Election_record)::Answer
    comment = "No duplicate confirmation codes found."
    count = 0                   # Records checked
    failed = 0
    seen = Dict{BigInt, String}()
    size = length(er.submitted_ballots)
    sizehint!(seen, size)       # Preallocate dictionary size

    # Check submitted ballots
    for ballot in er.submitted_ballots
        count += 1
        if haskey(seen, ballot.code)
            # Found duplicate confirmation code
            failed += 1
            old = seen[ballot.code]
            new = ballot.object_id
            comment = "Duplicate confirmation codes detected $old and $new."
        else
            seen[ballot.code] = ballot.object_id
        end
    end
    answer(6, failed == 0 ? "" : "B",
           "Validation of confirmation codes",
           comment, count, failed)
end

end
