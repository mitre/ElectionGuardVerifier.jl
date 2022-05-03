# 12. Validation of Correct Decryption of Spoiled Ballots

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Spoiled_ballots

using ..Datatypes
using ..Partial_decryptions
using ..Substitute_decryptions
using ..Missing_tally_share
using ..Tally_decryptions
using ..Contest_selections

export check_spoiled_ballots

function chk(ans::Bool, probe::Bool)::Bool
    probe && ans
end

"12. Validation of Correct Decryption of Spoiled Ballots"
function check_spoiled_ballots(er::Election_record)
    ans = true
    println("12. Checking spoiled ballots...")
    for ballot in er.spoiled_ballots
        println()
        id = ballot.object_id
        println("Checking ballot $id")
        ans = chk(ans, Partial_decryptions.
            check_partial_decryptions(er, ballot, false))
        ans = chk(ans, Substitute_decryptions.
            check_substitute_decryptions(er, ballot, false))
        ans = chk(ans, Missing_tally_share.
            check_missing_tally_share(er, ballot, false))
        ans = chk(ans, Tally_decryptions.
            check_tally_decryptions(er, ballot, false))
        ans = chk(ans, Contest_selections.
            check_contest_selections(er, ballot, false))
    end
    ans
end

end
