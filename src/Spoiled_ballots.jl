# 13. Validation of Correct Decryption of Spoiled Ballots

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Spoiled_ballots

using ..Datatypes
using ..Answers
using ..Partial_decryptions
using ..Substitute_decryptions
using ..Missing_tally_share
using ..Tally_decryptions
using ..Contest_selections

export verify_spoiled_ballots

function print_push!(as::Vector{Answer}, a::Answer)
    println(a)
    push!(as, a)
end

"13. Validation of Correct Decryption of Spoiled Ballots"
function verify_spoiled_ballots(er::Election_record)::Vector{Answer}
    as = Vector{Answer}()
    for ballot in er.spoiled_ballots
        print_push!(as, Partial_decryptions.
            verify_partial_decryptions(er, ballot, false))
        print_push!(as, Substitute_decryptions.
            verify_substitute_decryptions(er, ballot, false))
        print_push!(as, Missing_tally_share.
            verify_missing_tally_share(er, ballot, false))
        print_push!(as, Tally_decryptions.
            verify_tally_decryptions(er, ballot, false))
        # Is the correct?  Couldn't a ballot be spoiled because this
        # does not verify?
        print_push!(as, Contest_selections.
            verify_contest_selections(er, ballot, false))
    end
    as
end

end
