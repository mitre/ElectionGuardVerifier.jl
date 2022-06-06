# ElectionGuard Verifier Main Module

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

#=
This module incorporates all of the modules that make up this
ElectionGuard verifier.  Its exported functions are expected to be
made available by using the module in a Julia intepreter.
=#

module ElectionGuardVerifier

export load, check, verify

import JSON

include("Datatypes.jl")

using .Datatypes: Election_record

include("Record_version.jl")
include("Loader.jl")

using .Loader: load

include("Utils.jl")

include("Parallel_mapreduce.jl")

include("ElGamal.jl")           # Not currently used

include("Hash.jl")

include("Answers.jl")

using .Answers: Answer, Verification_record, verification_record

# Parameter validation
include("Standard_constants.jl")
include("Params.jl")

# Guardian Public-key Validation
include("Guardian_pubkey.jl")

# Election Public-Key Validation
include("Election_pubkey.jl")

# Correctness of Selection Encryptions
include("Selection_encryptions.jl")

# Adherence to vote limits
include("Vote_limits.jl")

# Check for Duplicate Ballots
include("Duplicate_ballots.jl")

# Correctness of Ballot Aggregation
include("Ballot_aggregation.jl")

# Correctness of Partial Decryptions
include("Partial_decryptions.jl")

# Correctness of Substitute Decryptions
include("Substitute_decryptions.jl")

# Correctness of Coefficients
include("Coefficients.jl")

# Missing Tally Share
include("Missing_tally_share.jl")

# Validation of Correct Decryption of Tallies
include("Tally_decryptions.jl")

# Validation of Contest Selections with the Manifest
include("Contest_selections.jl")

# Validation of Correct Decryption of Spoiled Ballots
include("Spoiled_ballots.jl")

function print_push!(as::Vector{Answer}, a::Answer)
    println(a)
    push!(as, a)
end

"""
    verify(er::Election_record)::Verification_record

Verify election records.  Return a verification record.
"""
function verify(er::Election_record)::Verification_record
    println(er.manifest["election_scope_id"])
    as = Vector{Answer}()
    print_push!(as, Params.verify_params(er))
    print_push!(as, Guardian_pubkey.verify_guardian_pubkey(er))
    print_push!(as, Election_pubkey.verify_election_pubkey(er))
    print_push!(as, Selection_encryptions.verify_selection_encryptions(er))
    print_push!(as, Vote_limits.verify_vote_limits(er))
    print_push!(as, Duplicate_ballots.check_duplicate_ballots(er))
    println(" 6. Ballot chaining validity was not checked.")
    print_push!(as, Ballot_aggregation.verify_ballot_aggregation(er))
    print_push!(as, Partial_decryptions.
        verify_partial_decryptions(er, er.tally, true))
    print_push!(as, Substitute_decryptions.
        verify_substitute_decryptions(er, er.tally, true))
    print_push!(as, Coefficients.verify_coefficients(er))
    print_push!(as, Missing_tally_share.
        verify_missing_tally_share(er, er.tally, true))
    print_push!(as, Tally_decryptions.
        verify_tally_decryptions(er, er.tally, true))
    print_push!(as, Contest_selections.
        verify_contest_selections(er, er.tally, true))
    println("12. Correctness of partial decryptions of extended data not checked.")
    append!(as, Spoiled_ballots.verify_spoiled_ballots(er))
    verification_record(er, as)
end

"""
    check(er::Election_record, path::String="")::Bool

Check election record.  Write answers to path in JSON if path is not empty.
"""
function check(er::Election_record, path::String="")::Bool
    vr = verify(er)
    if path != ""
        handle = open(path, "w")
        try
            JSON.print(handle, vr, 2)
        finally
            close(handle)
        end
    end
    vr.verified
end

end # ElectionGuard module
