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

export load, check

include("Datatypes.jl")

using .Datatypes: Election_record

include("Record_version.jl")
include("Loader.jl")

using .Loader: load

include("Utils.jl")

include("ElGamal.jl")           # Not currently used

include("Hash.jl")

# 1. Parameter validation
include("Standard_constants.jl")
include("Params.jl")

# 2. Guardian Public-key Validation
include("Guardian_pubkey.jl")

# 3. Election Public-Key Validation
include("Election_pubkey.jl")

# 4. Selection Encryptions  Validation
include("Selection_encryptions.jl")

# 5. Adherence to vote limits
include("Vote_limits.jl")

# 5. Check for Duplicate Ballots
include("Duplicate_ballots.jl")

# 7. Correctness of Ballot Aggregation
include("Ballot_aggregation.jl")

# 8. Correctness of Partial Decryptions
include("Partial_decryptions.jl")

# 9. Correctness of Substitute Decryptions
include("Substitute_decryptions.jl")

# 10. Correctness of Coefficients
include("Coefficients.jl")

# 10. Missing Tally Share
include("Missing_tally_share.jl")

# 11. Validation of Correct Decryption of Tallies
include("Tally_decryptions.jl")

# 11. Validation of Contest Selections with the Manifest
include("Contest_selections.jl")

# 12. Validation of Correct Decryption of Spoiled Ballots
include("Spoiled_ballots.jl")

function chk(ans::Bool, probe::Bool)::Bool
    probe && ans
end

"""
    check(er::Election_record)::Bool

Check election records.  Return true if all checks pass.
"""
function check(er::Election_record)::Bool
    println(er.manifest["election_scope_id"])
    ans = true
    ans = chk(ans, Params.check_params(er))
    ans = chk(ans, Guardian_pubkey.check_guardian_pubkey(er))
    ans = chk(ans, Election_pubkey.check_election_pubkey(er))
    ans = chk(ans, Selection_encryptions.check_selection_encryptions(er))
    ans = chk(ans, Vote_limits.check_vote_limits(er))
    ans = chk(ans, Duplicate_ballots.check_duplicate_ballots(er))
    println(" 6. Ballot chaining validity was not checked.")
    ans = chk(ans, Ballot_aggregation.check_ballot_aggregation(er))
    ans = chk(ans, Partial_decryptions.
        check_partial_decryptions(er, er.tally, true))
    ans = chk(ans, Substitute_decryptions.
        check_substitute_decryptions(er, er.tally, true))
    ans = chk(ans, Coefficients.check_coefficients(er))
    ans = chk(ans, Missing_tally_share.
        check_missing_tally_share(er, er.tally, true))
    ans = chk(ans, Tally_decryptions.
        check_tally_decryptions(er, er.tally, true))
    ans = chk(ans, Contest_selections.
        check_contest_selections(er, er.tally, true))
    # Ignore errors in spoiled ballots for now.
    _ = chk(ans, Spoiled_ballots.check_spoiled_ballots(er))
    ans
end

end # ElectionGuard module
