# Data types used in ElectionGuard records.

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
    Datatypes

This module contains the structures that appear in the JSON data files
that make up an ElectionGuard election record.  The field names in
structs are the field names that appear in the JSON file with the
exception of constants.  The use of constants is too ubiquitous to use
the verbose field names.

To see the structure of the data, it is best that you read the structs
in this file in reverse order.
"""
module Datatypes

export Election_record,

    Manifest, Manifest_contest, Manifest_selection,

    Constants, Context, Configuration, Coefficients,

    Guardian, Schnorr_proof,

    Encryption_device,

    Ciphertext, Data_ciphertext,

    Submitted_ballot, Contest, Ballot_selection,
    Disjunctive_proof, Constant_proof,

    Encrypted_tally, Encrypted_tally_contest, Encrypted_tally_selection,

    Tally, Tally_contest, Tally_selection,
    Tally_selection_share, Recovered_part, Chaum_Pedersen_proof

# The content of manifest.json is only partially extracted.

struct Manifest_selection
    object_id::String
    candidate_id::String
end

struct Manifest_contest
    object_id::String
    votes_allowed::Int64
    ballot_selections::Dict{String, Manifest_selection}
end

struct Manifest
    election_scope_id::String
    spec_version::String
    start_date::String          # ISO data time
    end_date::String            # ISO data time
    contests::Dict{String, Manifest_contest}
end

# The content of constants.json

#= The ElGamal constants

p and q are primes such that q is not a divisor of r = (p - 1) / q.
g is a generator of order q.

=#

"""
The ElGamal constants:
 - p (large prime),
 - q (small prime),
 - r (cofactor), and
 - g (generator)
"""
struct Constants
    p::BigInt                   # Key name is "large_prime".
    q::BigInt                   # Key name is "small_prime".
    r::BigInt                   # Key name is "cofactor"
    g::BigInt                   # Key name is "generator"
end

# Content of context.json

struct Configuration
    allow_overvotes::Bool
    max_votes::Int64
end

"The context of an election"
struct Context
    manifest_hash::BigInt
    commitment_hash::BigInt
    crypto_base_hash::BigInt          # Q
    crypto_extended_base_hash::BigInt # Q bar
    elgamal_public_key::BigInt        # K
    number_of_guardians::Int64        # n
    quorum::Int64                     # k
    extended_data
    configuration::Configuration
end

# Content of coefficients.json

struct Coefficients
    coefficients::Dict{String, BigInt}
end

# For guardian.json

struct Schnorr_proof
    usage::String
    public_key::BigInt          # K_ij
    commitment::BigInt          # h_ij
    challenge::BigInt           # c_ij
    response::BigInt            # u_ij
end

# Content of guardian.json

struct Guardian
    guardian_id::String
    sequence_order::Int64       # ℓ - guardian index
    election_public_key::BigInt # K_i
    election_commitments::Vector{BigInt}
    election_proofs::Vector{Schnorr_proof}
end

# Content of encrypted_device.json

struct Encryption_device
    location::String
    device_id::Int64
    session_id::Int64
    launch_code::Int64
end

# Encryption

struct Ciphertext
    pad::BigInt
    data::BigInt
end

# Encryption with MAC

struct Data_ciphertext
    pad::BigInt
    data::BigInt
    mac::BigInt
end

# For submitted_ballot.json

struct Disjunctive_proof
    usage::String
    challenge::BigInt           # c - challenge
    proof_zero_pad::BigInt      # a_0 - commitment to vote being zero
    proof_zero_data::BigInt     # b_0 - commitment to vote being zero
    proof_zero_challenge::BigInt # c_0 - derived challenge to zero
    proof_zero_response::BigInt  # v_0 - response to zero challenge
    proof_one_pad::BigInt       # a_1 - commitment to vote being one
    proof_one_data::BigInt      # b_1 - commitment to vote being one
    proof_one_challenge::BigInt # c_1 - derived challenge to zero
    proof_one_response::BigInt  # v_1 - response to one challenge
end

struct Ballot_selection
    object_id::String
    sequence_order::Int64
    description_hash::BigInt
    crypto_hash::BigInt
    nonce
    is_placeholder_selection::Bool
    proof::Disjunctive_proof
    ciphertext::Ciphertext      # (α, β) - encryption of vote
    extended_data
end

struct Constant_proof
    constant::Int64             # L
    usage::String
    pad::BigInt                 # a
    data::BigInt                # b
    challenge::BigInt           # C
    response::BigInt            # V
end

struct Contest
    object_id::String
    sequence_order::Int64
    nonce
    description_hash::BigInt
    crypto_hash::BigInt
    ballot_selections::Vector{Ballot_selection}
    proof::Constant_proof
    ciphertext_accumulation::Ciphertext # (A, B)
end

# Content of submitted_ballot.json

struct Submitted_ballot
    object_id::String
    state::Int64
    style_id::String
    manifest_hash::BigInt
    crypto_hash::BigInt
    code_seed::BigInt
    code::BigInt                # H_i
    timestamp::Int64
    nonce
    contests::Vector{Contest}
end

# For encrypted_tally.json

struct Encrypted_tally_selection
    object_id::String
    sequence_order::Int64
    description_hash::BigInt
    ciphertext::Ciphertext
end

struct Encrypted_tally_contest
    object_id::String
    sequence_order::Int64
    description_hash::BigInt
    selections::Dict{String, Encrypted_tally_selection}
end

# Content of encrypted_tally.json

struct Encrypted_tally
    object_id::String
    contests::Dict{String, Encrypted_tally_contest}
end

# For tally.json and spoiled_ballot.json

struct Chaum_Pedersen_proof
    usage::String
    # (a_i, b_i) commitment by guardian T_i to partial decryption of (A, B)
    pad::BigInt                 # a_i
    data::BigInt                # b_i
    challenge::BigInt           # c_i - challenge to partial decryption
    response::BigInt            # v_i - response to challenge
end

struct Recovered_part
    object_id::String
    guardian_id::String         # T_l -- surrogate guardian
    missing_guardian_id::String # T_i
    share::BigInt               # M_il - share
    recovery_key::BigInt
    proof::Chaum_Pedersen_proof
end

struct Tally_selection_share
    object_id::String
    guardian_id::String
    # M_i - partial decryption of (A, B) by guardian T_i
    share::BigInt
    # I assume exactly one of the following is nothing.
    proof::Union{Chaum_Pedersen_proof, Nothing}
    recovered_parts::Union{Dict{String, Recovered_part}, Nothing}
end

struct Tally_selection
    object_id::String
    tally::Int64                # t - tally value
    value::BigInt               # M - full decryption of (A, B)
    message::Ciphertext         # (A, B)
    shares::Vector{Tally_selection_share}
end

struct Tally_contest
    object_id::String
    selections::Dict{String, Tally_selection}
end

# Content of tally.json and spoiled_ballot.json

struct Tally
    object_id::String
    contests::Dict{String, Tally_contest}
end

# See the loader for the directory structure assumed to create an
# election record.

"Records that make up an election"
struct Election_record
    manifest::Manifest
    constants::Constants
    context::Context
    coefficients::Coefficients
    guardians::Vector{Guardian}
    encryption_devices::Vector{Encryption_device}
    submitted_ballots::Vector{Submitted_ballot}
    spoiled_ballots::Vector{Tally}
    encrypted_tally::Encrypted_tally
    tally::Tally
end

end
