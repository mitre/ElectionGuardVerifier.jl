# 3. Election Public-Key Validation

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Election_pubkey

using ..Datatypes
using ..Answers
using ..Hash

export verify_election_pubkey

" 3. Election Public-Key Validation"
function verify_election_pubkey(er::Election_record)::Answer
    bits = 0

    # A. K = prod(K_i) mod p
    keys = map(g -> g.election_public_key, er.guardians)
    if mod(prod(keys), er.constants.p) != er.context.elgamal_public_key
        bits |= A
    end

    # B. Qbar = H(Q, K)
    qbar = eg_hash(er.constants.q,
                   er.context.crypto_base_hash,
                   er.context.commitment_hash)
    if qbar != er.context.crypto_extended_base_hash
        bits |= B
    end

    if bits == 0
        answer(3, "", "Election public-key validation",
               "Election pubkey is valid.", 1, 0)
    else
        answer(3, bits2items(bits), "Election public-key validation",
               "Election pubkey is invalid.", 1, 1)
    end
end

end
