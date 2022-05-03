# 3. Election Public-Key Validation

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Election_pubkey

using ..Datatypes
using ..Hash

export check_election_pubkey

" 3. Election Public-Key Validation"
function check_election_pubkey(er::Election_record)::Bool
    ans = true

    # A. K = prod(K_i) mod p
    keys = map(g -> g.election_public_key, er.guardians)
    if mod(prod(keys), er.constants.p) != er.context.elgamal_public_key
        println(" 3A. Election joint election pubkey is not valid.")
        ans = false
    end

    # B. Qbar = H(Q, K)
    #! Spec conflict
    # B. Qbar = H(Q, ???)
    qbar = eg_hash(er.constants.q,
                   er.context.crypto_base_hash,
                   # er.context.elgamal_public_key)
                   er.context.commitment_hash)
    if qbar != er.context.crypto_extended_base_hash
        println(" 3B. Election extended base hash is not valid.")
        ans = false
    end

    if ans
        println(" 3. Election pubkey is valid.")
    end
    ans
end

end
