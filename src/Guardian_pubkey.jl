# 2. Guardian Public-key Validation

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Guardian_pubkey

using ..Datatypes
using ..Utils
using ..Hash

export check_guardian_pubkey

"2. Guardian Public-key Validation"
function check_guardian_pubkey(er::Election_record)::Bool
    ans = true
    for g in er.guardians
        if !check_proofs(er.constants, er.context, g)
            name = g.guardian_id
            println(" 2. Guardian $name pubkey is invalid.")
            ans = false
        end
    end
    if ans
        println(" 2. Guardian pubkeys are valid.")
    end
    ans
end

function check_proofs(c::Constants, ctx::Context, g::Guardian)::Bool
    all(p -> check_schnorr(c, ctx, p), g.election_proofs)
end

"Check Guardian Public-Key Validation."
function check_schnorr(c::Constants, ctx::Context, p::Schnorr_proof)::Bool
    check_schnorr_a(c, ctx, p) && check_schnorr_b(c, p)
end

"Check that c_ij = H(Q, K_ij, h_ij) (Eq. A), NOT."
function check_schnorr_a(c::Constants, ctx::Context, p::Schnorr_proof)::Bool
    p.challenge ==
        mod(eg_hash(c.q,
                    #! Spec conflict
                    # Deleted in code but not yet in spec
                    # ctx.crypto_base_hash,
                    p.public_key,
                    p.commitment),
            c.q)
end

"Check that g^u_ij mod p = h_ij K_ij ^ c_ij mod p (Eq. B)."
function check_schnorr_b(c::Constants, p::Schnorr_proof)::Bool
    powermod(c.g, p.response, c.p) ==
        mulpowmod(p.commitment, p.public_key, p.challenge, c.p)
end

end
