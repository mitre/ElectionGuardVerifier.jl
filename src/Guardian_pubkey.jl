# 2. Guardian Public-key Validation

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
    Guardian_pubkey

Verify the correct computation of the joint election public key and
extended base hash.
"""
module Guardian_pubkey

using ..Datatypes
using ..Answers
using ..Utils
using ..Hash

export verify_guardian_pubkey

"2. Guardian Public-key Validation"
function verify_guardian_pubkey(er::Election_record)::Answer
    acc = 0                     # Accumulated bit items
    comment = "Guardian pubkeys are valid."
    count = 0                   # Records checked
    failed = 0
    for g in er.guardians
        count += 1
        bits =  verify_proofs(er.constants, er.context, g)
        if bits != 0
            name = g.guardian_id
            comment = "Guardian $name pubkey is invalid."
            failed += 1
            acc |= bits
        end
    end
    answer(2, bits2items(acc), "Guardian public-key validation",
           comment, count, failed)
end

function verify_proofs(c::Constants, ctx::Context, g::Guardian)::Int64
    bitor(p -> verify_schnorr(c, ctx, p), g.election_proofs)
end

"Verify Guardian Public-Key Validation."
function verify_schnorr(c::Constants, ctx::Context, p::Schnorr_proof)::Int64
    verify_schnorr_a(c, ctx, p) | verify_schnorr_b(c, p)
end

"Verify that c_ij = H(K_ij, h_ij) mod q (Item A)."
function verify_schnorr_a(c::Constants, ctx::Context, p::Schnorr_proof)::Int64
    p.challenge ==
        mod(eg_hash(c.q,
                    p.public_key,
                    p.commitment),
            c.q) ? 0 : A
end

"Verify that g^u_ij mod p = h_ij K_ij ^ c_ij mod p (Item B)."
function verify_schnorr_b(c::Constants, p::Schnorr_proof)::Int64
    powermod(c.g, p.response, c.p) ==
        mulpowmod(p.commitment, p.public_key, p.challenge, c.p) ? 0 : B
end

end
