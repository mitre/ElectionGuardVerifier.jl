# 9. Correctness of Substitute Decryptions

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Substitute_decryptions

using ..Datatypes
using ..Answers
using ..Utils
using ..Hash

export verify_substitute_decryptions

"9. Correctness of Substitute Decryptions"
function verify_substitute_decryptions(er::Election_record,
                                       tally::Tally,
                                       is_tally)::Answer
    acc = 0                     # Accumulated bit items
    count = 0                   # Records checked
    failed = 0
    # for each contest
    for (_, c) in tally.contests
        # for each selection in contest
        for (_, sel) in c.selections
            msg = sel.message
            for share in sel.shares
                if share.proof == nothing
                    count += 1
                    bits = are_substitute_decryptions_correct(er, msg, share)
                    if bits != 0
                        failed += 1
                        acc |= bits
                    end
                end
            end
        end
    end
    if is_tally
        name = "Tally"
        step = 9
    else
        name = "Spoiled ballot " * tally.object_id
        step = 13
    end
    if failed == 0
        comment = "$name substitute decryptions are correct."
    else
        comment = "$name substitute decryptions are incorrect."
    end
    answer(step, bits2items(acc),
           "Correctness of substitute data for missing guardian",
           comment, count, failed)
end

function are_substitute_decryptions_correct(er::Election_record,
                                            msg::Ciphertext,
                                            shr::Tally_selection_share)::Int64
    acc = 0
    for (_, part) in shr.recovered_parts
        acc |= are_part_substitute_decryptions_correct(er, msg, part)
    end
    acc
end

function are_part_substitute_decryptions_correct(er::Election_record,
                                                 msg::Ciphertext,
                                                 rp::Recovered_part)::Int64
    p = rp.proof
    are_substitute_decryptions_correct_a(er, p) |
        are_substitute_decryptions_correct_b(er, p) |
        are_substitute_decryptions_correct_c(er, msg, rp) |
        are_substitute_decryptions_correct_d(er, msg, rp) |
        are_substitute_decryptions_correct_e(er, msg, rp)
end

function are_substitute_decryptions_correct_a(er::Election_record,
                                              p::Chaum_Pedersen_proof)::Int64
    within(p.response, er.constants.q) ? 0 : A
end

function are_substitute_decryptions_correct_b(er::Election_record,
                                              p::Chaum_Pedersen_proof)::Int64
    c = er.constants
    within_mod(p.pad, c.q, c.p) && within_mod(p.data, c.q, c.p) ? 0 : B
end

function are_substitute_decryptions_correct_c(er::Election_record,
                                              msg::Ciphertext,
                                              rp::Recovered_part)::Int64
    c = er.constants
    p = rp.proof
    p.challenge ==
        eg_hash(c.q,
                er.context.crypto_extended_base_hash,
                msg.pad,
                msg.data,
                p.pad,
                p.data,
                rp.share) ? 0 : C
end

function are_substitute_decryptions_correct_d(er::Election_record,
                                              msg::Ciphertext,
                                              rp::Recovered_part)::Int64
    c = er.constants
    p = rp.proof
    ell = guardian(er, rp.guardian_id).sequence_order
    g = guardian(er, rp.missing_guardian_id)
    K = BigInt(1)
    # Vector indexing in Julia is one based.
    for (j, p) in enumerate(g.election_proofs)
        ell_sup_j = BigInt(ell ^ (j - 1))
        K = mulpowmod(K, p.public_key, ell_sup_j, c.p)
    end
    powermod(c.g, p.response, c.p) ==
        mulpowmod(p.pad, K, p.challenge, c.p) ? 0 : D
end

# Why are guardian_id's strings instead of int64s?  If they were ints,
# the following could be replaced with
#
#     er.guardians[guardian]
#
function guardian(er::Election_record, guardian::String)::Guardian
    for g in er.guardians
        if g.guardian_id == guardian
            return g
        end
    end
    error("Guardian $guardian not found")
end

function are_substitute_decryptions_correct_e(er::Election_record,
                                              msg::Ciphertext,
                                              rp::Recovered_part)::Int64
    c = er.constants
    p = rp.proof
    powermod(msg.pad, p.response, c.p) ==
        mulpowmod(p.data,
                  rp.share,
                  p.challenge,
                  c.p) ? 0 : E
end

end
