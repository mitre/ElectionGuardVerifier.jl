# 9. Correctness of Substitute Decryptions

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Substitute_decryptions

using ..Datatypes
using ..Utils
using ..Hash

export check_substitute_decryptions

"9. Correctness of Substitute Decryptions"
function check_substitute_decryptions(er::Election_record,
                                      tally::Tally,
                                      is_tally)::Bool
    decrypts = 0
    good_decrypts = 0
    # for each contest
    for (_, c) in tally.contests
        # for each selection in contest
        for (_, sel) in c.selections
            msg = sel.message
            for share in sel.shares
                if share.proof == nothing
                    decrypts += 1
                    if are_substitute_decryptions_correct(er, msg, share)
                        good_decrypts += 1
                    end
                end
            end
        end
    end
    if is_tally
        name = "Tally"
    else
        name = "Spoiled ballot"
    end
    if decrypts == good_decrypts
        println(" 9. $name substitute decryptions are correct.")
        true
    else
        println(" 9. $name substitute decryptions are incorrect,")
        good_decrypts = decrypts - good_decrypts
        println("    $good_decrypts out of $decrypts incorrect.")
        false
    end
end

function are_substitute_decryptions_correct(er::Election_record,
                                            msg::Ciphertext,
                                            shr::Tally_selection_share)::Bool
    for (_, part) in shr.recovered_parts
        if !are_part_substitute_decryptions_correct(er, msg, part)
            return false
        end
    end
    true
end

function are_part_substitute_decryptions_correct(er::Election_record,
                                                 msg::Ciphertext,
                                                 rp::Recovered_part)::Bool
    p = rp.proof
    are_substitute_decryptions_correct_a(er, p) &&
        are_substitute_decryptions_correct_b(er, p) &&
        are_substitute_decryptions_correct_c(er, msg, rp) &&
        are_substitute_decryptions_correct_d(er, msg, rp) &&
        are_substitute_decryptions_correct_e(er, msg, rp)
end

function are_substitute_decryptions_correct_a(er::Election_record,
                                              p::Chaum_Pedersen_proof)::Bool
    within(p.response, er.constants.q)
end

function are_substitute_decryptions_correct_b(er::Election_record,
                                              p::Chaum_Pedersen_proof)::Bool
    c = er.constants
    within_mod(p.pad, c.q, c.p) && within_mod(p.data, c.q, c.p)
end

function are_substitute_decryptions_correct_c(er::Election_record,
                                              msg::Ciphertext,
                                              rp::Recovered_part)::Bool
    c = er.constants
    p = rp.proof
    p.challenge ==
        #! Spec conflict
        # Incorrect hash was specified.
        # This is the correct one.
        eg_hash(c.q,
                er.context.crypto_extended_base_hash,
                msg.pad,
                msg.data,
                p.pad,
                p.data,
                rp.share)
end

function are_substitute_decryptions_correct_d(er::Election_record,
                                              msg::Ciphertext,
                                              rp::Recovered_part)::Bool
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
        mulpowmod(p.pad, K, p.challenge, c.p)
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
                                              rp::Recovered_part)::Bool
    c = er.constants
    p = rp.proof
    powermod(msg.pad, p.response, c.p) ==
        mulpowmod(p.data,
                  rp.share,
                  p.challenge,
                  c.p)
end

end
