# 8. Correctness of Partial Decryptions

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Partial_decryptions

using ..Datatypes
using ..Utils
using ..Hash

export check_partial_decryptions

"8. Correctness of Partial Decryptions"
function check_partial_decryptions(er::Election_record,
                                   tally::Tally,
                                   is_tally::Bool)::Bool
    decrypts = 0
    good_decrypts = 0
    # for each contest
    for (_, c) in tally.contests
        # for each selection in contest
        for (_, sel) in c.selections
            msg = sel.message
            for share in sel.shares
                if share.proof != nothing
                    decrypts += 1
                    if are_partial_decryptions_correct(er, msg, share)
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
        println(" 8. $name partial decryptions are correct.")
        true
    else
        println(" 8. $name partial decryptions are incorrect,")
        good_decrypts = decrypts - good_decrypts
        println("    $good_decrypts out of $decrypts incorrect.")
        false
    end
end

function are_partial_decryptions_correct(er::Election_record,
                                         msg::Ciphertext,
                                         shr::Tally_selection_share)::Bool
    p = shr.proof
    are_partial_decryptions_correct_a(er, p) &&
        are_partial_decryptions_correct_b(er, p) &&
        are_partial_decryptions_correct_c(er, msg, shr) &&
        are_partial_decryptions_correct_d(er, msg, shr) &&
        are_partial_decryptions_correct_e(er, msg, shr)
end

function are_partial_decryptions_correct_a(er::Election_record,
                                           p::Chaum_Pedersen_proof)::Bool
    within(p.response, er.constants.q)
end

function are_partial_decryptions_correct_b(er::Election_record,
                                           p::Chaum_Pedersen_proof)::Bool
    c = er.constants
    within_mod(p.pad, c.q, c.p) && within_mod(p.data, c.q, c.p)
end

function are_partial_decryptions_correct_c(er::Election_record,
                                           msg::Ciphertext,
                                           shr::Tally_selection_share)::Bool
    c = er.constants
    p = shr.proof
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
                shr.share)
end

function are_partial_decryptions_correct_d(er::Election_record,
                                           msg::Ciphertext,
                                           shr::Tally_selection_share)::Bool
    c = er.constants
    p = shr.proof
    Ki = get_guardian_pubkey(er, shr.guardian_id)
    powermod(c.g, p.response, c.p) ==
        mulpowmod(p.pad, Ki, p.challenge, c.p)
end

function get_guardian_pubkey(er::Election_record, guardian::String)
    for g in er.guardians
        if g.guardian_id == guardian
            return g.election_public_key
        end
    end
    nothing
end

function are_partial_decryptions_correct_e(er::Election_record,
                                           msg::Ciphertext,
                                           shr::Tally_selection_share)::Bool
    c = er.constants
    p = shr.proof
    powermod(msg.pad, p.response, c.p) ==
        mulpowmod(p.data,
                  shr.share,
                  p.challenge,
                  c.p)
end

end
