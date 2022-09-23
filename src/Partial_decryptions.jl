# 8. Correctness of Partial Decryptions

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Partial_decryptions

using ..Datatypes
using ..Answers
using ..Utils
using ..Hash

export verify_partial_decryptions

"8. Correctness of Partial Decryptions"
function verify_partial_decryptions(er::Election_record,
                                    tally::Tally,
                                    is_tally::Bool)::Answer
    acc = 0                     # Accumated bit items
    count = 0                   # Records checked
    failed = 0
    # for each contest
    for (_, c) in tally.contests
        # for each selection in contest
        for (_, sel) in c.selections
            msg = sel.message
            for share in sel.shares
                if share.proof != nothing
                    count += 1
                    bits = are_partial_decryptions_correct(er, msg, share)
                    if bits != 0
                        failed += 1
                        acc |= bits
                    end
                end
            end
        end
    end
    step = 8
    if is_tally
        name = "Tally"
    else
        name = "Spoiled ballot " * tally.object_id
        step += STEP_DELTA
    end
    if failed == 0
        comment = "$name partial decryptions are correct."
    else
        comment = "$name partial decryptions are incorrect."
    end
    answer(step, bits2items(acc), "Correctness of partial decryptions",
           comment, count, failed)
end

function are_partial_decryptions_correct(er::Election_record,
                                         msg::Ciphertext,
                                         shr::Tally_selection_share)::Int64
    p = shr.proof
    are_partial_decryptions_correct_a(er, p) |
        are_partial_decryptions_correct_b(er, p) |
        are_partial_decryptions_correct_c(er, msg, shr) |
        are_partial_decryptions_correct_d(er, msg, shr) |
        are_partial_decryptions_correct_e(er, msg, shr)
end

function are_partial_decryptions_correct_a(er::Election_record,
                                           p::Chaum_Pedersen_proof)::Int64
    within(p.response, er.constants.q) ? 0 : A
end

function are_partial_decryptions_correct_b(er::Election_record,
                                           p::Chaum_Pedersen_proof)::Int64
    c = er.constants
    within_mod(p.pad, c.q, c.p) && within_mod(p.data, c.q, c.p) ? 0 : B
end

function are_partial_decryptions_correct_c(er::Election_record,
                                           msg::Ciphertext,
                                           shr::Tally_selection_share)::Int64
    c = er.constants
    p = shr.proof
    p.challenge ==
        eg_hash(c.q,
                er.context.crypto_extended_base_hash,
                msg.pad,
                msg.data,
                p.pad,
                p.data,
                shr.share) ? 0 : C
end

function are_partial_decryptions_correct_d(er::Election_record,
                                           msg::Ciphertext,
                                           shr::Tally_selection_share)::Int64
    c = er.constants
    p = shr.proof
    Ki = get_guardian_pubkey(er, shr.guardian_id)
    if Ki !== nothing
        powermod(c.g, p.response, c.p) ==
    	    mulpowmod(p.pad, Ki, p.challenge, c.p) ? 0 : D
    else
        D
    end
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
                                           shr::Tally_selection_share)::Int64
    c = er.constants
    p = shr.proof
    powermod(msg.pad, p.response, c.p) ==
        mulpowmod(p.data,
                  shr.share,
                  p.challenge,
                  c.p) ? 0 : E
end

end
