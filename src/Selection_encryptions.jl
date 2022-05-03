# 4. Correctness of Selection Encryptions

# Ensure the selection encryptions are valid

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Selection_encryptions

using ..Datatypes
using ..Utils
using ..Hash

export check_selection_encryptions

"4. Correctness of Selection Encryptions"
function check_selection_encryptions(er::Election_record)::Bool
    ans = true
    for ballot in er.submitted_ballots
        for contest in ballot.contests
            for sel in contest.ballot_selections
                if !is_selection_encryption_correct(er, sel)
                    if ans
                        name = ballot.object_id
                        println(" 4. Ballot $name has a bad selection encryption.")
                    end
                    ans = false
                end
            end
        end
    end
    if ans
        println(" 4. Selection encryptions are valid.")
    end
    ans
end

function is_selection_encryption_correct(er::Election_record,
                                         sel::Ballot_selection)::Bool
    is_selection_encryption_correct_a(er, sel) &&
        is_selection_encryption_correct_b(er, sel) &&
        is_selection_encryption_correct_c(er, sel) &&
        is_selection_encryption_correct_d(er, sel) &&
        is_selection_encryption_correct_e(er, sel) &&
        is_selection_encryption_correct_f(er, sel) &&
        is_selection_encryption_correct_g(er, sel) &&
        is_selection_encryption_correct_h(er, sel)
end

function is_selection_encryption_correct_a(er::Election_record,
                                           sel::Ballot_selection)::Bool
    c = er.constants
    p = sel.proof
    within_mod(sel.ciphertext.pad, c.q, c.p) &&
        within_mod(sel.ciphertext.data, c.q, c.p) &&
        within_mod(p.proof_zero_pad, c.q, c.p) &&
        within_mod(p.proof_zero_data, c.q, c.p) &&
        within_mod(p.proof_one_pad, c.q, c.p) &&
        within_mod(p.proof_one_data, c.q, c.p)
end

function is_selection_encryption_correct_b(er::Election_record,
                                           sel::Ballot_selection)::Bool
    c = er.constants
    p = sel.proof
    p.challenge ==
        #! Spec conflict
        #=
        eg_hash(c.q,
                er.context.crypto_extended_base_hash,
                sel.ciphertext,
                Ciphertext(p.proof_zero_pad, p.proof_zero_data),
                Ciphertext(p.proof_one_pad, p.proof_one_data))
        =#
        eg_hash(c.q,
                er.context.crypto_extended_base_hash,
                sel.ciphertext.pad,
                sel.ciphertext.data,
                p.proof_zero_pad,
                p.proof_zero_data,
                p.proof_one_pad,
                p.proof_one_data)
end

function is_selection_encryption_correct_c(er::Election_record,
                                           sel::Ballot_selection)::Bool
    c = er.constants
    p = sel.proof
    within(p.proof_zero_challenge, c.q) &&
        within(p.proof_one_challenge, c.q) &&
        within(p.proof_zero_response, c.q) &&
        within(p.proof_one_response, c.q)
end

function is_selection_encryption_correct_d(er::Election_record,
                                           sel::Ballot_selection)::Bool
    c = er.constants
    p = sel.proof
    p.challenge ==
        mod(p.proof_zero_challenge + p.proof_one_challenge, c.q)
end

function is_selection_encryption_correct_e(er::Election_record,
                                           sel::Ballot_selection)::Bool
    c = er.constants
    p = sel.proof
    powermod(c.g, p.proof_zero_response, c.p) ==
        mulpowmod(p.proof_zero_pad,
                  sel.ciphertext.pad,
                  p.proof_zero_challenge,
                  c.p)
end

function is_selection_encryption_correct_f(er::Election_record,
                                           sel::Ballot_selection)::Bool
    c = er.constants
    p = sel.proof
    powermod(c.g, p.proof_one_response, c.p) ==
        mulpowmod(p.proof_one_pad,
                  sel.ciphertext.pad,
                  p.proof_one_challenge,
                  c.p)
end

function is_selection_encryption_correct_g(er::Election_record,
                                           sel::Ballot_selection)::Bool
    c = er.constants
    p = sel.proof
    powermod(er.context.elgamal_public_key,
             p.proof_zero_response, c.p) ==
                 mulpowmod(p.proof_zero_data,
                           sel.ciphertext.data,
                           p.proof_zero_challenge,
                           c.p)
end

function is_selection_encryption_correct_h(er::Election_record,
                                           sel::Ballot_selection)::Bool
    c = er.constants
    p = sel.proof
    mulpowmod(powermod(c.g, p.proof_one_challenge, c.p),
              er.context.elgamal_public_key,
              p.proof_one_response,
              c.p) ==
                  mulpowmod(p.proof_one_data,
                            sel.ciphertext.data,
                            p.proof_one_challenge,
                            c.p)
end

end
