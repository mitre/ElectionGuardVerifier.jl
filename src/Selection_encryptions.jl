# 4. Correctness of Selection Encryptions

# Ensure the selection encryptions are valid

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Selection_encryptions

using ..Datatypes
using ..Answers
using ..Utils
using ..Hash

export verify_selection_encryptions

"4. Correctness of Selection Encryptions"
function verify_selection_encryptions(er::Election_record)::Answer
    acc = 0                     # Accumulated bit items
    comment = "Selection encryptions are valid."
    count = 0                   # Records checked
    failed = 0
    for ballot in er.submitted_ballots
        count += 1
        failed_yet = false      # Ensure at most one failure
        for contest in ballot.contests
            for sel in contest.ballot_selections
                bits = is_selection_encryption_correct(er, sel)
                if bits != 0
                    name = ballot.object_id
                    comment = "Ballot $name has a bad selection encryption."
                    acc |= bits
                    if !failed_yet
                        failed += 1
                        failed_yet = true
                    end
                end
            end
        end
    end
    answer(4, bits2items(acc), "Correctness of selection encryption",
           comment, count, failed)
end

function is_selection_encryption_correct(er::Election_record,
                                         sel::Ballot_selection)::Int64
    is_selection_encryption_correct_a(er, sel) |
        is_selection_encryption_correct_b(er, sel) |
        is_selection_encryption_correct_c(er, sel) |
        is_selection_encryption_correct_d(er, sel) |
        is_selection_encryption_correct_e(er, sel) |
        is_selection_encryption_correct_f(er, sel) |
        is_selection_encryption_correct_g(er, sel) |
        is_selection_encryption_correct_h(er, sel)
end

function is_selection_encryption_correct_a(er::Election_record,
                                           sel::Ballot_selection)::Int64
    c = er.constants
    p = sel.proof
    within_mod(sel.ciphertext.pad, c.q, c.p) &&
        within_mod(sel.ciphertext.data, c.q, c.p) &&
        within_mod(p.proof_zero_pad, c.q, c.p) &&
        within_mod(p.proof_zero_data, c.q, c.p) &&
        within_mod(p.proof_one_pad, c.q, c.p) &&
        within_mod(p.proof_one_data, c.q, c.p) ? 0 : A
end

function is_selection_encryption_correct_b(er::Election_record,
                                           sel::Ballot_selection)::Int64
    c = er.constants
    p = sel.proof
    p.challenge ==
        eg_hash(c.q,
                er.context.crypto_extended_base_hash,
                sel.ciphertext.pad,
                sel.ciphertext.data,
                p.proof_zero_pad,
                p.proof_zero_data,
                p.proof_one_pad,
                p.proof_one_data) ? 0 : B
end

function is_selection_encryption_correct_c(er::Election_record,
                                           sel::Ballot_selection)::Int64
    c = er.constants
    p = sel.proof
    within(p.proof_zero_challenge, c.q) &&
        within(p.proof_one_challenge, c.q) &&
        within(p.proof_zero_response, c.q) &&
        within(p.proof_one_response, c.q) ? 0 : C
end

function is_selection_encryption_correct_d(er::Election_record,
                                           sel::Ballot_selection)::Int64
    c = er.constants
    p = sel.proof
    p.challenge ==
        mod(p.proof_zero_challenge + p.proof_one_challenge, c.q) ? 0 : D
end

function is_selection_encryption_correct_e(er::Election_record,
                                           sel::Ballot_selection)::Int64
    c = er.constants
    p = sel.proof
    powermod(c.g, p.proof_zero_response, c.p) ==
        mulpowmod(p.proof_zero_pad,
                  sel.ciphertext.pad,
                  p.proof_zero_challenge,
                  c.p) ? 0 : E
end

function is_selection_encryption_correct_f(er::Election_record,
                                           sel::Ballot_selection)::Int64
    c = er.constants
    p = sel.proof
    powermod(c.g, p.proof_one_response, c.p) ==
        mulpowmod(p.proof_one_pad,
                  sel.ciphertext.pad,
                  p.proof_one_challenge,
                  c.p) ? 0 : F
end

function is_selection_encryption_correct_g(er::Election_record,
                                           sel::Ballot_selection)::Int64
    c = er.constants
    p = sel.proof
    powermod(er.context.elgamal_public_key,
             p.proof_zero_response, c.p) ==
                 mulpowmod(p.proof_zero_data,
                           sel.ciphertext.data,
                           p.proof_zero_challenge,
                           c.p) ? 0 : G
end

function is_selection_encryption_correct_h(er::Election_record,
                                           sel::Ballot_selection)::Int64
    c = er.constants
    p = sel.proof
    mulpowmod(powermod(c.g, p.proof_one_challenge, c.p),
              er.context.elgamal_public_key,
              p.proof_one_response,
              c.p) ==
                  mulpowmod(p.proof_one_data,
                            sel.ciphertext.data,
                            p.proof_one_challenge,
                            c.p) ? 0 : H
end

end
