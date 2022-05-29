# 11. Validation of Correct Decryption of Tallies

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Tally_decryptions

using ..Datatypes
using ..Answers

export verify_tally_decryptions

"11. Validation of Correct Decryption of Tallies"
function verify_tally_decryptions(er::Election_record,
                                  tally::Tally,
                                  is_tally::Bool)::Answer
    acc = 0                     # Accumulated item bits
    count = 0                   # Records checked
    failed = 0
    # for each contest
    for (_, c) in tally.contests
        # for each selection in contest
        for (_, sel) in c.selections
            count += 1
            bits = are_tally_decryptions_correct(er, sel)
            if bits != 0
                failed += 1
                acc |= bits
            end
        end
    end
    if is_tally
        name = "Tally"
        step = 11
    else
        name = "Spoiled ballot " * tally.object_id
        step = 13
    end
    if failed == 0
        comment = "$name decryptions are correct."
    else
        comment = "$name decryptions are incorrect."
    end
    answer(step, bits2items(acc),
           "Validation of correct decryption of tallies",
           comment, count, failed)
end

function are_tally_decryptions_correct(er::Election_record,
                                       sel::Tally_selection)::Int64
    are_tally_decryptions_correct_a(er, sel) |
        are_tally_decryptions_correct_b(er, sel)
end

# B = (M * prod(M_i) mod p
function are_tally_decryptions_correct_a(er::Election_record,
                                         sel::Tally_selection)::Int64
    c = er.constants
    decr = BigInt(1)
    for shr in sel.shares
        decr = mod(decr * shr.share, c.p)
    end
    sel.message.data == mod(sel.value * decr, c.p) ? 0 : A
end

# M = g^t mod p
function are_tally_decryptions_correct_b(er::Election_record,
                                         sel::Tally_selection)::Int64
    c = er.constants
    sel.value == powermod(c.g, sel.tally, c.p) ? 0 : B
end

end
