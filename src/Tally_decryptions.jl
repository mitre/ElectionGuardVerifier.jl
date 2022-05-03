# 11. Validation of Correct Decryption of Tallies

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Tally_decryptions

using ..Datatypes

export check_tally_decryptions

"11. Validation of Correct Decryption of Tallies"
function check_tally_decryptions(er::Election_record,
                                 tally::Tally,
                                 is_tally::Bool)::Bool
    decrypts = 0
    good_decrypts = 0
    # for each contest
    for (_, c) in tally.contests
        # for each selection in contest
        for (_, sel) in c.selections
            decrypts += 1
            if are_tally_decryptions_correct(er, sel)
                good_decrypts += 1
            end
        end
    end
    if is_tally
        name = "Tally"
    else
        name = "Spoiled ballot"
    end
    if decrypts == good_decrypts
        println("11. $name decryptions are correct.")
        true
    else
        println("11. $name decryptions are incorrect,")
        good_decrypts = decrypts - good_decrypts
        println("   $good_decrypts out of $decrypts incorrect.")
        false
    end
end

function are_tally_decryptions_correct(er::Election_record,
                                       sel::Tally_selection)::Bool
    are_tally_decryptions_correct_a(er, sel) &&
        are_tally_decryptions_correct_b(er, sel)
end

# B = (M * prod(M_i) mod p
function are_tally_decryptions_correct_a(er::Election_record,
                                         sel::Tally_selection)::Bool
    c = er.constants
    decr = BigInt(1)
    for shr in sel.shares
        decr = mod(decr * shr.share, c.p)
    end
    sel.message.data == mod(sel.value * decr, c.p)
end

# M = g^t mod p
function are_tally_decryptions_correct_b(er::Election_record,
                                         sel::Tally_selection)::Bool
    c = er.constants
    sel.value == powermod(c.g, sel.tally, c.p)
end

end
