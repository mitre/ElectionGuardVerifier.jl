# 10. Missing Tally Share

# Check the second part of 10, that the missing tally shares are
# correct.

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Missing_tally_share

using ..Datatypes
using ..Utils: mulpowmod

export check_missing_tally_share

"10. Missing Tally Share"
function check_missing_tally_share(er::Election_record,
                                   tally::Tally,
                                   is_tally::Bool)::Bool
    shares = 0
    good_shares = 0
    # for each contest
    for (_, c) in tally.contests
        # for each selection in contest
        for (_, sel) in c.selections
            for share in sel.shares
                if share.proof == nothing
                    shares += 1
                    prod = BigInt(1)
                    for (_, rp) in share.recovered_parts
                        coef = er.coefficients.coefficients[rp.guardian_id]
                        prod = mulpowmod(prod,
                                         rp.share,
                                         coef,
                                         er.constants.p)
                    end
                    # M_i == prod(M_il ^ w_l) mod p?
                    if share.share == prod
                        good_shares += 1
                    end
                end
            end
        end
    end
    if is_tally
        name = "tally"
    else
        name = "spoiled ballot"
    end
    if shares == good_shares
        println("10. Missing $name shares are correct.")
        true
    else
        println("10. Missing $name shares are incorrect,")
        good_shares = shares - good_shares
        println("    $good_shares out of $shares incorrect.")
        false
    end
end

end
