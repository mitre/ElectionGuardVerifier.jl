# 10. Missing Tally Share

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
    Missing_tally_share

Check the second part of 10, that the missing tally shares are
correct.
"""
module Missing_tally_share

using ..Datatypes
using ..Answers
using ..Utils: mulpowmod

export verify_missing_tally_share

"10B. Missing Tally Share"
function verify_missing_tally_share(er::Election_record,
                                    tally::Tally,
                                    is_tally::Bool)::Answer
    count = 0                   # Records checked
    failed = 0
    # for each contest
    for (_, c) in tally.contests
        # for each selection in contest
        for (_, sel) in c.selections
            for share in sel.shares
                if share.proof == nothing
                    count += 1
                    prod = one(BigInt)
                    for (_, rp) in share.recovered_parts
                        coef = er.coefficients.coefficients[rp.guardian_id]
                        prod = mulpowmod(prod,
                                         rp.share,
                                         coef,
                                         er.constants.p)
                    end
                    # M_i == prod(M_il ^ w_l) mod p?
                    if share.share != prod
                        failed += 1
                    end
                end
            end
        end
    end
    step = 10
    if is_tally
        name = "tally"
    else
        name = "spoiled ballot " * tally.object_id
        step += STEP_DELTA
    end
    if failed == 0
        comment = "Missing $name shares are correct."
    else
        comment = "Missing $name shares are incorrect."
    end
    answer(step, failed == 0 ? "" : "B",
           "Correctness of construction of replacement partial decryptions",
           comment, count, failed)
end

end
