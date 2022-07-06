# 1. Parameter Validation

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
    Params

Ensure the constants are the standard ones.
"""
module Params

using ..Datatypes
using ..Answers
using ..Utils: same
using ..Standard_constants

export verify_params

"1. Parameter Validation"
function verify_params(er::Election_record)::Answer
    acc = 0
    comment = "Standard parameters were found."
    count = 0
    failed = 0
    er_const = er.constants

    # Large prime (Item A)
    count += 1
    bits = er_const.p == constants.p ? 0 : A
    if bits != 0
        acc |= bits
        comment = "Large prime is not standard."
        failed += 1
    end

    # Small prime (Item B)
    count += 1
    bits = er_const.q == constants.q ? 0 : B
    if bits != 0
        acc |= bits
        comment = "Small prime is not standard."
        failed += 1
    end

    # Cofactor (Item C)
    count += 1
    bits = er_const.r == constants.r ? 0 : C
    if bits != 0
        acc |= bits
        comment = "Cofactor is not standard."
        failed += 1
    end

    # Generator (Item D)
    count += 1
    bits = er_const.g == constants.g ? 0 : D
    if bits != 0
        acc |= bits
        comment = "Generator is not standard."
        failed += 1
    end

    answer(1, bits2items(acc), "Parameter verification",
           comment, count, failed)
end

end
