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
    ans = same(er.constants, constants)
    if ans
        comment = "Standard parameters were found."
        failed = 0
    else
        comment = "Non-standard parameters were found."
        failed = 1
    end
    answer(1, "", "Parameter verification", comment, 1, failed)
end

end
