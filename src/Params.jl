# 1. Parameter Validation

# Ensure the constants are the standard ones.

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Params

using ..Datatypes
using ..Utils: same
using ..Standard_constants

export check_params

"1. Parameter Validation"
function check_params(er::Election_record)::Bool
    ans = same(er.constants, constants)
    if ans
        println(" 1. Standard parameters were found.")
    else
        println(" 1. Non-standard parameters were found.")
    end
    ans
end

end
