# 10. Correctness of Coefficients

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Coefficients

using ..Datatypes

export check_coefficients

"10. Correctness of Coefficients"
function check_coefficients(er::Election_record)::Bool
    ans = true
    c = er.constants
    coefs = er.coefficients.coefficients
    for (ell, w_ell) = enumerate(coefs)
        prod_j = 1
        prod_j_minus_ell = 1
        for j in 1:length(coefs)
            if j != ell
                prod_j *= j
                prod_j_minus_ell *= j - ell
            end
        end
        if mod(BigInt(prod_j), c.q) !=
            mod(w_ell * BigInt(prod_j_minus_ell), c.q)
            println("10. Coefficient check for guardian $ell failed.")
            ans = false
        end
    end
    if ans
        println("10. Coefficients validated.")
    end
    ans
end

end
