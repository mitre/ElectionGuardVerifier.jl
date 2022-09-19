# 10A. Correctness of Coefficients

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Coefficients

using ..Datatypes
using ..Answers

export verify_coefficients

"10A. Correctness of Coefficients"
function verify_coefficients(er::Election_record)::Answer
    comment = "Coefficients validated."
    count = 0                   # Records checked
    failed = 0                  # Failure count
    c = er.constants
    coefs = er.coefficients.coefficients
    for (ell, w_ell) in coefs
        count += 1
        ell = tryparse(Int64, ell)
	if ell === nothing
	    failed += 1
	    comment = "Bad guardian identifier $ell -- must be an int."
	    continue
	end
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
            failed += 1
            comment = "Coefficient check for guardian $ell failed."
        end
    end
    answer(10, failed == 0 ? "" : "A",
           "Correctness of construction of replacement partial decryption",
           comment, count, failed)
end

end
