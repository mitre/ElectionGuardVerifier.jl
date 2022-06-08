# Miscellaneous utilities

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
    Utils

Functions used to implement Election Guard checks.
"""
module Utils

import Base.iterate
using ..Datatypes

export mulpowmod, same, within, within_mod, one_ct, prod_ct

"mulpowermod(a, x, b, p) = (a * x ^ b) mod p"
function mulpowmod(a::BigInt, x::BigInt, b::BigInt, p::BigInt)::BigInt
    mod(a * powermod(x, b, p), p)
end

"""
    same(c1::Constants, c2::Constants)::Bool

Are two sets of constants the same?
"""
function same(c1::Constants, c2::Constants)::Bool
    c1.p == c2.p &&
        c1.q == c2.q &&
        c1.r == c2.r &&
        c1.g == c2.g
end

"""
    same(c1::Ciphertext, c2::Ciphertext)::Bool

Are two ciphertexts the same?
"""
function same(c1::Ciphertext, c2::Ciphertext)::Bool
    c1.pad == c2.pad && c1.data == c2.data
end

"Make ciphertexts iterable."
function iterate(c::Ciphertext)
    c.pad, true
end

function iterate(c::Ciphertext, more::Bool)
    if more
        c.data, false
    else
        nothing
    end
end

"""
    within(x::BigInt, p::BigInt)::Bool

Is 0 ≤ x < p?
"""
function within(x::BigInt, p::BigInt)::Bool
    zero(BigInt) ≤ x < p
end

"""
    within_mod(x::BigInt, q::BigInt, p::BigInt)::Bool

Is 0 ≤ x < p and (x ^ q) mod p == 1?
"""
function within_mod(x::BigInt, q::BigInt, p::BigInt)::Bool
    within(x, p) && powermod(x, q, p) == one(BigInt)
end

"""
    one_ct::Ciphertext

one_ct = Ciphertext(1, 1)
"""
const one_ct = Ciphertext(one(BigInt), one(BigInt))

"""
    prod_ct(x1::Ciphertext, x2::Ciphertext, p::BigInt)::Ciphertext

Multiply two ciphertexts mod p
"""
function prod_ct(x1::Ciphertext, x2::Ciphertext, p::BigInt)::Ciphertext
    Ciphertext(mod(x1.pad * x2.pad, p),
               mod(x1.data * x2.data, p))
end

end
