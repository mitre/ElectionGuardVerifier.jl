# An exponential form of the ElGamal cryptosystem

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module ElGamal

using ..Datatypes

export encr, Keys, make_keys, decr

"Pick a random number in [1, q)."
function randq(c::Constants)::BigInt
    rand(1:c.q - 1)
end

"Compute g^x mod p."
function powmod(c::Constants, x::BigInt)::BigInt
    powermod(c.g, x, c.p)
end

"""
    encr(c, M, K)

Encrypt message M using public key K and constants c.
The output is:

(g^r mod p, g^M * K^r mod p)

where r is randomly chosen.

Message M is a boolean value.
"""
function encr(c::Constants, mess::Bool, pubk::BigInt)::Tuple{BigInt, BigInt}
    r = randq(c)
    (powmod(c, r), mod(powmod(c, big(mess))
                       * powermod(pubk, r, c.p),
                       c.p))
end

"ElGamal asymmetric key pair"
struct Keys
    consts::Constants
    privk::BigInt
    pubk::BigInt
    one::BigInt                 # Cache g mod p for use in decryption
end

"""
    make_keys(c)

Generate an ElGamal public/private key pair from constants c.

The output is:

(g^s mod p, s)

where s is randomly chosen.
"""
function make_keys(c::Constants)::Keys
    privk = randq(c)
    pubk = powmod(c, privk)
    Keys(c, privk, pubk, mod(c.g, c.p))
end

"""
    decr(k, (α, β))

Decrypt ElGamal cyphertext using keys k.

The output is:

β / α^s mod p == 1 ==> false

β / α^s mod p == g mod p ==> true

otherwise ==> throw domain error

where s is the private key in k.
"""
function decr(k::Keys, (α, β)::Tuple{BigInt, BigInt})::Bool
    val = mod(mod(β, k.consts.p)
               * powermod(α, -k.privk, k.consts.p),
               k.consts.p)
    if val == 1
        false
    elseif val == k.one
        true
    else
        throw(DomainError(val, "ElGamal message must be one or zero"))
    end
end

end
