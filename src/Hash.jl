# Hashing for ElectionGuard

#=
ElectionGuard uses SHA2 256 for hashing.  When
there is more than one item to be hashed, it
concatenates the items using the vertical bar
character as a separator.  Vertical bar is also
used to delimit the contents of the hash.
=#

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Hash

using SHA
import Printf

export eg_hash

const null_bytestring = Vector{UInt8}("null")

const vbar_bytestring = Vector{UInt8}("|")

"""
    eg_hash(q::BigInt, x, xs...)::BigInt

Return the SHA2 256 hash of the arguments x,xs.
"""
function eg_hash(q::BigInt, x, xs...)::BigInt
    ctx = SHA2_256_CTX()
    # Start with vertical bar.
    update!(ctx, vbar_bytestring)
    eg_hash!(ctx, q, x)
    for y in xs
        # Use vertical bar as a separator.
        update!(ctx, vbar_bytestring)
        eg_hash!(ctx, q, y)
    end
    # End with vertical bar.
    update!(ctx, vbar_bytestring)
    # Convert hash to a BigInt assuming a big endian byte ordering.
    mod(to_big(digest!(ctx)), q)
end

"Hash a single item."
function eg_hash!(ctx, q, x)
    if x isa BigInt
        eg_hash_bigint!(ctx, x)
    elseif x isa Integer
        # Convert to base 10 UTF-8 and hash the string.
        update!(ctx, Vector{UInt8}(string(x)))
    elseif x isa AbstractString
        # Hash the UTF-8 string.
        update!(ctx, Vector{UInt8}(x))
    elseif isempty(x)
        update!(ctx, null_bytestring)
    else
        # Hash the sequence, then add that result to the SHA context.
        eg_hash_bigint!(ctx, eg_hash(q, x...))

        #= A better hashing function would be:

        eg_hash!(q, ctx, x[1])
        for y in x[2:length(x)]
            update!(ctx, vbar_bytestring)
            eg_hash!(q, ctx, y)
        end

        With this definition, q would not have to be passed to eg_hash!
        =#
    end
end

"Hash a BigInt."
function eg_hash_bigint!(ctx, x)
    str = Printf.@sprintf("%02X", x)
    if isodd(length(str))
        str = "0" * str
    end
    update!(ctx, Vector{UInt8}(str))
end

"Convert a vector of bytes to a BigInt using a big endian byte ordering"
function to_big(bytes::Vector{UInt8})::BigInt
    sum = BigInt(0)
    for b in bytes
        sum = BigInt(256) * sum + BigInt(b)
    end
    sum
end

end
