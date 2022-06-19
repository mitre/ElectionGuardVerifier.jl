# A script that makes src/Standard_constants.jl

# To update src/Standard_constants.jl from data/constants.json,
# in the project directory, type:
#
# julia --project=. src/Make_constants.jl

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

using JSON

in_file = joinpath(@__DIR__, "..", "data", "constants.json")

out_file = joinpath(@__DIR__, "Standard_constants.jl")

function load_json(path)
    handle = open(path)
    try
        JSON.parse(handle)
    finally
        close(handle)
    end
end

dict = load_json(in_file)

out = open(out_file, "w")

"Load a BigInt."
function load_bigint(str)
    parse(BigInt, str, base = 16)
end

println(out, "# Standard constants")
println(out)
println(out, "# Made from ../data/constants.json")
println(out, "# by the Make_constants.jl script.")
println(out)
println(out, "#=")
println(out, "Copyright (c) 2022 The MITRE Corporation")
println(out)
println(out, "This program is free software: you can redistribute it and/or")
println(out, "modify it under the terms of the MIT License.")
println(out, "=#")
println(out)
println(out, "module Standard_constants")
println(out)
println(out, "using ..Datatypes")
println(out)
println(out, "export constants")
println(out)
println(out, "const constants = Constants(")
println(out, "  ", load_bigint(dict["large_prime"]), ',')
println(out, "  ", load_bigint(dict["small_prime"]), ',')
println(out, "  ", load_bigint(dict["cofactor"]), ',')
println(out, "  ", load_bigint(dict["generator"]), ')')
println(out)
println(out, "end")

close(out)
