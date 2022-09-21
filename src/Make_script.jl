# A script that makes a shell script for this verifier.

# julia src/Make_script.jl

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

println("#! /bin/sh")
println()
println("# Verify an election record")
println("# The first argument is the directory containing")
println("# the election record (. by default).")
println()
println("path=\${1:-.}")
project = joinpath(@__DIR__, "..")
println("julia --project=" * project * " --threads=auto -e '")
println("using ElectionGuardVerifier;")
println("er=load(\"'\$path'\");")
println("println(check(er, \"vr.json\"))'")
