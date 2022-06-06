# Parallel mapreduce for ElectionGuard

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
   Parallel_mapreduce

This module provides a thread parallel implementation of mapreduce.
"""
module Parallel_mapreduce

export pmapreduce

import Base.mapreduce
using Base.Threads

const MIN_STRIDE = 4

"""
    pmapreduce(f, op, vec::AbstractVector)

When Julia is started with enough threads, this version of mapreduce
divides a vector into into sections, runs mapreduce on each section in
parallel, and then collects the results using the op function.
"""
function pmapreduce(f, op, vec::AbstractVector)
    if nthreads == 1
        return mapreduce(f, op, vec)
    end
    len = length(vec)
    t = nthreads()
    # The stride is the length of the vector processed by one thread.
    stride = div(len, t)
    # Avoid dividing the vector too much.
    stride = max(MIN_STRIDE, stride)
    # The number of tasks that will be scheduled.
    ntasks = div(len, stride)
    if ntasks < 2
        return mapreduce(f, op, vec)
    end
    task = Vector{Task}()
    # Spawn all but the last task.
    i = 1                       # i is the start index of a section.
    for j in 1 : ntasks - 1
        v = vec[i : stride + i - 1] # v is the section to be processed.
        # Note that the value for v is interpolated because v is changing.
        push!(task, @spawn mapreduce(f, op, $v))
        i += stride
    end
    # Process whatever remains to be done.
    v = vec[i : len]
    push!(task, @spawn mapreduce(f, op, $v))

    # Collect the results.
    acc = fetch(task[1])
    for j in 2 : ntasks
        acc = op(acc, fetch(task[j]))
    end
    acc
end

end
