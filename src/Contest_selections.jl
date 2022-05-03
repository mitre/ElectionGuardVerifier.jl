# 11. Validation of Contest Selections with the Manifest

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Contest_selections

using ..Datatypes

export check_contest_selections

"11. Validation of Contest Selections with the Manifest"
function check_contest_selections(er::Election_record,
                                  tally::Tally,
                                  is_tally)::Bool
    ans = true
    if is_tally
        name = "Tally"
    else
        name = "Spoiled ballot"
    end

    # See if every contest selection in the manifest is in the tally.
    contests = er.manifest["contests"]
    tally_contests = tally.contests

    for contest in contests
        id = contest["object_id"]
        if !haskey(tally_contests, id)
            ans = false
            println("11. $name missing contest $id.")
        else
            tally_contest = tally_contests[id]
            for sel in contest["ballot_selections"]
                sel_id = sel["object_id"]
                if !haskey(tally_contest.selections, sel_id)
                    ans = false
                    println("11. $name missing selection $sel_id in contest $id.")
                end
            end
        end
    end

    # See if every contest selection in the tally is in the manifest.
    contests = to_dict(contests)
    for (_, tally_contest) in tally_contests
        id = tally_contest.object_id
        if !haskey(contests, id)
            ans = false
            println("11. $name has extra contest $id.")
        else
            contest = contests[id]
            sels = to_dict(contest["ballot_selections"])
            for (_, sel) in tally_contest.selections
                sel_id = sel.object_id
                if !haskey(sels, sel_id)
                    ans = false
                    println("11. $name has extra selection $sel_id in contest $id.")
                end
            end
        end
    end

    if ans
        println("11. $name selections agree with the manifest.")
    end
    ans
end

# Create a dictionary from a vector that contains a dictionaries with
# the key "object_id".  Use the key "object_id" key as the
# dictionary's key.
function to_dict(vector::Vector{Any})
    dict = Dict{String, Any}()
    for item in vector
        dict[item["object_id"]] = item
    end
    dict
end

end
