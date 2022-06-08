# 11. Validation of Contest Selections with the Manifest

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Contest_selections

using ..Datatypes
using ..Answers

export verify_contest_selections

"11. Validation of Contest Selections with the Manifest"
function verify_contest_selections(er::Election_record,
                                   tally::Tally,
                                   is_tally)::Answer
    acc = 0                     # Accumulated bit items
    # C means a contest is  missing in the tally
    # D means a ballot selection is missing in the tally
    # E means an extra contest is in the tally
    # F means an extra ballot selection is in the tally
    count = 0                   # Records checked
    failed = 0
    if is_tally
        name = "Tally"
        step = 11
    else
        name = "Spoiled ballot " * tally.object_id
        step = 13
    end
    comment = "$name selections agree with the manifest."

    # See if every contest selection in the manifest is in the tally.
    contests = er.manifest["contests"]
    tally_contests = tally.contests

    for contest in contests
        count += 1
        id = contest["object_id"]
        if !haskey(tally_contests, id)
            comment = "$name missing contest $id."
            acc |= C
            failed += 1
        else
            tally_contest = tally_contests[id]
            for sel in contest["ballot_selections"]
                failed_yet = false
                sel_id = sel["object_id"]
                if !haskey(tally_contest.selections, sel_id)
                    comment = "$name missing selection $sel_id in contest $id."
                    acc |= D
                    if !failed_yet
                        failed += 1
                        failed_yet = true
                    end
                end
            end
        end
    end

    # See if every contest selection in the tally is in the manifest.
    contests = to_dict(contests)
    for (_, tally_contest) in tally_contests
        count += 1
        id = tally_contest.object_id
        if !haskey(contests, id)
            comment = "$name has extra contest $id."
            acc |= E
            failed += 1
        else
            contest = contests[id]
            sels = to_dict(contest["ballot_selections"])
            failed_yet = false
            for (_, sel) in tally_contest.selections
                sel_id = sel.object_id
                if !haskey(sels, sel_id)
                    comment =
                        "$name has extra selection $sel_id in contest $id."
                    acc |= F
                    if !failed_yet
                        failed += 1
                        failed_yet = true
                    end
                end
            end
        end
    end

    answer(step, bits2items(acc),
           "Validation of correct decryption of tallies",
           comment, count, failed)
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