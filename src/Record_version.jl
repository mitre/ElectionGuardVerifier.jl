# Check the election record version number.

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Record_version

using ..Datatypes

export check_record_version

const version = "1.0"

"Check that the spec_version in the manifest is the one expected."
function check_record_version(manifest::Manifest)::Bool
    spec_version = manifest.spec_version
    if spec_version == version
        println("Found $spec_version election records as expected.")
        return true
    else
        println("Found unexpected $spec_version election records.")
        println("Record loading errors are likely.")
        return false
    end
end

end
