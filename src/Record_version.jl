# Check the election record version number.

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Record_version

export check_record_version

const version = "v0.95"

"Check that the spec_version in the manifest is v0.95."
function check_record_version(manifest::Dict{String, Any})::Bool
    spec_version = manifest["spec_version"]
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
