# Load minimal, small, full, and hamilton-general sample data

using ElectionGuardVerifier

function load_sample(sample_data, election)
    elec_rec = load(joinpath(sample_data,
                             joinpath(election, "election_record")))
    println(election)
    elec_rec
end

function load_elections(sample_data)
    map(election -> load_sample(sample_data, election),
        ["minimal", "small", "full", "hamilton-general"])
end
