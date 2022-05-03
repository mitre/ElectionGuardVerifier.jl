# Load sample data in electionguard directory.

include("Sample.jl")

sample_data = "../../electionguard/data/0.95.0/sample"

es = load_elections(sample_data)

# Check the small sample data.
check(es[2])
