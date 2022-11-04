# ElectionGuardVerifier.jl documentation
#
# Build with:
#
# julia --project make.jl

using Documenter, ElectionGuardVerifier

makedocs(
    sitename = "ElectionGuard Verifier",
    authors = "John D. Ramsdell and Moses D. Liskov",
    format = Documenter.HTML(prettyurls = false),
    pages = [
        "Home" => "index.md",
        "installation.md",
        "usage.md",
        "results.md",
	"gitpod.md",
        "development.md"
    ]
)
