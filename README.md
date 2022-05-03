# MITRE ElectionGuard Verifier

[ElectionGuard](https://www.electionguard.vote/) is a software system
designed to make voting more secure, transparent and accessible.
ElectionGuard uses cryptography to ensure that

 - voters can verify that their own selections have been correctly
   recorded, and

 - anyone can verify that the recorded votes have been correctly
   tallied.

The MITRE ElectionGuard Verifier provides the means to validate
ElectionGuard election records in an easy to use package.  It is
written in the [Julia](https://julialang.org/) programming language.
Follow the instructions at the Julia web site to download and install
the system on your computer.

## User Instructions

Eventually, this software will be made available using the Julia
package management system.  For now, follow these instructions.

 1. Start Julia with the command

   	```sh
	$ julia --project=PROJ_DIR
	```

	where `PROJ_DIR` is the directory containing this project's
    `Project.toml` file.

 2. Load the software with

    ```julia
    julia> using ElectionGuardVerifier
    ```

 3. Load your election records with

    ```julia
    julia> er = load("ER_DIR");
    ```

    where `ER_DIR` is the directory containing the election records'
    `manifest.json` file.

 4. Check your election records with

    ```julia
    julia> check(er)
    ```

    The final line of output is `true` if your election records pass
    all tests, otherwise it is `false`.

 5. Exit Julia with `exit()` or type cntl-D.

## Debugging

For debugging, I place sample data at
`../../electionguard/data/0.95.0/sample`, start julia with `julia
--project=.`, and replace steps 2-5 with `include("src/Chk.jl")`.  By
default, it checks the small sample.  You can test the minimal sample
with `check(es[1])`, the full sample with `check(es[3])`, and the
hamilton-general sample with `check(es[4])`.

## Documentation

Build and view the documentation with:

``` sh
$ cd docs
$ julia --project make.jl
$ open build/index.html
```
