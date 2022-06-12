# MITRE ElectionGuard Verifier

John D. Ramsdell and Moses D. Liskov

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
the system on your computer.  The user instructions are at 
[ElectionGuardVerifier.jl](https://mitre.github.io/ElectionGuardVerifier.jl).

## Developer Instructions

To develop the code locally, one must install the
[JSON](https://github.com/JuliaIO/JSON.jl) package.  From the Julia
REPL, type `]` to enter the Pkg REPL mode and run

```
pkg> add JSON.jl
```

Type the delete key or cntl-C to exit the Pkg REPL mode.

### Documentation

View developer documentation
[here](https://mitre.github.io/ElectionGuardVerifier.jl/development.html).

### Modifying Code

To develop code, a useful pattern is to create the `er` directory in
the directory containing this `README`, and place sample data within
it.

 1. Start Julia with the command

   	```sh
	$ julia --project=.
	```
	
    Unix OS users should look at the `ju` script.

 2. Load the software with

    ```julia
    julia> using ElectionGuardVerifier
    ```

 3. Load your election records with

    ```julia
    julia> er = load("er");
    ```

 4. Check your election records with

    ```julia
    julia> check(er)
    ```

    The final line of output is `true` if your election records pass
    all tests, otherwise it is `false`.

 5. Exit Julia with `exit()` or type cntl-D.

### Debugging

For debugging 1.0.0-preview-1 data, I place sample data at
`../electionguard/data/1.0.0-preview-1/sample`, start julia with
`julia --project=.` (see the `ju` script), replace steps 2-3 with
`include("src/Run.jl")`, and then load the data with `er=load(path);`.

For Windows, be sure to replace forward slash with backslash in path
names.

### Visual Studio Code

VS Code has a good extension for Julia.  When the extension is
installed, the following ensures that VS Code finds the correct Julia
project.

```sh
$ code .
```
