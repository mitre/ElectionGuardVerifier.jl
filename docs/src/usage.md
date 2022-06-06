# Usage

To run the verifier, change your directory to the location of the
election records.  It's the directory that contains a `manifest.json`
file.

 1. Start the Julia interpreter with

    ```sh
    $ julia
    ```

 2. Load the verifier with

    ```julia
    julia> using ElectionGuardVerifier
    ```

 3. Load the election records with

    ```julia
    julia> er = load(".");
    ```

 4. Check the election records with

    ```julia
    julia> check(er)
    ```

    The final line of output is `true` if the election records pass
    all tests, otherwise it is `false`.

 5. Exit Julia with `exit()` or type cntl-D.

## Performance

When there are a large number of ballots to verify, the performance of
the verifier can be improved by starting Julia with many threads, such
as with

```sh
$ julia --threads=auto
```
