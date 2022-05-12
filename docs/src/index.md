# MITRE ElectionGuard Verifier

John D. Ramsdell and Moses D. Liskov

[ElectionGuard](https://www.electionguard.vote/) is a software system
designed to make voting more secure, transparent and accessible.
ElectionGuard uses cryptography to ensure that

 - voters can verify that their own selections have been correctly
   recorded, and

 - anyone can verify that the recorded votes have been correctly
   tallied.

Version 0.8.0 of the MITRE ElectionGuard Verifier provides the means to
validate specification [version 1.0
ElectionGuard](https://www.electionguard.vote/spec/) election records
that use version [0.95 data
formats](https://github.com/microsoft/electionguard/tree/main/data/0.95.0)
in an easy to use package.

## Design Goal

Our goal is to write easily understood correct code.
We follow Donald Knuth advice's on writing software:

>  Instead of imagining that our main task is to instruct a
>  *computer* what to do, let us concentrate rather on
>  explaining to *human beings* what we want a computer to do.
