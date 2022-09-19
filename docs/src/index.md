# MITRE ElectionGuard Verifier

John D. Ramsdell and Moses D. Liskov

[ElectionGuard](https://www.electionguard.vote/) is a software system
designed to make voting more secure, transparent and accessible.
ElectionGuard uses cryptography to ensure that

 - voters can verify that their own selections have been correctly
   recorded, and

 - anyone can verify that the recorded votes have been correctly
   tallied.

Version 0.9.5 of the MITRE ElectionGuard Verifier provides the means
to validate specification [version 1.1
ElectionGuard](https://www.electionguard.vote/spec/) election records
that use version [1.0 data
formats](https://github.com/microsoft/electionguard/releases/tag/v1.0)
in an easy to use package.  Version 1.1 of the ElectionGuard spec is
currently not available to the public, which impedes the evaluation of
the correctness of this software.  This page will be immediately
updated when the spec becomes public.

## Design Goals

Our primary goal is to write easily understood correct code.
We follow Donald Knuth advice's on writing software:

>  Instead of imagining that our main task is to instruct a
>  *computer* what to do, let us concentrate rather on
>  explaining to *human beings* what we want a computer to do.

We have two secondary goals.

 - When the verifier detects a problem with a part of an election
   record, it provides a clear link to the equations in the spec that
   where violated by the election record, thereby easing the task of
   diagosing what went wrong.

 - The verifier makes effective use of parallel processing without
   contradicting our pledge to write easily understood corret code.
