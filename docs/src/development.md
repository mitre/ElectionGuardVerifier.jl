# Development

```@meta
CurrentModule = ElectionGuardVerifier
```

This section introduces the source code that makes up the verifier.
According to C.A.R Hoare:

>  There are two ways of constructing a software design.
>  One way is to make it so simple that there are obviously
>  no deficiencies.  And the other way is to make it so
>  complicated that there are no obvious deficiencies.

Our goal is to always write code that is obviously correct.

## Datatypes

The way to understand the software is to start by viewing the
Datatypes module.

```@docs
Datatypes
```

## Loader

The loader describes the expected directory structure of an election
record.

```@docs
Loader
load(path::AbstractString)
```

## Utililies

```@meta
CurrentModule = ElectionGuardVerifier.Utils
```

```@docs
Utils
mulpowmod(a::BigInt, x::BigInt, b::BigInt, p::BigInt)
same(c1::Constants, c2::Constants)
same(c1::Ciphertext, c2::Ciphertext)
within(x::BigInt, p::BigInt)
within_mod
one_ct
prod_ct(x1::Ciphertext, x2::Ciphertext, p::BigInt)
```

## Answers

```@meta
CurrentModule = ElectionGuardVerifier.Answers
```

```@docs
Answers
answer(step::Int64, items::String, section::String,
       comment::String, count::Int64, failed::Int64)
verification_record(er::Election_record,
                    anss::Vector{Answer})
bits2items(bits::Int64)
```

## Check

```@meta
CurrentModule = ElectionGuardVerifier
```

The `check` function implements what is described in the version 1.0
[ElectionGuard Specification](https://www.electionguard.vote/spec/).

```@docs
check(er::Election_record)
```
