# Development

```@meta
CurrentModule = ElectionGuardVerifier
```

This section introduces the source code that makes up the verifier.

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

## Check

```@meta
CurrentModule = ElectionGuardVerifier
```

The `check` function implements what is described in the version 1.0
[ElectionGuard Specification](https://www.electionguard.vote/spec/).

```@docs
check(er::Election_record)
```

## Errata

The places at which the code is at odds with what is in the spec can
be found by searching for the follow comment in the Julia source code:

```
#! Spec conflict
```
