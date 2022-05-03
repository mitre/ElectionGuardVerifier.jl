# Results

The `check` function implements what is described in the version 1.0
[ElectionGuard Specification](https://www.electionguard.vote/spec/).
To understand the output of the MITRE ElectionGuard Verifier, please
turn to Section 6.2 titled "Verifier Steps".  The numbers in the
output correspond to the steps listed in this section.  For example,
the line of output that says:

```
1. Standard parameters were found.
```

is the result of performing the test described in Step 1.

The verifier implements all verification steps with the follow
exceptions:

 * Step 6 on the validation of ballot chaining is not implemented.
   The manifest, also known as the ballot coding file, does not say
   how to hash individual ballots.

 * Step 5 includes an addition check that ensures that there are no
   duplicate submitted ballots.

 * The spec incorrectly specifies hashes computed in six steps.

   * In Step 2A, ``c_{i,j} = H(Q, K_{i,j},h_{i,j})\mod q`` should be
     ``c_{i,j}=H(K_{i,j},h_{i,j})\mod q``.

   * In Step 3B, ``\bar Q = H(Q, K)`` should be ``\bar Q = H(K, C)``,
     where ``C`` is the commitment hash.

   * In Step 4B, ``c = H(\bar Q,(\alpha,\beta),(a_0,b_0),(a_1,b_1))``
     should be ``c = H(\bar Q,\alpha,\beta,a_0,b_0, a_1,b_1)``.

   * In Step 5E, ``C = H(\bar Q,(A,B),(a,b))``
     should be ``C = H(\bar Q,A,B,a,b)``.

   * In Step 8C, ``c_{i} = H(\bar Q,(A,B),(a_{i},b_{i}), M_{i})``
     should be ``c_{i} = H(\bar Q,A,B,a_{i},b_{i}, M_{i})``.

   * In Step 9C, ``c_{i,\ell} = H(\bar Q,(A,B),(a_{i,\ell},b_{i,\ell}), M_{i,\ell})``
     should be ``c_{i,\ell} = H(\bar Q,A,B,a_{i,\ell},b_{i,\ell}, M_{i,\ell})``.
