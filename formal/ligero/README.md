# Ligero V1 soundness and Longfellow V7 parameters

This directory proves soundness of the formal **Ligero V1 verifier**, including
its Fiat–Shamir transformation and Merkle openings in a finite random-oracle
model. It also certifies the actual parameters of Longfellow's registered V7
signature and hash circuit components, for one through four attributes.

The resulting theorem bounds the probability that Merkle verification and the
formal Ligero verifier both accept a false constraint system. The bound includes
both Fiat–Shamir query orders, a proved Merkle binding error, and exact numerical
certificates. The implementation correspondence and composition needed to extend
this result to Longfellow's complete mdoc verifier remain separate proof obligations.

## Exact V7 result

The top-level theorem is

```lean
Ligero.Examples.Grid.Rigid.Longfellow.RegisteredCircuit.v7_soundness
```

in [V7.lean](examples/Ligero/Longfellow/V7.lean). It applies to every component
`circuit ∈ registeredCircuits`, where the checked catalog in
[Parameters.lean](examples/Ligero/Longfellow/Parameters.lean) contains the eight
V7 components: signature and hash, each for one through four attributes.

For a false formal constraint system, the theorem proves

\[
\Pr[\mathsf{FalseAccept}_c]
\;\le\;
\frac{\binom{p}{2}+M(2p+1)}{2^{256}}
\; +\; (N+2)\,2^{-b_c},
\qquad
b_c =
\begin{cases}
122 & \text{signature component},\\
121 & \text{hash component}.
\end{cases}
\]

Here `N` is the depth/query bound of the typed Fiat–Shamir adversary tree,
`M = merkleT > 0` is the Merkle oracle tape length, and
`p = prefixFuel ≤ M` bounds the shared root-exposure phase. The complete Merkle
run has `runFuel ≤ M`, as required by `PrefixBindingFamily`. The extra two
Fiat–Shamir tape slots are part of the compiler's defining-answer/fallback
accounting. The binomial term is represented in Lean by natural-number
`p * (p - 1) / 2`.

The probability is **exact uniform finite counting**, rather than an asymptotic
or floating-point estimate. The sample space is the product of two independent
tapes:

```lean
(Fin M → D) × (Fin (N + 2) → Bcs.TypedFiatShamir.Answer Alpha Subset)
```

The digest type satisfies `Fintype.card D = 2 ^ 256`; `Alpha` is the formal V1
challenge type and `Subset` is the type of query sets of 132 coordinates.
`Pr[E]` is the cardinality of the event divided by the cardinality of this
sample space. Typed Fiat–Shamir answers are uniform products of challenges and
query sets, with lazy random-oracle execution reusing answers to repeated queries.

For each pair of tapes, `FalseAccept` is the conjunction of:

1. The Merkle claim's coordinate set equals the defining Fiat–Shamir query set.
2. `Merkle.MH.Accepts` accepts the claimed columns and their opening proofs under
   the root exposed by the commitment phase.
3. `SchemeVerifier.policy ... C Ligero.V1.scheme` accepts the adversary's response
   to the defining challenge, using those opened columns.

The theorem assumes `¬statement.Language`: there is no witness satisfying the
formal linear and quadratic constraints. It bounds the full conjunction above,
including the possibility of inconsistent Merkle openings. Both orders of the
challenge and subset queries are accounted for by the compiler.

**122 and 121 are coefficients before the query factor and Merkle term.**
They are not a claim of 122- or 121-bit security for a complete deployed proof.
The Fiat–Shamir term alone loses `log₂(N + 2)` bits relative to its coefficient;
the total bound also includes the displayed Merkle error. No concrete adversary
query budget is fixed by these certificates.

## Parameters certified for V7

Both components use 132 openings and inverse rate parameter 7. The signature
field has the exact P-256 base-field order

\[
q_{\rm sig}=2^{256}-2^{224}+2^{192}+2^{96}-1,
\]

and the hash field has order `q_hash = 2^128`.

| Component | Attributes | Encoded block `E` | Block `k` | Columns `n` | Witness width `w` | Base distance `d` | Coefficient |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Signature | 1–4 | 4096 | 455 | 3187 | 323 | 2733 | `2^-122` |
| Hash | 1 | 4151 | 461 | 3230 | 329 | 2770 | `2^-121` |
| Hash | 2 | 4265 | 474 | 3318 | 342 | 2845 | `2^-121` |
| Hash | 3 | 4307 | 478 | 3352 | 346 | 2875 | `2^-121` |
| Hash | 4 | 4415 | 490 | 3436 | 358 | 2947 | `2^-121` |

The layout uses `k = floor((E + 1) / 9)`, `n = E - (2k - 1)`, `w = k - 132`,
and `d = n - k + 1`. The code rate is `k / n`, at most `1/7` for these layouts;
`k / E` is a different ratio.

[Certificates.lean](examples/Ligero/Longfellow/Certificates.lean) certifies all
five distinct parameter sets. Its exact integer inequalities are connected by
`Result.bound_of_integer_upper_bound` to the rational compiler coefficient
`Result.workNormalizedBound`. `native_decide` checks the parameter conditions
and inequalities; it does not leave them as assumptions.

The registered-circuit theorem also discharges the catalog's row geometry,
opening count, field order, and mask width. Its remaining code hypothesis is
`HasMinimumDistanceAtLeast C.baseCode d`, for a formal `MultiplicativeCode` over a
finite field of the specified order. Reed–Solomon distance results are available
in the formal code library; correspondence with the C++ evaluation domains and
field implementations is a separate obligation.

The catalog records the circuit and bundle identifiers from Longfellow commit
`d5e6be77336933d50bf7f25a954f8ec273eb51ce`.
[inspect_parameters.py](examples/Ligero/Longfellow/inspect_parameters.py)
extracts the layouts and verifies their canonical identifiers against the
registered artifacts. The full metadata and selected analysis parameters are in
[certified-results.json](examples/Ligero/Longfellow/certified-results.json).
Artifact and layout checks establish the provenance of the numerical parameters;
they do not establish semantic equivalence of the circuit or verifier code.

## What the proof covers and what remains

Within its stated model, this is a connected soundness theorem from the
adversary's finite oracle execution to acceptance by the formal V1 verifier.
The proof constructs the required V1 soundness classifiers, accounts for the
response-agreement and arithmetic failure events, and invokes the Merkle
extraction/binding reduction. No assumed numerical soundness bound or external
binding-error estimate replaces those proofs.

The following conditions describe its precise scope:

- **Commitment and adversary model.** The theorem covers arbitrary bounded typed
  Fiat–Shamir query trees under a fixed `alphaKey`. Merkle opening claims and later
  runs can depend on the Fiat–Shamir tape, but every run in `PrefixBindingFamily`
  shares one root-exposure phase and one root function, independent of that tape.
  Merkle commitments may depend adaptively on the Merkle oracle. The result does
  not yet instantiate a general adversary that grinds commitments using the
  Fiat–Shamir oracle before choosing the exposed root or challenge key.
- **Merkle encoding and execution.** Callers supply a `Codec`, valid
  `RoleDecoders`, and a `PrefixBindingFamily`. These require the relevant decoding
  laws, that the commitment phase's lazy slots prefix the complete run, and that
  the opening verification queries occur in that run. The abstract binding
  reduction is proved; these objects and laws have not been instantiated for
  Longfellow's concrete serialization, parser, and Merkle execution.
- **Random oracles and challenge generation.** The two tapes are independent and
  exactly uniform. The `sha256` theorem suffix specializes the ideal digest
  cardinality to 256 bits. It does not prove that concrete SHA-256 is a random
  oracle or reduce Longfellow's SHA-256 transcript, AES-based expansion, and
  field/subset sampling to the typed uniform-tape experiment. That correspondence
  must also account for any sampling bias and dependence between components.
- **Formal verifier and code.** The accepted response is checked by the Lean V1
  policy. Equivalence to the C++ verifier, its parsing, field arithmetic,
  transcript messages, and Reed–Solomon domains is not proved here. The formal
  response code has dimension `2k`, whereas the implementation's response
  polynomial has dimension `2k - 1`. The larger formal space is conservative
  for this degree restriction; a formal implementation embedding is still needed.
- **Protocol composition.** This result concerns a false Ligero constraint system.
  A false mdoc assertion must first be reduced to such a system. Connecting
  Sumcheck and circuit reduction to this theorem, and composing the signature
  and hash components with their shared transcript and MAC checks, remains to
  be proved. The eight catalog entries are eight individual component instances;
  there is no proved whole-mdoc bound obtained by combining them here.
- **Kind of guarantee.** The conclusion is false-statement acceptance soundness.
  The proof uses Merkle message extraction internally. It does not state a
  general Fiat–Shamir proof-of-knowledge theorem with an efficient witness
  extractor for arbitrary adaptive adversaries.

These obligations delimit how the theorem can be applied to the deployed
system. They do not weaken the displayed finite-ROM bound for the formal
experiment satisfying its hypotheses.

## Proof entry points and checking

- [V7.lean](examples/Ligero/Longfellow/V7.lean):
  `RegisteredCircuit.v7_soundness`, with the explicit V7 coefficients.
- [Parameters.lean](examples/Ligero/Longfellow/Parameters.lean): checked catalog,
  `registered_matches`, and `RegisteredCircuit.end_to_end_soundness_sha256`.
- [Soundness.lean](examples/Ligero/Longfellow/Soundness.lean):
  `CertifiedResult.end_to_end_soundness` and its 256-bit digest specialization.
- [FixedOpenings.lean](examples/Ligero/Longfellow/FixedOpenings.lean):
  `Result.v1_prefixBinding_ratio_le_of_bound`, which connects the V1 classifier
  and compiler to fixed opening counts without requiring opening-count minimality.
- [RigidCompiler.lean](LigeroFamily/Soundness/RigidCompiler.lean):
  `canonical_scheme_prefixBinding_profiled_ratio_le`, the underlying combined
  verifier, Fiat–Shamir, and Merkle theorem.

Run from `formal`:

```sh
lake build
```

The default targets include the V7 theorem and its dependencies. To check that
entry point alone, use `lake build examples.Ligero.Longfellow.V7`.

The proofs contain no `sorry` or handwritten soundness axioms. As with other
Lean developments, checking relies on Lean and the imported library; the
numerical `native_decide` certificates additionally rely on Lean's native
compiler/evaluation mechanism. Canonical circuit extraction is an external
validation step, not a Lean proof of the artifact parser.
