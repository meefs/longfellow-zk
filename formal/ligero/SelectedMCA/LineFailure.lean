import SelectedMCA.DirectLineExtraction

/-!
# The per-line interface of selected agreement

Ligero's selected-MCA density argument uses exactly one fact about a decoder
line: *how many selected parameters can fail directional `g`-liftability*.  The
marked-triples clique condition is one way to bound that count; the Johnson
regime is another; unique decoding is a third.  `LineFailureBound` names the
fact itself, so a soundness theorem can be stated once and paid for by whichever
proximity theorem is available at the parameters in hand.

`lineFailureBound_of_directClique` is the clique route, and is the only reason
the rest of the stack ever mentioned `DirectCliqueCondition`.
-/

namespace SelectedMCA

open CodingTheory AffineAgreement

variable {F : Type*} [Field F] [DecidableEq F]

/-- **The per-line selected-MCA bound.**  On every decoder line for `(u, v)` at
selection radius `e`, at most `bound` selected parameters fail directional
`g`-liftability.

Quantifying over `m`, `u` and `v` is what makes this usable downstream: the
density argument applies it to one line per direction, with the line determined
by the prover's response rather than by the certificate. -/
def LineFailureBound {n : ℕ} (C : LinearCode F n) (e g bound : ℕ) : Prop :=
  ∀ {m : ℕ} {u v : Word F n} (D : DecoderData (e := e) (m := m) C u v),
    (directionallyNonliftableParameters D g).card ≤ bound

/-- The marked-triples clique route supplies the per-line bound. -/
theorem lineFailureBound_of_directClique {n e g d threshold : ℕ}
    {C : LinearCode F n} (hmin : HasMinimumDistanceAtLeast C d)
    (hcondition : DirectCliqueCondition n e g d threshold) :
    LineFailureBound C e g (directLineFailureBound threshold) :=
  fun D => directionallyNonliftableParameters_card_le_direct D hmin hcondition

/-- **The small-radius route supplies the per-line bound.**

Below one third of the minimum distance all selected decodings lie on a single
affine codeword line, and distinct nonliftable parameters have disjoint
directional-cancellation sets inside that line's active support -- so the
incidence bound alone caps the count, with no clique threshold, no Johnson
condition and no Reed-Solomon presentation.

This is the cheapest route in hypotheses and the most expensive in radius:
`3e < d`, against the clique route's `(n-e)³ > n²(n-d)`.  The `1 +` is the
pigeonhole slack -- one parameter may fail for free -- and it vanishes from the
bound once `g ≥ e`.

Note this is *not* the unique-decoding radius.  `2e < d` makes each affine point's
decoding unique, but uniqueness says nothing about directional liftability: the
count still comes from the same disjointness argument, which needs three points to
pin the line.  A bound of `1` at `2e < d` is not a corollary of anything here. -/
theorem lineFailureBound_of_threeRadius {n e g d : ℕ} {C : LinearCode F n}
    (hmin : HasMinimumDistanceAtLeast C d) (hthree : 3 * e < d) :
    LineFailureBound C e g (1 + e / (g + 1)) :=
  fun D ↦ directionallyNonliftableParameters_card_le_of_three_radius D hmin hthree

/-- A per-line bound weakens freely, which is what lets a certificate record a
round number in place of the exact threshold a theorem produces. -/
theorem LineFailureBound.mono {n e g bound bound' : ℕ} {C : LinearCode F n}
    (h : LineFailureBound C e g bound) (hle : bound ≤ bound') :
    LineFailureBound C e g bound' :=
  fun D => (h D).trans hle

end SelectedMCA
