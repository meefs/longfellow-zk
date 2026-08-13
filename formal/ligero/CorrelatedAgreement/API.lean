import CorrelatedAgreement.Main

/-!
# Public arbitrary-code agreement API

This module contains only the intrinsic arbitrary-code correlated-agreement
surface. Selected-MCA extraction and Johnson list decoding are independent
packages.
-/

namespace CorrelatedAgreement

open AffineAgreement

variable {F : Type*} [Field F] [DecidableEq F]

/-- Proof-oriented form of arbitrary-code correlated agreement for an exact
selected decoder family. -/
theorem correlated_agreement_of_decoderData {n e h d b : ℕ}
    (C : LinearCode F n) (u v : Word F n)
    (hmin : HasMinimumDistanceAtLeast C d)
    (numeric : NumericalHypotheses n e h d b)
    (data : DecoderData (e := e) (m := selectedDecoderCount e h d) C u v) :
    Correlated (e := h) C u v :=
  Internal.correlated_agreement_impl C u v hmin numeric data

/-- **Arbitrary-code correlated agreement.**

If sufficiently many distinct points of the affine received-word line
`u + t • v` are radius-`e` close to an arbitrary linear code, then two
codewords explain `u` and `v` outside one common set of at most `h`
coordinates. -/
theorem correlated_agreement {n e h d b : ℕ}
    (C : LinearCode F n) (u v : Word F n)
    (hmin : HasMinimumDistanceAtLeast C d)
    (numeric : NumericalHypotheses n e h d b)
    (parameters : Finset F)
    (hmany : selectedDecoderCount e h d ≤ parameters.card)
    (hclose : ∀ scalar ∈ parameters,
      ∃ decoded ∈ C, weight (affineWord u v scalar - decoded) ≤ e) :
    Correlated (e := h) C u v := by
  classical
  obtain ⟨selected, hselected, hselectedCard⟩ :=
    Finset.exists_subset_card_eq (s := parameters) hmany
  let decoder : selected → Word F n := fun scalar ↦
    Classical.choose (hclose scalar.1 (hselected scalar.2))
  let data : DecoderData
      (e := e) (m := selectedDecoderCount e h d) C u v := {
    parameters := selected
    decoder := decoder
    card_parameters := hselectedCard
    decoder_mem := fun scalar ↦
      (Classical.choose_spec (hclose scalar.1 (hselected scalar.2))).1
    decoder_near := fun scalar ↦
      (Classical.choose_spec (hclose scalar.1 (hselected scalar.2))).2 }
  exact correlated_agreement_of_decoderData C u v hmin numeric data

end CorrelatedAgreement
