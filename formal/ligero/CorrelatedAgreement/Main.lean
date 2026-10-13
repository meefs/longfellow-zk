import CorrelatedAgreement.LineConsolidation

/-! Implementation of the arbitrary-code correlated-agreement theorem. -/

namespace CorrelatedAgreement

open AffineAgreement

variable {F : Type*} [Field F] [DecidableEq F]

/-- Triple counting, affine codeword-line extraction, and consolidation yield correlated
agreement for an arbitrary linear code. -/
theorem Internal.correlated_agreement_impl {n e h d b : ℕ}
    (C : LinearCode F n) (u v : Word F n)
    (hmin : HasMinimumDistanceAtLeast C d)
    (numeric : NumericalHypotheses n e h d b)
    (data : DecoderData (e := e) (m := selectedDecoderCount e h d) C u v) :
    Correlated (e := h) C u v := by
  have hm : 3 ≤ selectedDecoderCount e h d := by
      have heL : e < nontrivialSupportLowerBound e h d := by
        apply lt_of_lt_of_le (show e < h + 1 by
          exact Nat.lt_succ_of_le numeric.testRadius_le_commonRadius)
        exact Nat.le_max_left _ _
      have hpositive : 1 ≤ nontrivialLineOccupancyBound e h d := by
        apply (Nat.le_div_iff_mul_le (Nat.sub_pos_of_lt heL)).2
        simp only [one_mul]
        exact Nat.sub_le _ _
      have htwo : 2 ≤ agreementBound e h d :=
        (Nat.mul_le_mul_left 2 hpositive).trans (Nat.le_max_right _ _)
      dsimp only [selectedDecoderCount]
      omega
  have hed : e < d := Internal.testRadius_lt_distance_of_extraction_bound
    hm numeric.extraction_bound
  have hen : e ≤ n :=
    (Nat.le_of_lt hed).trans hmin.distance_le_length
  obtain ⟨padded⟩ := Internal.paddedErrorFamily_nonempty data hen
  obtain ⟨line, hline⟩ := Internal.exists_affineCodewordLine_with_many_followers
    data padded hmin data.card_parameters hm hed numeric.extraction_bound
  exact Internal.correlated_of_large_affineCodewordLine data hmin
    data.card_parameters numeric.testRadius_le_commonRadius
      numeric.line_card_lower line hline rfl numeric.consolidation_bound

end CorrelatedAgreement
