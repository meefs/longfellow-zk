import LigeroFamily.Soundness.ChallengeCounting

/-!
# Counting global arithmetic labels

For a nonzero residual vector, the dot product of a uniform challenge vector
is uniform.  This finite union form charges an arbitrary set of labels and is
the counting bridge used by unchecked-mask profiles.
-/

namespace Ligero.V1

open LigeroFamily

variable {F Index : Type*} [Field F] [Fintype F] [DecidableEq F]
variable [Fintype Index] [DecidableEq Index]

noncomputable def finiteDotLabelPreimage
    (coefficients : Index → F) (labels : Finset F) : Finset (Index → F) := by
  classical
  exact Finset.univ.filter fun weights ↦ finiteDot weights coefficients ∈ labels

theorem finiteDotLabelPreimage_density
    (coefficients : Index → F) (labels : Finset F) (hnonzero : coefficients ≠ 0) :
    Fintype.card F * (finiteDotLabelPreimage coefficients labels).card ≤
      labels.card * Fintype.card (Index → F) := by
  classical
  let solutions := fun label : F ↦ affineEquationSolutions coefficients label
  have hpreimage : finiteDotLabelPreimage coefficients labels =
      labels.biUnion solutions := by
    ext weights
    simp [finiteDotLabelPreimage, solutions, affineEquationSolutions]
  rw [hpreimage]
  calc
    Fintype.card F * (labels.biUnion solutions).card ≤
        Fintype.card F * ∑ label ∈ labels, (solutions label).card :=
      Nat.mul_le_mul_left _ Finset.card_biUnion_le
    _ = ∑ label ∈ labels, Fintype.card F * (solutions label).card := by
      simp_rw [Finset.mul_sum]
    _ ≤ ∑ _label ∈ labels, Fintype.card (Index → F) :=
      Finset.sum_le_sum fun label _ ↦
        affineEquationSolutions_density coefficients label hnonzero
    _ = labels.card * Fintype.card (Index → F) := by simp

end Ligero.V1
