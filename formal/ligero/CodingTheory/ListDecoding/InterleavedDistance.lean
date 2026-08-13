import CodingTheory.Proximity

/-!
# Column distance of interleaved codewords

The Johnson-list argument treats rowwise codeword matrices as a code over a
larger alphabet.  Its first ingredient is that interleaving does not reduce
the column distance.  The actual Johnson cardinality theorem is not in this
module; see the soundness audit ledger.
-/

namespace CodingTheory.InterleavedJohnson

open CodingTheory

variable {F Row : Type*} [Field F] [DecidableEq F] [Fintype Row]
variable {n d : ℕ}

/-- Distinct interleaved codeword matrices differ in at least the base-code
distance many columns. -/
theorem matrixErrorCoordinates_card_ge_distance
    (C : LinearCode F n) (hmin : HasMinimumDistanceAtLeast C d)
    {first second : Row → Word F n}
    (hfirst : ∀ row, first row ∈ C) (hsecond : ∀ row, second row ∈ C)
    (hne : first ≠ second) :
    d ≤ (matrixErrorCoordinates first second).card := by
  obtain ⟨row, hrow⟩ : ∃ row, first row ≠ second row := by
    simpa [Function.ne_iff] using hne
  let difference := first row - second row
  have hdifferenceMem : difference ∈ C := C.sub_mem (hfirst row) (hsecond row)
  have hdifferenceNe : difference ≠ 0 := sub_ne_zero.mpr hrow
  have hdistance : d ≤ weight difference :=
    hmin.weight_ge_distance difference hdifferenceMem hdifferenceNe
  have hsubset : supportOn Finset.univ difference ⊆
      matrixErrorCoordinates first second := by
    intro j hj
    apply Finset.mem_filter.mpr
    refine ⟨Finset.mem_univ _, row, ?_⟩
    exact sub_ne_zero.mp ((mem_supportOn Finset.univ difference j).mp hj |>.2)
  exact hdistance.trans (Finset.card_le_card hsubset)

end CodingTheory.InterleavedJohnson
