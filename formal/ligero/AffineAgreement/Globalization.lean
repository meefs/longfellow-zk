import AffineAgreement.Basic
import CodingTheory.AffineCounting
import CodingTheory.Proximity

/-!
# Affine-decoder globalization

This module isolates the field-avoidance argument shared by correlated
agreement and selected MCA.  Its input is an affine, code-valued decoder with
uniformly sparse errors; it is deliberately independent of how decoder
affineness was proved.
-/

namespace AffineAgreement

open CodingTheory

variable {F Row : Type*} [Field F] [Fintype F] [DecidableEq F]
variable [Fintype Row] [DecidableEq Row] [Nonempty Row]
variable {n e g d : ℕ}

omit [Fintype F] [DecidableEq F] [DecidableEq Row] [Nonempty Row] in
private theorem wordCombination_affine
    (rows : Row → Word F n) (x y : Row → F) (scalar : F) :
    wordCombination rows (x + scalar • y) =
      affineWord (wordCombination rows x) (wordCombination rows y) scalar := by
  rw [wordCombination_add_smul]
  rfl

/- Three local radius-`g` errors force a chosen codeword decoder to respect
affine lines.  Deleted coordinates reduce the usable code distance by `e`. -/
omit [Fintype F] [DecidableEq Row] [Nonempty Row] in
theorem decoded_affine_of_three_errors_on
    (C : LinearCode F n) (rows : Row → Word F n)
    (allowed : Finset (Fin n))
    (decoded : (Row → F) → Word F n)
    (hmin : HasMinimumDistanceAtLeast C d)
    (hdeleted : (Finset.univ \ allowed).card ≤ e)
    (hthree : 3 * g < d - e)
    (hdecodedCode : ∀ weights, decoded weights ∈ C)
    (hdecodedClose : ∀ weights,
      (supportOn allowed
        (wordCombination rows weights - decoded weights)).card ≤ g) :
    ∀ x y scalar,
      decoded (x + scalar • y) =
        affineWord (decoded x) (decoded y) scalar := by
  intro x y scalar
  let errors : (Row → F) → Word F n := fun weights ↦
    wordCombination rows weights - decoded weights
  let defect := decoded (x + scalar • y) -
    affineWord (decoded x) (decoded y) scalar
  have hdefectMem : defect ∈ C := by
    dsimp [defect]
    exact C.sub_mem (hdecodedCode _)
      (C.add_mem (hdecodedCode x) (C.smul_mem scalar (hdecodedCode y)))
  have hdefectError : defect =
      -errors (x + scalar • y) + errors x + scalar • errors y := by
    dsimp [defect, errors]
    rw [wordCombination_affine]
    funext i
    simp [affineWord]
    ring
  have hlocal : (supportOn allowed defect).card ≤ 3 * g := by
    rw [hdefectError]
    calc
      (supportOn allowed
          (-errors (x + scalar • y) + errors x + scalar • errors y)).card ≤
          (supportOn allowed (-errors (x + scalar • y) + errors x)).card +
            (supportOn allowed (scalar • errors y)).card :=
        supportOn_add_card_le allowed _ _
      _ ≤ ((supportOn allowed (-errors (x + scalar • y))).card +
            (supportOn allowed (errors x)).card) +
            (supportOn allowed (errors y)).card :=
        Nat.add_le_add (supportOn_add_card_le allowed _ _)
          (supportOn_smul_card_le allowed _ _)
      _ = ((supportOn allowed (errors (x + scalar • y))).card +
            (supportOn allowed (errors x)).card) +
            (supportOn allowed (errors y)).card := by simp
      _ ≤ 3 * g := by
        have h₁ := hdecodedClose (x + scalar • y)
        have h₂ := hdecodedClose x
        have h₃ := hdecodedClose y
        change (supportOn allowed (errors (x + scalar • y))).card ≤ g at h₁
        change (supportOn allowed (errors x)).card ≤ g at h₂
        change (supportOn allowed (errors y)).card ≤ g at h₃
        omega
  have hweight : weight defect < d := by
    have htotal := weight_le_supportOn_add_complement allowed defect
    have : weight defect ≤ 3 * g + e :=
      htotal.trans (Nat.add_le_add hlocal hdeleted)
    omega
  exact sub_eq_zero.mp
    (CodingTheory.eq_zero_of_weight_lt_distance hmin hdefectMem hweight)

/-- An affine, code-valued decoder whose errors have radius at most `g` on
`allowed` globalizes to row decodings with one common set of at most `g` bad
columns. -/
theorem affine_decoder_globalizes_on
    (C : LinearCode F n) (rows : Row → Word F n)
    (allowed : Finset (Fin n))
    (decoded : (Row → F) → Word F n)
    (hdecodedCode : ∀ weights, decoded weights ∈ C)
    (hdecodedClose : ∀ weights,
      (supportOn allowed
        (wordCombination rows weights - decoded weights)).card ≤ g)
    (hdecodedAffine : ∀ x y scalar,
      decoded (x + scalar • y) =
        affineWord (decoded x) (decoded y) scalar)
    (hfield : g + 1 < Fintype.card F) :
    ∃ decodedRows : Row → Word F n,
      (∀ row, decodedRows row ∈ C) ∧
      (allowed.filter fun j ↦
        ∃ row, rows row j ≠ decodedRows row j).card ≤ g := by
  classical
  let errors : (Row → F) → Word F n := fun weights ↦
    wordCombination rows weights - decoded weights
  have herrorsAffine (x y : Row → F) (scalar : F) :
      errors (x + scalar • y) = affineWord (errors x) (errors y) scalar := by
    dsimp [errors]
    rw [wordCombination_affine, hdecodedAffine, affineWord_sub]
  let decodedRows : Row → Word F n := fun row ↦ decoded (rowBasis row)
  let bad := allowed.filter fun j ↦ ∃ row, rows row j ≠ decodedRows row j
  have hbad : bad.card ≤ g := by
    by_contra hnot
    obtain ⟨selected, hselected, hselectedCard⟩ :=
      Finset.exists_subset_card_eq (s := bad)
        (show g + 1 ≤ bad.card by omega)
    let zeroAt (j : Fin n) : Finset (Row → F) :=
      Finset.univ.filter fun weights ↦ errors weights j = 0
    have hzeroCard (j : Fin n) (hj : j ∈ selected) :
        (zeroAt j).card ≤ Fintype.card F ^ (Fintype.card Row - 1) := by
      have hjbad : j ∈ bad := hselected hj
      obtain ⟨pivot, hpivot⟩ := (Finset.mem_filter.mp hjbad).2
      have hpivotError : errors (rowBasis pivot) j ≠ 0 := by
        simpa [errors, decodedRows, wordCombination_rowBasis]
          using sub_ne_zero.mpr hpivot
      apply card_filter_univ_le_pow_of_line_subsingleton
        (property := fun weights ↦ errors weights j = 0)
        (direction := rowBasis pivot)
      · intro hzero
        have := congrFun hzero pivot
        simp [rowBasis] at this
      · intro base first hfirst second hsecond
        have hfirst' : affineWord (errors base)
              (errors (rowBasis pivot)) first j = 0 := by
          simpa [herrorsAffine] using hfirst
        have hsecond' : affineWord (errors base)
              (errors (rowBasis pivot)) second j = 0 := by
          simpa [herrorsAffine] using hsecond
        apply sub_eq_zero.mp
        apply (mul_eq_zero.mp ?_).resolve_right hpivotError
        calc
          (first - second) * errors (rowBasis pivot) j =
              affineWord (errors base) (errors (rowBasis pivot)) first j -
                affineWord (errors base) (errors (rowBasis pivot)) second j := by
            simp [affineWord]
            ring
          _ = 0 := by rw [hfirst', hsecond', sub_self]
    let covered := selected.biUnion zeroAt
    have hcoveredCard : covered.card ≤
        (g + 1) * Fintype.card F ^ (Fintype.card Row - 1) :=
      (Finset.card_biUnion_le_card_mul selected zeroAt
        (Fintype.card F ^ (Fintype.card Row - 1))
        (fun j hj ↦ hzeroCard j hj)).trans_eq (by rw [hselectedCard])
    have hpowPos : 0 < Fintype.card F ^ (Fintype.card Row - 1) :=
      pow_pos Fintype.card_pos _
    have hunivCard : Fintype.card (Row → F) =
        Fintype.card F * Fintype.card F ^ (Fintype.card Row - 1) := by
      rw [Fintype.card_fun]
      nth_rw 1 [show Fintype.card Row = (Fintype.card Row - 1) + 1 by
        have := Fintype.card_pos (α := Row)
        omega]
      simp [pow_succ']
    have hcoveredLt : covered.card < Fintype.card (Row → F) := by
      rw [hunivCard]
      exact hcoveredCard.trans_lt
        (Nat.mul_lt_mul_of_pos_right hfield hpowPos)
    obtain ⟨weights, _hweightsUniv, hweights⟩ :=
      Finset.exists_mem_notMem_of_card_lt_card hcoveredLt
    have hselectedSupport : selected ⊆ supportOn allowed (errors weights) := by
      intro j hj
      have hjallowed := (Finset.mem_filter.mp (hselected hj)).1
      apply (mem_supportOn allowed (errors weights) j).mpr
      refine ⟨hjallowed, ?_⟩
      intro hzero
      apply hweights
      exact Finset.mem_biUnion.mpr
        ⟨j, hj, Finset.mem_filter.mpr ⟨Finset.mem_univ _, hzero⟩⟩
    have hlarge : g + 1 ≤ (supportOn allowed (errors weights)).card := by
      rw [← hselectedCard]
      exact Finset.card_le_card hselectedSupport
    have hclose := hdecodedClose weights
    change (supportOn allowed (errors weights)).card ≤ g at hclose
    exact (Nat.not_succ_le_self g) (hlarge.trans hclose)
  exact ⟨decodedRows, (fun row ↦ hdecodedCode (rowBasis row)), by
    simpa [bad] using hbad⟩

/-- Punctured three-error globalization, with the decoder choice and its
affineness proof assembled from the two reusable kernels above. -/
theorem interleavedWithinRadiusOn_of_all_combinations_close_three
    (C : LinearCode F n) (rows : Row → Word F n)
    (allowed : Finset (Fin n))
    (hmin : HasMinimumDistanceAtLeast C d)
    (hdeleted : (Finset.univ \ allowed).card ≤ e)
    (hthree : 3 * g < d - e) (hfield : g + 1 < Fintype.card F)
    (hall : ∀ weights : Row → F, ∃ decoded ∈ C,
      (supportOn allowed
        (wordCombination rows weights - decoded)).card ≤ g) :
    ∃ decodedRows : Row → Word F n,
      (∀ row, decodedRows row ∈ C) ∧
      (allowed.filter fun j ↦ ∃ row,
        rows row j ≠ decodedRows row j).card ≤ g := by
  classical
  let decoded : (Row → F) → Word F n := fun weights ↦
    Classical.choose (hall weights)
  have hdecodedCode (weights : Row → F) : decoded weights ∈ C :=
    (Classical.choose_spec (hall weights)).1
  have hdecodedClose (weights : Row → F) :
      (supportOn allowed
        (wordCombination rows weights - decoded weights)).card ≤ g :=
    (Classical.choose_spec (hall weights)).2
  have hdecodedAffine := decoded_affine_of_three_errors_on C rows allowed decoded
    hmin hdeleted hthree hdecodedCode hdecodedClose
  exact affine_decoder_globalizes_on C rows allowed decoded hdecodedCode
    hdecodedClose hdecodedAffine hfield

end AffineAgreement
