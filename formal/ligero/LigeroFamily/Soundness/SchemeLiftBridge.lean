import LigeroFamily.Soundness.SchemeFixedLiftList
import SelectedMCA.Punctured

/-!
# Punctured agreement witnesses for every mask scheme

This is the extraction boundary used by both versions.  A witness supplies
base-code rows whose common matrix errors, after deleting the selected
response disagreements, occupy at most `g` further columns.  The theorem
below turns it into a member of the fixed radius-`e+g` Johnson list.
-/

namespace LigeroFamily

open CodingTheory
open MultiplicativeCode

variable {F CheckedMask DirectMask : Type*}
variable [Field F] [Fintype F] [DecidableEq F]
variable [Fintype CheckedMask]
variable {r w n nw nq e g d : ℕ}

/-- A punctured affine-agreement decoding of the committed matrix. -/
structure SchemeGLiftWitness
    (C : MultiplicativeCode F r w n)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (weights : SchemeTestedRow CheckedMask nw nq 1 → F)
    (response : EvaluationRow F r w n) (g : ℕ) where
  offset : EvaluationRow F r w n
  row : SchemeTestedRow CheckedMask nw nq 1 → EvaluationRow F r w n
  offset_mem : offset ∈ C.base
  row_mem : ∀ index, row index ∈ C.base
  extra : Finset (Fin n)
  extra_card : extra.card ≤ g
  matrixErrors_subset :
    matrixErrorCoordinates (schemeLiftCommittedRows oracle)
        (schemeLiftCandidateRows offset row) ⊆
      schemeProximityDisagreement oracle weights response ∪ extra

namespace SchemeGLiftWitness

variable {C : MultiplicativeCode F r w n}
variable {oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1}
variable {weights : SchemeTestedRow CheckedMask nw nq 1 → F}
variable {response : EvaluationRow F r w n}

/-- Globalize directional decodings on the actual agreement coordinates of
one selected response, then choose an affine offset so that the decoded
matrix aggregates exactly to that response.  This is the mask-scheme-generic
form of the punctured selected-MCA extraction. -/
theorem nonempty_of_all_directional_combinations
    [Nonempty (SchemeTestedRow CheckedMask nw nq 1)]
    (hresponse : response ∈ C.base)
    (hsmall : (schemeProximityDisagreement oracle weights response).card ≤ e)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (hthree : 3 * g < d - e) (hfield : g + 1 < Fintype.card F)
    (hall : ∀ direction : SchemeTestedRow CheckedMask nw nq 1 → F,
      ∃ decoded ∈ C.baseCode,
        (supportOn (schemeProximityAgreement oracle weights response)
          (wordCombination oracle.testedRow direction - decoded)).card ≤ g) :
    Nonempty (SchemeGLiftWitness C oracle weights response g) := by
  classical
  let allowed := schemeProximityAgreement oracle weights response
  let disagreement := schemeProximityDisagreement oracle weights response
  have hdeleted : (Finset.univ \ allowed).card ≤ e := by
    have hcomplement : (Finset.univ \ allowed).card = disagreement.card := by
      apply congrArg Finset.card
      ext j
      simp [allowed, disagreement, schemeProximityAgreement,
        schemeProximityDisagreement]
    rw [hcomplement]
    exact hsmall
  obtain ⟨decodedWords, hdecodedWords, hextra⟩ :=
    SelectedMCA.interleavedWithinRadiusOn_of_all_combinations_close_three
      C.baseCode oracle.testedRow allowed hmin hdeleted hthree hfield (by
        simpa [allowed] using hall)
  choose decodedRows hdecodedRows hdecodedCodeword using fun index ↦
    C.exists_base_row_of_mem_baseCode (hdecodedWords index)
  let offset : EvaluationRow F r w n :=
    response - ∑ index, weights index • decodedRows index
  have hoffsetMem : offset ∈ C.base :=
    C.base.sub_mem hresponse
      (Submodule.sum_mem _ fun index _ ↦
        C.base.smul_mem (weights index) (hdecodedRows index))
  let extra := allowed.filter fun j ↦
    ∃ index, oracle.testedRow index j ≠ decodedWords index j
  have hextraCard : extra.card ≤ g := by
    simpa [extra] using hextra
  refine ⟨{
    offset := offset
    row := decodedRows
    offset_mem := hoffsetMem
    row_mem := hdecodedRows
    extra := extra
    extra_card := hextraCard
    matrixErrors_subset := ?_ }⟩
  intro j hj
  by_cases hjDisagreement : j ∈ disagreement
  · exact Finset.mem_union_left _ (by
      simpa [disagreement] using hjDisagreement)
  · apply Finset.mem_union_right
    by_contra hjExtra
    have hagree : response (codePosition j) =
        schemeProximityObserved oracle weights j := by
      have : ¬response (codePosition j) ≠
          schemeProximityObserved oracle weights j := by
        simpa [disagreement, schemeProximityDisagreement] using hjDisagreement
      exact not_ne_iff.mp this
    have hjAllowed : j ∈ allowed := by
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, hagree⟩
    have hrow (index : SchemeTestedRow CheckedMask nw nq 1) :
        oracle.testedRow index j = decodedRows index (codePosition j) := by
      have hnotMismatch : ¬oracle.testedRow index j ≠ decodedWords index j := by
        intro hmismatch
        apply hjExtra
        exact Finset.mem_filter.mpr ⟨hjAllowed, index, hmismatch⟩
      calc
        oracle.testedRow index j = decodedWords index j :=
          not_ne_iff.mp hnotMismatch
        _ = decodedRows index (codePosition j) := by
          simpa [codeword] using congrFun (hdecodedCodeword index).symm j
    have hoffset : oracle.proximityBlind 0 j = offset (codePosition j) := by
      have hsum : wordCombination oracle.testedRow weights j =
          (∑ index, weights index • decodedRows index) (codePosition j) := by
        simp only [wordCombination_apply, Finset.sum_apply, Pi.smul_apply,
          smul_eq_mul]
        apply Finset.sum_congr rfl
        intro index _
        rw [hrow index]
      rw [schemeProximityObserved] at hagree
      dsimp [offset]
      rw [← hsum]
      apply (eq_sub_iff_add_eq).2
      rw [add_comm]
      simpa [wordCombination_apply] using hagree.symm
    obtain ⟨matrixRow, hmismatch⟩ := (Finset.mem_filter.mp hj).2
    cases matrixRow with
    | none =>
        exact hmismatch (by
          simpa [schemeLiftCommittedRows, schemeLiftCandidateRows, codeword]
            using hoffset)
    | some index =>
        exact hmismatch (by
          simpa [schemeLiftCommittedRows, schemeLiftCandidateRows, codeword]
            using hrow index)

omit [Fintype F] in
/-- A punctured `g`-lift is a fixed-list candidate of radius `e+g`, and its
affine aggregate is the selected response. -/
theorem exists_schemeLiftCandidate
    (witness : SchemeGLiftWitness C oracle weights response g)
    (hresponse : response ∈ C.base)
    (hsmall : (schemeProximityDisagreement oracle weights response).card ≤ e)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (hradius : e + g < d) :
    ∃ candidate : SchemeLiftCandidate C oracle (e + g),
      candidate.proximityRow weights = response ∧
        (candidate.remainingBadColumns weights response).card ≤ g := by
  classical
  let responseErrors := schemeProximityDisagreement oracle weights response
  let matrixErrors := matrixErrorCoordinates (schemeLiftCommittedRows oracle)
    (schemeLiftCandidateRows witness.offset witness.row)
  have hmatrixCard : matrixErrors.card ≤ e + g := by
    calc
      matrixErrors.card ≤ (responseErrors ∪ witness.extra).card :=
        Finset.card_le_card witness.matrixErrors_subset
      _ ≤ responseErrors.card + witness.extra.card := Finset.card_union_le _ _
      _ ≤ e + g := Nat.add_le_add hsmall witness.extra_card
  let candidate : SchemeLiftCandidate C oracle (e + g) := {
    offset := witness.offset
    row := witness.row
    offset_mem := witness.offset_mem
    row_mem := witness.row_mem
    close := hmatrixCard }
  have hcandidateBad : candidate.badColumns = matrixErrors := rfl
  have haggregateCodeword :
      codeword (candidate.proximityRow weights) = codeword response := by
    let difference := codeword (candidate.proximityRow weights) - codeword response
    have hsupport : supportOn Finset.univ difference ⊆
        responseErrors ∪ witness.extra := by
      intro j hj
      by_contra hnot
      have hnotUnion : j ∉ responseErrors ∪ witness.extra := hnot
      have hnotResponse : j ∉ responseErrors := fun hjResponse ↦
        hnotUnion (Finset.mem_union_left _ hjResponse)
      have hnotExtra : j ∉ witness.extra := fun hjExtra ↦
        hnotUnion (Finset.mem_union_right _ hjExtra)
      have hnotMatrix : j ∉ matrixErrors := by
        intro hjMatrix
        rcases Finset.mem_union.mp (witness.matrixErrors_subset hjMatrix) with
          hjResponse | hjExtra
        · exact hnotResponse hjResponse
        · exact hnotExtra hjExtra
      have hresponseObserved :
          response (codePosition j) =
            schemeProximityObserved oracle weights j := by
        apply not_ne_iff.mp
        intro hne
        exact hnotResponse (Finset.mem_filter.mpr ⟨Finset.mem_univ _, hne⟩)
      have hcandidateObserved :
          candidate.proximityRow weights (codePosition j) =
            schemeProximityObserved oracle weights j := by
        have hnotBad : j ∉ candidate.badColumns := by
          simpa [hcandidateBad] using hnotMatrix
        have hoffset := candidate.offset_eq_of_not_bad j hnotBad
        have hrow (index : SchemeTestedRow CheckedMask nw nq 1) :=
          candidate.row_eq_of_not_bad index j hnotBad
        simp only [SchemeLiftCandidate.proximityRow,
          schemeProximityObserved, Pi.add_apply, Finset.sum_apply,
          Pi.smul_apply, smul_eq_mul]
        rw [← hoffset]
        calc
          oracle.proximityBlind 0 j +
              ∑ index, weights index * candidate.row index (codePosition j) =
            oracle.proximityBlind 0 j +
              ∑ index, weights index * oracle.testedRow index j := by
                congr 1
                apply Finset.sum_congr rfl
                intro index _
                exact congrArg (weights index * ·) (hrow index).symm
          _ = ∑ index, weights index * oracle.testedRow index j +
              oracle.proximityBlind 0 j := add_comm _ _
      have hzero : difference j = 0 := by
        simp [difference, codeword, hcandidateObserved, hresponseObserved]
      exact (mem_supportOn Finset.univ difference j).mp hj |>.2 hzero
    have hweight : weight difference ≤ e + g := by
      calc
        weight difference ≤ (responseErrors ∪ witness.extra).card :=
          Finset.card_le_card hsupport
        _ ≤ responseErrors.card + witness.extra.card := Finset.card_union_le _ _
        _ ≤ e + g := Nat.add_le_add hsmall witness.extra_card
    have hdifferenceMem : difference ∈ C.baseCode :=
      C.baseCode.sub_mem
        (C.codeword_mem_baseCode (candidate.proximityRow_mem weights))
        (C.codeword_mem_baseCode hresponse)
    have hdifferenceZero : difference = 0 :=
      AffineAgreement.eq_zero_of_weight_lt_distance hmin
        hdifferenceMem (hweight.trans_lt hradius)
    exact sub_eq_zero.mp hdifferenceZero
  have haggregate : candidate.proximityRow weights = response :=
    C.baseRow_eq_of_codeword_eq (candidate.proximityRow_mem weights)
      hresponse haggregateCodeword
  have hremainingSubset :
      candidate.remainingBadColumns weights response ⊆ witness.extra := by
    intro j hj
    have hjParts := Finset.mem_sdiff.mp hj
    have hjMatrix : j ∈ matrixErrors := by
      simpa [hcandidateBad] using hjParts.1
    rcases Finset.mem_union.mp (witness.matrixErrors_subset hjMatrix) with
      hjResponse | hjExtra
    · exact False.elim (hjParts.2 hjResponse)
    · exact hjExtra
  exact ⟨candidate, haggregate,
    (Finset.card_le_card hremainingSubset).trans witness.extra_card⟩

end SchemeGLiftWitness

end LigeroFamily
