import CodingTheory.ListDecoding.InterleavedJohnson
import Ligero.Common.Soundness.CodewordInjective
import Ligero.Common.Soundness.ProfiledLiftList








namespace Ligero.Common

open CodingTheory
open MultiplicativeCode

variable {F Equations CheckedMask DirectMask : Type*}
variable [Field F] [Fintype F] [DecidableEq F]
variable [Fintype Equations] [DecidableEq Equations]
variable [Fintype CheckedMask] [DecidableEq CheckedMask]
variable {r w n nw nq radius d : ℕ}

namespace SchemeLiftCandidate

variable {C : MultiplicativeCode F r w n}
variable {oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1}

omit [Fintype F] [Fintype Equations] [DecidableEq Equations]
    [DecidableEq CheckedMask] in
/-- The rowwise committed-codeword matrix determines a scheme lift candidate. -/
theorem candidateRows_injective : Function.Injective
    (fun candidate : SchemeLiftCandidate C oracle radius ↦
      schemeLiftCandidateRows candidate.offset candidate.row) := by
  intro first second hmatrix
  apply SchemeLiftCandidate.ext
  · apply C.baseRow_eq_of_codeword_eq first.offset_mem second.offset_mem
    exact congrFun hmatrix none
  · funext index
    apply C.baseRow_eq_of_codeword_eq (first.row_mem index)
      (second.row_mem index)
    exact congrFun hmatrix (some index)

omit [Fintype Equations] [DecidableEq Equations] [DecidableEq CheckedMask] in
/-- The complete fixed list of radius-`radius` scheme candidates satisfies
the interleaved Johnson cardinality bound. -/
theorem univ_card_le_listBound
    (C : MultiplicativeCode F r w n)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (hradiusLength : radius ≤ n) (hradiusDistance : radius < d)
    (hden : 0 < CodingTheory.InterleavedJohnson.denominator n d radius) :
    (Finset.univ : Finset (SchemeLiftCandidate C oracle radius)).card ≤
      CodingTheory.InterleavedJohnson.listBound n d radius := by
  let matrices : Finset
      (Option (SchemeTestedRow CheckedMask nw nq 1) → Word F n) :=
    Finset.univ.image fun candidate : SchemeLiftCandidate C oracle radius ↦
      schemeLiftCandidateRows candidate.offset candidate.row
  have hmatricesCard : matrices.card =
      (Finset.univ : Finset (SchemeLiftCandidate C oracle radius)).card := by
    change (Finset.univ.image fun candidate : SchemeLiftCandidate C oracle radius ↦
      schemeLiftCandidateRows candidate.offset candidate.row).card = _
    rw [Finset.card_image_of_injective _ candidateRows_injective]
  have hcode (matrix : Option (SchemeTestedRow CheckedMask nw nq 1) → Word F n)
      (hmatrix : matrix ∈ matrices)
      (row : Option (SchemeTestedRow CheckedMask nw nq 1)) :
      matrix row ∈ C.baseCode := by
    obtain ⟨candidate, _hcandidate, rfl⟩ := Finset.mem_image.mp hmatrix
    cases row with
    | none => exact C.codeword_mem_baseCode candidate.offset_mem
    | some index => exact C.codeword_mem_baseCode (candidate.row_mem index)
  have hclose (matrix : Option (SchemeTestedRow CheckedMask nw nq 1) → Word F n)
      (hmatrix : matrix ∈ matrices) :
      (matrixErrorCoordinates (schemeLiftCommittedRows oracle) matrix).card ≤
        radius := by
    obtain ⟨candidate, _hcandidate, rfl⟩ := Finset.mem_image.mp hmatrix
    exact candidate.close
  have hbound :=
    CodingTheory.InterleavedJohnson.card_le_listBound
      C.baseCode (schemeLiftCommittedRows oracle) matrices hmin hcode hclose
        hradiusLength hradiusDistance hden
  rw [hmatricesCard] at hbound
  exact hbound

end SchemeLiftCandidate

end Ligero.Common
