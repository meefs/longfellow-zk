import LigeroFamily.Protocol.Basic

/-!
# Response-row agreement

The mask-independent interpolation fact used by both agreement profiles:
distinct response rows agree on at most `2 * k - 1` committed columns.
-/

namespace LigeroFamily

open CodingTheory
open MultiplicativeCode

variable {F : Type*} [Field F] [DecidableEq F]
variable {r w n : ℕ}

abbrev responseAgreement (left right : EvaluationRow F r w n) : Finset (Fin n) :=
  agreementCoordinates (codeword left) (codeword right)

omit [Field F] in
@[simp] theorem mem_responseAgreement
    (left right : EvaluationRow F r w n) (j : Fin n) :
    j ∈ responseAgreement left right ↔
      left (codePosition j) = right (codePosition j) := by
  simp [responseAgreement, codeword]

/-- Distinct response rows agree at fewer than `2 * k` committed locations. -/
theorem responseAgreement_card_lt
    (C : MultiplicativeCode F r w n)
    {left right : EvaluationRow F r w n}
    (hleft : left ∈ C.response) (hright : right ∈ C.response)
    (hne : left ≠ right) :
    (responseAgreement left right).card < 2 * C.k := by
  classical
  apply Nat.lt_of_not_ge
  intro hlarge
  obtain ⟨J, hJsubset, hJcard⟩ := Finset.exists_subset_card_eq hlarge
  apply hne
  apply C.response_unique hleft hright
    (codePositions (r := r) (w := w) J)
  · simp [hJcard]
  · intro i hi
    rcases Finset.mem_image.mp hi with ⟨j, hj, rfl⟩
    exact (mem_responseAgreement left right j).mp (hJsubset hj)

theorem responseAgreement_card_le
    (C : MultiplicativeCode F r w n)
    {left right : EvaluationRow F r w n}
    (hleft : left ∈ C.response) (hright : right ∈ C.response)
    (hne : left ≠ right) :
    (responseAgreement left right).card ≤ 2 * C.k - 1 := by
  have := responseAgreement_card_lt C hleft hright hne
  omega

end LigeroFamily
