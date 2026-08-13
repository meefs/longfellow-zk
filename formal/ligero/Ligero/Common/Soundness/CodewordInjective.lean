import Ligero.Common.Protocol.Evaluation

/-! # Injectivity of committed base-row evaluations -/

namespace Ligero.Common.MultiplicativeCode

open CodingTheory
open Ligero.Common

variable {F : Type*} [Field F] {r w n : ℕ}

/-- A base evaluation row is determined by its committed codeword. -/
theorem baseRow_eq_of_codeword_eq
    (C : MultiplicativeCode F r w n)
    {left right : EvaluationRow F r w n}
    (hleft : left ∈ C.base) (hright : right ∈ C.base)
    (hcodeword : codeword left = codeword right) :
    left = right := by
  obtain ⟨J, _hJsubset, hJcard⟩ := Finset.exists_subset_card_eq
    (s := (Finset.univ : Finset (Fin n)))
      (show C.k ≤ (Finset.univ : Finset (Fin n)).card by
        simpa using C.k_le_n)
  apply C.base_unique hleft hright (codePositions (r := r) (w := w) J)
  · simp [hJcard]
  · intro i hi
    obtain ⟨j, _hj, rfl⟩ := Finset.mem_image.mp hi
    exact congrFun hcodeword j

end Ligero.Common.MultiplicativeCode
