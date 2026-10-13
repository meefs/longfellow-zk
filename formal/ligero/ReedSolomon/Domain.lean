import CodingTheory.Basic
import Mathlib.Data.Fintype.EquivFin

/-! Ordered Reed--Solomon evaluation domains. -/

namespace ReedSolomon

export CodingTheory (Word)

variable {F : Type*} [Field F]

/-- An ordered collection of distinct evaluation points. -/
structure EvaluationDomain (F : Type*) [Field F] (n : ℕ) where
  point : Fin n → F
  injective : Function.Injective point

namespace EvaluationDomain

/-- Choose an ordered evaluation domain from the cardinality condition that
there are at least `n` field elements. -/
noncomputable def ofCardLE [Fintype F] {n : ℕ}
    (h : n ≤ Fintype.card F) : EvaluationDomain F n := by
  let embedding : Fin n ↪ F := Classical.choice <|
    Function.Embedding.nonempty_of_card_le (by simpa using h)
  exact ⟨embedding, embedding.injective⟩

/-- Every evaluation domain certifies its field-cardinality requirement. -/
theorem length_le_card [Fintype F] {n : ℕ} (D : EvaluationDomain F n) :
    n ≤ Fintype.card F := by
  simpa using Fintype.card_le_of_embedding
    ⟨D.point, D.injective⟩

end EvaluationDomain

end ReedSolomon
