import ReedSolomon.Domain
import Mathlib.Algebra.Polynomial.Eval.SMul
import Mathlib.RingTheory.Polynomial.Basic

/-!
# Reed--Solomon evaluation codes
-/

namespace ReedSolomon

open Polynomial

variable {F : Type*} [Field F]

/-- Simultaneous evaluation on an ordered domain, as a linear map. -/
noncomputable def evaluationLinearMap {n : ℕ} (D : EvaluationDomain F n) :
    F[X] →ₗ[F] Word F n :=
  LinearMap.pi fun i ↦ Polynomial.leval (D.point i)

/-- The length-`n`, degree-`<k` Reed--Solomon evaluation code. -/
noncomputable def evaluationCode {n : ℕ} (D : EvaluationDomain F n) (k : ℕ) :
    CodingTheory.LinearCode F n :=
  (Polynomial.degreeLT F k).map (evaluationLinearMap D)

theorem mem_evaluationCode {n k : ℕ} {D : EvaluationDomain F n}
    {w : Word F n} :
    w ∈ evaluationCode D k ↔
      ∃ p : F[X], p ∈ Polynomial.degreeLT F k ∧
        ∀ i, w i = p.eval (D.point i) := by
  constructor
  · rintro ⟨p, hp, rfl⟩
    exact ⟨p, hp, fun _ ↦ rfl⟩
  · rintro ⟨p, hp, hword⟩
    refine ⟨p, hp, ?_⟩
    funext i
    exact (hword i).symm

end ReedSolomon
