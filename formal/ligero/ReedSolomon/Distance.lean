import ReedSolomon.Code
import Mathlib.Algebra.Polynomial.Roots

/-!
# Minimum distance of Reed--Solomon evaluation codes
-/

namespace ReedSolomon

open CodingTheory Polynomial

variable {F : Type*} [Field F] [DecidableEq F]

/-- A degree-`<k` evaluation code on `n` distinct points has minimum distance
at least `n-k+1`. -/
theorem evaluation_code_minimum_distance {n k : ℕ}
    (D : EvaluationDomain F n) (hkpos : 1 ≤ k) (hk : k ≤ n) :
    HasMinimumDistanceAtLeast (evaluationCode D k) (n - k + 1) := by
  refine ⟨by omega, ?_⟩
  intro c hc hc0
  obtain ⟨p, hpDegree, hEval⟩ := mem_evaluationCode.mp hc
  have hp0 : p ≠ 0 := by
    intro hp
    apply hc0
    funext i
    simpa [hp] using hEval i
  have hpNatDegree : p.natDegree < k := by
    have hp := Polynomial.mem_degreeLT.mp hpDegree
    rw [Polynomial.degree_eq_natDegree hp0] at hp
    exact WithBot.coe_lt_coe.mp hp
  let zeros : Finset (Fin n) := Finset.univ.filter fun i ↦ c i = 0
  let rootValues : Finset F := zeros.image D.point
  have hrootValues : rootValues.card ≤ p.natDegree := by
    apply Polynomial.card_le_degree_of_subset_roots
    intro x hx
    have hx' : x ∈ rootValues := by simpa using hx
    obtain ⟨i, hi, rfl⟩ := Finset.mem_image.mp hx'
    have hiZero : c i = 0 := (Finset.mem_filter.mp hi).2
    apply (Polynomial.mem_roots hp0).mpr
    unfold Polynomial.IsRoot
    rw [← hEval i]
    exact hiZero
  have hzeros : zeros.card ≤ p.natDegree := by
    rw [show zeros.card = rootValues.card by
      exact (Finset.card_image_of_injective zeros D.injective).symm]
    exact hrootValues
  have hpartition : zeros.card + weight c = n := by
    simpa [zeros, weight, supportOn, Nat.add_comm] using
      Finset.card_filter_add_card_filter_not
        (s := (Finset.univ : Finset (Fin n))) (fun i ↦ c i = 0)
  omega

end ReedSolomon
