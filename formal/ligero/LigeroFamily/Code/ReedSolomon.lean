import LigeroFamily.Protocol.Evaluation
import ReedSolomon.Distance
import Mathlib.LinearAlgebra.Lagrange

/-!
# Concrete Longfellow Reed--Solomon model for LigeroFamily

This file proves that the abstract evaluation-space assumptions used by the
main analysis are inhabited by the intended polynomial construction.  The
proofs remain outside the protocol analysis: soundness continues to use the
arbitrary committed-coordinate linear code exposed by `baseCode`.
-/

namespace LigeroFamily.ReedSolomon

open Polynomial
open MultiplicativeCode

variable {F : Type*} [Field F]
variable {r w n : ℕ}

/-- Distinct field points for every random-prefix, witness, and committed-code
evaluation used by Longfellow. -/
structure Domain (F : Type*) [Field F] (r w n : ℕ) where
  point : Position r w n → F
  injective : Function.Injective point

namespace Domain

/-- Choose a Longfellow domain from the exact field-cardinality requirement. -/
noncomputable def ofCardLE [Fintype F]
    (h : r + w + n ≤ Fintype.card F) : Domain F r w n := by
  let embedding : Position r w n ↪ F := Classical.choice <|
    Function.Embedding.nonempty_of_card_le (by
      simpa [Position, MessagePosition, Nat.add_assoc] using h)
  exact ⟨embedding, embedding.injective⟩

/-- The committed-coordinate Reed--Solomon domain. -/
def codeDomain (D : Domain F r w n) :
    _root_.ReedSolomon.EvaluationDomain F n where
  point j := D.point (codePosition j)
  injective := fun _ _ h ↦ by
    simpa [codePosition] using D.injective h

end Domain

/-- Evaluate a polynomial at every Longfellow position. -/
noncomputable def evaluationLinearMap (D : Domain F r w n) :
    F[X] →ₗ[F] EvaluationRow F r w n :=
  LinearMap.pi fun i ↦ Polynomial.leval (D.point i)

/-- Evaluation rows represented by polynomials of degree strictly below
`degree`. -/
noncomputable def evaluationSpace (D : Domain F r w n) (degree : ℕ) :
    Submodule F (EvaluationRow F r w n) :=
  (Polynomial.degreeLT F degree).map (evaluationLinearMap D)

theorem mem_evaluationSpace (D : Domain F r w n) {degree : ℕ}
    {row : EvaluationRow F r w n} :
    row ∈ evaluationSpace D degree ↔
      ∃ p : F[X], p ∈ Polynomial.degreeLT F degree ∧
        ∀ i, row i = p.eval (D.point i) := by
  constructor
  · rintro ⟨p, hp, rfl⟩
    exact ⟨p, hp, fun _ ↦ rfl⟩
  · rintro ⟨p, hp, hrow⟩
    refine ⟨p, hp, ?_⟩
    funext i
    exact (hrow i).symm

theorem mul_mem_degreeLT_add {a b : ℕ} {p q : F[X]}
    (hp : p ∈ Polynomial.degreeLT F a)
    (hq : q ∈ Polynomial.degreeLT F b) :
    p * q ∈ Polynomial.degreeLT F (a + b) := by
  by_cases hpzero : p = 0
  · simp [hpzero]
  by_cases hqzero : q = 0
  · simp [hqzero]
  rw [Polynomial.mem_degreeLT] at hp hq ⊢
  refine (Polynomial.degree_mul_le p q).trans_lt ?_
  rw [Polynomial.degree_eq_natDegree hpzero] at hp
  rw [Polynomial.degree_eq_natDegree hqzero] at hq
  rw [Polynomial.degree_eq_natDegree hpzero,
    Polynomial.degree_eq_natDegree hqzero, ← Nat.cast_add]
  exact WithBot.coe_lt_coe.mpr <|
    Nat.add_lt_add (WithBot.coe_lt_coe.mp hp) (WithBot.coe_lt_coe.mp hq)

private theorem rows_unique (D : Domain F r w n) (degree : ℕ)
    {left right : EvaluationRow F r w n}
    (hleft : left ∈ evaluationSpace D degree)
    (hright : right ∈ evaluationSpace D degree)
    (S : Finset (Position r w n)) (hS : S.card = degree)
    (hagree : ∀ i ∈ S, left i = right i) : left = right := by
  obtain ⟨p, hp, hpEval⟩ := (mem_evaluationSpace D).mp hleft
  obtain ⟨q, hq, hqEval⟩ := (mem_evaluationSpace D).mp hright
  have hpDegree : p.degree < S.card := by
    simpa [hS] using Polynomial.mem_degreeLT.mp hp
  have hqDegree : q.degree < S.card := by
    simpa [hS] using Polynomial.mem_degreeLT.mp hq
  have hpq : p = q :=
    Polynomial.eq_of_degrees_lt_of_eval_index_eq
      S D.injective.injOn hpDegree hqDegree (by
        intro i hi
        rw [← hpEval i, ← hqEval i]
        exact hagree i hi)
  funext i
  rw [hpEval i, hqEval i, hpq]

/-- The intended base and response evaluation spaces form a
`MultiplicativeCode`. -/
noncomputable def multiplicativeCode (D : Domain F r w n)
    (hk : r + w ≤ n) : MultiplicativeCode F r w n where
  k := r + w
  k_eq := rfl
  k_le_n := hk
  base := evaluationSpace D (r + w)
  response := evaluationSpace D (2 * (r + w))
  base_le_response := by
    intro row hrow
    obtain ⟨p, hp, hpEval⟩ := (mem_evaluationSpace D).mp hrow
    apply (mem_evaluationSpace D).mpr ⟨p, ?_, hpEval⟩
    exact Polynomial.degreeLT_mono (by omega) hp
  interpolateBase := by
    intro S hS values
    let prescribed : Position r w n → F := fun i ↦
      if hi : i ∈ S then values ⟨i, hi⟩ else 0
    let p := Lagrange.interpolate S D.point prescribed
    let row : EvaluationRow F r w n := fun i ↦ p.eval (D.point i)
    refine ⟨row, (mem_evaluationSpace D).mpr ⟨p, ?_, fun _ ↦ rfl⟩, ?_⟩
    · rw [Polynomial.mem_degreeLT]
      exact (Lagrange.degree_interpolate_lt prescribed D.injective.injOn).trans_le
        (by exact_mod_cast hS)
    · intro i
      change p.eval (D.point i.1) = values i
      rw [show p.eval (D.point i.1) = prescribed i.1 from
        Lagrange.eval_interpolate_at_node prescribed D.injective.injOn i.2]
      simp [prescribed, i.2]
  base_unique := by
    intro left right hleft hright S hS hagree
    exact rows_unique D (r + w) hleft hright S hS hagree
  response_unique := by
    intro left right hleft hright S hS hagree
    exact rows_unique D (2 * (r + w)) hleft hright S hS hagree
  mul_mem := by
    intro left right hleft hright
    obtain ⟨p, hp, hpEval⟩ := (mem_evaluationSpace D).mp hleft
    obtain ⟨q, hq, hqEval⟩ := (mem_evaluationSpace D).mp hright
    apply (mem_evaluationSpace D).mpr
    refine ⟨p * q, by simpa [two_mul] using mul_mem_degreeLT_add hp hq, ?_⟩
    intro i
    simp [rowMul, hpEval i, hqEval i]

/-- The monic polynomial that vanishes at every Longfellow message point. -/
noncomputable def vanishingPolynomial (D : Domain F r w n) : F[X] :=
  ∏ i : MessagePosition r w, (Polynomial.X - Polynomial.C (D.point (Sum.inl i)))

theorem vanishingPolynomial_monic (D : Domain F r w n) :
    (vanishingPolynomial D).Monic := by
  classical
  unfold vanishingPolynomial
  exact Polynomial.monic_prod_of_monic _ _ fun i _ ↦
    Polynomial.monic_X_sub_C _

@[simp] theorem vanishingPolynomial_natDegree (D : Domain F r w n) :
    (vanishingPolynomial D).natDegree = r + w := by
  classical
  unfold vanishingPolynomial
  simpa [Fintype.card_sum] using
    (Polynomial.natDegree_finsetProd_X_sub_C_eq_card
      (s := (Finset.univ : Finset (MessagePosition r w)))
      (f := fun i ↦ D.point (Sum.inl i)))

/-- Evaluation of the vanishing polynomial on the complete domain. -/
noncomputable def vanishingRow (D : Domain F r w n) : EvaluationRow F r w n :=
  fun i ↦ (vanishingPolynomial D).eval (D.point i)

/-- The intended public vanishing multiplier satisfies the abstract masking
basis interface. -/
noncomputable def maskingBasis (D : Domain F r w n) (hk : r + w ≤ n) :
    (multiplicativeCode D hk).MaskingBasis where
  vanishing := vanishingRow D
  vanishing_message := by
    classical
    intro i
    unfold vanishingRow vanishingPolynomial
    rw [Polynomial.eval_prod]
    apply Finset.prod_eq_zero (Finset.mem_univ i)
    simp
  vanishing_code_ne := by
    classical
    intro j
    unfold vanishingRow vanishingPolynomial
    rw [Polynomial.eval_prod]
    apply Finset.prod_ne_zero_iff.mpr
    intro i _
    simp only [Polynomial.eval_sub, Polynomial.eval_X, Polynomial.eval_C]
    exact sub_ne_zero.mpr (D.injective.ne (by simp [codePosition]))
  vanishing_mul_mem := by
    intro row hrow
    obtain ⟨p, hp, hpEval⟩ := (mem_evaluationSpace D).mp hrow
    apply (mem_evaluationSpace D).mpr
    refine ⟨vanishingPolynomial D * p, ?_, ?_⟩
    · by_cases hpzero : p = 0
      · simp [hpzero]
      have hvzero : vanishingPolynomial D ≠ 0 :=
        (vanishingPolynomial_monic D).ne_zero
      rw [Polynomial.mem_degreeLT,
        Polynomial.degree_eq_natDegree (mul_ne_zero hvzero hpzero),
        Polynomial.natDegree_mul hvzero hpzero,
        vanishingPolynomial_natDegree]
      have hpDegree : p.natDegree < r + w := by
        have := Polynomial.mem_degreeLT.mp hp
        rw [Polynomial.degree_eq_natDegree hpzero] at this
        exact WithBot.coe_lt_coe.mp this
      exact_mod_cast (show r + w + p.natDegree < 2 * (r + w) by omega)
    · intro i
      simp [rowMul, vanishingRow, hpEval i]

/-- Restricting the concrete base space to committed coordinates gives the
ordinary degree-`<r+w` Reed--Solomon code. -/
theorem baseCode_eq_evaluationCode (D : Domain F r w n) (hk : r + w ≤ n) :
    (multiplicativeCode D hk).baseCode =
      _root_.ReedSolomon.evaluationCode D.codeDomain (r + w) := by
  ext word
  constructor
  · intro hword
    obtain ⟨row, hrow, hrowWord⟩ :=
      (multiplicativeCode D hk).exists_base_row_of_mem_baseCode hword
    obtain ⟨p, hp, hpEval⟩ := (mem_evaluationSpace D).mp hrow
    apply _root_.ReedSolomon.mem_evaluationCode.mpr
    refine ⟨p, hp, ?_⟩
    intro j
    rw [← hrowWord]
    exact hpEval (codePosition j)
  · intro hword
    obtain ⟨p, hp, hpEval⟩ :=
      _root_.ReedSolomon.mem_evaluationCode.mp hword
    let row : EvaluationRow F r w n := fun i ↦ p.eval (D.point i)
    have hrow : row ∈ (multiplicativeCode D hk).base :=
      (mem_evaluationSpace D).mpr ⟨p, hp, fun _ ↦ rfl⟩
    have hcode := (multiplicativeCode D hk).codeword_mem_baseCode hrow
    rw [show word = codeword row by
      funext j
      exact hpEval j]
    exact hcode

/-- The concrete Longfellow base code has the usual Reed--Solomon distance
`n - (r + w) + 1`.  This is the only Reed--Solomon-specific ingredient needed
to discharge the abstract distance hypothesis of the main soundness theorem. -/
theorem baseCode_minimum_distance [DecidableEq F]
    (D : Domain F r w n) (hkpos : 1 ≤ r + w) (hk : r + w ≤ n) :
    CodingTheory.HasMinimumDistanceAtLeast
      (multiplicativeCode D hk).baseCode (n - (r + w) + 1) := by
  rw [baseCode_eq_evaluationCode D hk]
  exact _root_.ReedSolomon.evaluation_code_minimum_distance
    D.codeDomain hkpos hk

end LigeroFamily.ReedSolomon
