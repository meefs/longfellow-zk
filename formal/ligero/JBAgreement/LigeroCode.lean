import JBAgreement.Certificate
import LigeroFamily.Code.ReedSolomon

/-!
# The Reed–Solomon presentation of Ligero's base code

`JBAgreement.RSPresentation` is the one structural hypothesis the Johnson route
needs and the clique route does not: the Johnson bound is a statement about
polynomials, so the code must be presented as low-degree evaluations.

Ligero's abstract `MultiplicativeCode` carries no such presentation -- it is
axiomatised by interpolation, uniqueness and multiplicativity -- but its
*concrete* Reed–Solomon instantiation does, and
`LigeroFamily.ReedSolomon.baseCode_eq_evaluationCode` says exactly that the
committed-coordinate projection is the ordinary degree-`<r+w` Reed–Solomon code.
So the presentation is constructed here, not assumed: on the instantiation the
whole grid uses, the Johnson route costs no new hypothesis.

A dimension-`k = r + w` code consists of polynomials of degree strictly below
`k`, matching the convention used by the public Johnson theorems.
-/

namespace JBAgreement

open CodingTheory Polynomial

variable {F : Type*} [Field F] [Fintype F] [DecidableEq F]
variable {r w n : ℕ}

omit [Fintype F] in
/-- Degree `≤ k - 1` is membership in `degreeLT F k`, for `k ≥ 1`. -/
theorem mem_degreeLT_of_natDegree_le {k : ℕ} (hk : 1 ≤ k) {p : F[X]}
    (hp : p.natDegree ≤ k - 1) : p ∈ Polynomial.degreeLT F k := by
  rw [Polynomial.mem_degreeLT]
  by_cases hzero : p = 0
  · simp [hzero]
  · rw [Polynomial.degree_eq_natDegree hzero]
    exact_mod_cast lt_of_le_of_lt hp (by omega)

omit [Fintype F] in
/-- Conversely, membership in `degreeLT F k` bounds the natural degree. -/
theorem natDegree_le_of_mem_degreeLT {k : ℕ} {p : F[X]}
    (hp : p ∈ Polynomial.degreeLT F k) : p.natDegree ≤ k - 1 := by
  by_cases hzero : p = 0
  · simp [hzero]
  · have hdeg := Polynomial.mem_degreeLT.mp hp
    rw [Polynomial.degree_eq_natDegree hzero] at hdeg
    have : p.natDegree < k := by exact_mod_cast hdeg
    omega

/-- **Ligero's concrete base code is Reed–Solomon, presented.**  The evaluation
domain is the committed-coordinate restriction of the Longfellow domain, and the
two inclusions are `baseCode_eq_evaluationCode` read in each direction. -/
noncomputable def rsPresentation (D : LigeroFamily.ReedSolomon.Domain F r w n)
    (hkpos : 1 ≤ r + w) (hk : r + w ≤ n) :
    RSPresentation n (r + w)
      (LigeroFamily.ReedSolomon.multiplicativeCode D hk).baseCode where
  dom := D.codeDomain.point
  dom_injective := D.codeDomain.injective
  mem_of_natDegree_lt p hp := by
    rw [LigeroFamily.ReedSolomon.baseCode_eq_evaluationCode D hk]
    exact _root_.ReedSolomon.mem_evaluationCode.mpr
      ⟨p, mem_degreeLT_of_natDegree_le hkpos (Nat.le_pred_of_lt hp), fun _ => rfl⟩
  exists_of_mem word hword := by
    rw [LigeroFamily.ReedSolomon.baseCode_eq_evaluationCode D hk] at hword
    obtain ⟨p, hp, hword⟩ := _root_.ReedSolomon.mem_evaluationCode.mp hword
    refine ⟨p, (natDegree_le_of_mem_degreeLT hp).trans_lt (by omega), ?_⟩
    funext j
    exact hword j

/-- **The Johnson route, on Ligero's concrete code.**  A checked Johnson
certificate at the code's own degree bound gives the per-line interface the
soundness stack consumes, with no hypothesis about the code left over. -/
theorem lineFailureBound_of_johnsonConditions_rs
    {e g bound etaBits : ℕ}
    (D : LigeroFamily.ReedSolomon.Domain F r w n)
    (hkpos : 1 ≤ r + w) (hk : r + w ≤ n)
    (h : JohnsonConditions n (r + w) e etaBits bound (Fintype.card F)) :
    SelectedMCA.LineFailureBound
      (LigeroFamily.ReedSolomon.multiplicativeCode D hk).baseCode e g bound :=
  lineFailureBound_of_johnsonConditions (rsPresentation D hkpos hk) rfl h

end JBAgreement
