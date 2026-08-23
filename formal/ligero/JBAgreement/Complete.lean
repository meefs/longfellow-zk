import JBAgreement.ScalarExtension
import JBAgreement.GS
import Mathlib.Algebra.Order.Archimedean.Real.Basic
import Mathlib.Data.Nat.Cast.Order.Field

/-!
# The unconditional theorem

`correlatedAgreement_unconditional_sharp_noFieldSize` constructs the
Guruswami–Sudan interpolant, uses the derivative-sensitive ledger, and selects the
good slice after finite scalar extension.  Its only hypotheses are the words, the
per-parameter proximity, and explicitly checkable numeric conditions on
`(m, D, dY, dZ)`:

* `hkdY`, `hcnt` — the interpolation is solvable (more coefficients than
  constraints);
* `hroot` — the agreement overwhelms the weighted degree (`D < m·(n-e)`);
* `hslack`, `hS` — positivity of the agreement slack and the weighted threshold.

The proof constructs a large enough extension internally and descends its affine
bucket, so there is no base-field size condition.

`Johnson.lean`-style feasibility (`johnson` below): in the Johnson regime
`n - e ≥ √(k·n) + 4·η·n` (stated in squared, `√`-free form) all these conditions are
satisfiable with `dY = O(n/(kη))`, `dZ = O(n/(kη²))`, giving the `η³` threshold.
-/

namespace JBAgreement

open Polynomial Finset

section Unconditional

variable {F : Type*} [Field F] [Fintype F] [DecidableEq F]
variable {ι : Type*} [Fintype ι] [DecidableEq ι]

/-- **The Guruswami–Sudan package, for a given family of proximates.**  Constructs the
interpolant and derives its root property at every parameter of `S`.  Shared by the
unconditional correlated agreement theorem and the strong mutual variant. -/
theorem exists_gs_for
    (dom : ι → F) (hdom : Function.Injective dom) (u₀ u₁ : ι → F) (k e : ℕ)
    (S : Finset F) (p : F → F[X])
    (hpdeg : ∀ z ∈ S, (p z).natDegree ≤ k)
    (hprox : ∀ z ∈ S,
      (disagree (fun x => u₀ x + z * u₁ x) (RSeval dom (p z))).card ≤ e)
    (m D dY dZ : ℕ)
    (hkdY : k * dY ≤ D)
    (hcnt : Fintype.card ι * (m * (m + 1)) * (dZ + dY + 1)
        < ((dY + 1) * (2 * (D + 1)) - k * (dY * (dY + 1))) * (dZ + 1))
    (hroot : D < m * (Fintype.card ι - e)) :
    ∃ Q : (F[X][X])[X], Q ≠ 0 ∧ Q.natDegree ≤ dY ∧
      (∀ j, (Q.coeff j).natDegree ≤ D) ∧
      (∀ j i, ((Q.coeff j).coeff i).natDegree ≤ dZ) ∧
      ∀ z ∈ S, ((Q.map (mapRingHom (evalRingHom z))).eval (p z)) = 0 := by
  obtain ⟨Q, hQ0, hQY, hQb, hQZ, hQvan⟩ :=
    exists_interpolant dom u₀ u₁ k m D dY dZ hkdY hcnt
  refine ⟨Q, hQ0, hQY, fun j => le_trans (hQb j) (Nat.sub_le _ _),
    fun j => hQZ j, ?_⟩
  intro z hz
  set T : Finset F :=
    (univ \ disagree (fun x => u₀ x + z * u₁ x) (RSeval dom (p z))).image dom
    with hT
  have hTcard : Fintype.card ι - e ≤ T.card := by
    rw [hT, Finset.card_image_of_injective _ hdom,
      card_sdiff_of_subset (subset_univ _), card_univ]
    have := hprox z hz
    omega
  refine eval_map_eq_zero_of_agreements (m := m) (T := T) hQY hkdY hQb
    (hpdeg z hz) ?_ ?_
  · intro x₀ hx₀
    obtain ⟨x, hx, rfl⟩ := Finset.mem_image.mp hx₀
    rw [mem_sdiff, mem_disagree, not_not] at hx
    have hagree : (p z).eval (dom x) = u₀ x + z * u₁ x := by
      simpa [RSeval] using hx.2.symm
    have hV := vanishesTo_map (evalRingHom z) (hQvan x)
    rw [show (evalRingHom z) (C (dom x)) = dom x by simp] at hV
    rw [show (evalRingHom z) (wordZ u₀ u₁ x) = (p z).eval (dom x) by
      show (wordZ u₀ u₁ x).eval z = _
      rw [wordZ_eval, hagree]] at hV
    exact hV
  · calc D < m * (Fintype.card ι - e) := hroot
      _ ≤ m * T.card := Nat.mul_le_mul_left _ hTcard

/-- **Unconditional sharp theorem with no field-size hypothesis.**  Guruswami–Sudan
is constructed over the base field, while only the good-slice/branch stage is run in
a sufficiently large finite scalar extension and then descended. -/
theorem correlatedAgreement_unconditional_sharp_noFieldSize
    (dom : ι → F) (hdom : Function.Injective dom) (u₀ u₁ : ι → F) (k e : ℕ)
    (hk : 1 ≤ k) (S : Finset F)
    (hclose : ∀ z ∈ S, ∃ p : F[X], p.natDegree ≤ k ∧
      (disagree (fun x => u₀ x + z * u₁ x) (RSeval dom p)).card ≤ e)
    (m D dY dZ : ℕ)
    (hkdY : k * dY ≤ D)
    (hcnt : Fintype.card ι * (m * (m + 1)) * (dZ + dY + 1)
        < ((dY + 1) * (2 * (D + 1)) - k * (dY * (dY + 1))) * (dZ + 1))
    (hroot : D < m * (Fintype.card ι - e))
    (hslack : 1 ≤ Fintype.card ι - e - k)
    (hS : dY * (e + 2) +
        (Fintype.card ι - k) * (4 * k * (dY * dZ) + dY) /
          (Fintype.card ι - e - k) + dZ + 3 * (dY * dZ) < S.card) :
    ∃ v₀ v₁ : F[X], v₀.degree ≤ (k : ℕ) ∧ v₁.degree ≤ (k : ℕ) ∧
      (pairDisagree u₀ u₁ (RSeval dom v₀) (RSeval dom v₁)).card ≤ e ∧
      (∀ S₂ : Finset F, e + 1 < S₂.card →
        (∀ z ∈ S₂, (disagree (fun x => u₀ x + z * u₁ x)
            (fun x => (v₀ + C z * v₁).eval (dom x))).card ≤ e) →
        (S₂.filter fun z =>
          lineAgree u₀ u₁ (RSeval dom v₀) (RSeval dom v₁) z
            ≠ corrAgree u₀ u₁ (RSeval dom v₀) (RSeval dom v₁)).card ≤ e) := by
  classical
  have hchoice : ∀ z : F, ∃ p : F[X], z ∈ S → (p.natDegree ≤ k ∧
      (disagree (fun x => u₀ x + z * u₁ x) (RSeval dom p)).card ≤ e) := by
    intro z
    by_cases hz : z ∈ S
    · obtain ⟨p, hp⟩ := hclose z hz
      exact ⟨p, fun _ => hp⟩
    · exact ⟨0, fun h => absurd h hz⟩
  choose p hp using hchoice
  obtain ⟨Q, hQ0, hQY, hQX, hQZ, hGS⟩ :=
    exists_gs_for dom hdom u₀ u₁ k e S p (fun z hz => (hp z hz).1)
      (fun z hz => (hp z hz).2) m D dY dZ hkdY hcnt hroot
  exact correlatedAgreement_of_GS_sharp_noFieldSize dom hdom u₀ u₁ k e hk S p
    (fun z hz => (hp z hz).1) (fun z hz => (hp z hz).2)
    Q hQ0 D dY dZ hQY hQX hQZ hGS hslack hS

end Unconditional

/-! ### Johnson-regime feasibility -/

section Johnson

set_option maxHeartbeats 1600000 in
/-- **Feasibility of the Guruswami–Sudan parameters in the Johnson regime.**

Under the (√-free, squared) Johnson condition `k·n ≤ (t - 4ηn)²` with
`t ≥ 4ηn`, `ηn ≥ 1`, `η ≤ 1/4`, the parameters
`m = ⌈t/(2ηn)⌉`, `D = m·t - 1`, `dY = ⌊D/k⌋`, `dZ = (m+1)(dY+1)` satisfy every
numeric hypothesis of the interpolation and root steps, with the `η`-sized bounds
`dY ≤ 3n/(4kη)`, `dZ ≤ n/(kη²)`, `D ≤ 3n/(4η)` — the shape that gives the `η³`
threshold. -/
theorem johnson_params (k n t : ℕ) (η : ℝ)
    (hk1 : 1 ≤ k) (hη : 0 < η) (hη4 : η ≤ 1/4)
    (hηn : 1 ≤ η * n)
    (ht4 : 4 * η * n ≤ (t : ℝ)) (htn : t ≤ n)
    (hJ : (k : ℝ) * n ≤ ((t : ℝ) - 4 * η * n) ^ 2) :
    ∃ m D dY dZ : ℕ,
      1 ≤ m ∧ k * dY ≤ D ∧ D < m * t ∧ 1 ≤ dY ∧ dZ = (m + 1) * (dY + 1) ∧
      (n * (m * (m + 1)) * (dZ + dY + 1)
        < ((dY + 1) * (2 * (D + 1)) - k * (dY * (dY + 1))) * (dZ + 1)) ∧
      (dY : ℝ) ≤ 3 * n / (4 * k * η) ∧
      (dZ : ℝ) ≤ n / (k * η ^ 2) ∧
      (D : ℝ) ≤ 3 * n / (4 * η) ∧
      (m : ℝ) ≤ (t : ℝ) / (2 * η * n) + 1 := by
  have hK1 : (1 : ℝ) ≤ (k : ℝ) := by exact_mod_cast hk1
  have hK0 : (0 : ℝ) < (k : ℝ) := by linarith
  have hN4 : (4 : ℝ) ≤ (n : ℝ) := by nlinarith
  have hN0 : (0 : ℝ) < (n : ℝ) := by linarith
  have hT4 : (4 : ℝ) ≤ (t : ℝ) := by nlinarith
  have hT0 : (0 : ℝ) < (t : ℝ) := by linarith
  have hTN : (t : ℝ) ≤ (n : ℝ) := by exact_mod_cast htn
  have hsub0 : (0 : ℝ) ≤ (t : ℝ) - 4 * η * n := by nlinarith
  have hKN : (k : ℝ) ≤ (n : ℝ) := by
    have h2 : (t : ℝ) - 4 * η * n ≤ (n : ℝ) := by nlinarith
    have h3 : ((t : ℝ) - 4 * η * n) ^ 2 ≤ (n : ℝ) ^ 2 := by nlinarith
    nlinarith
  have h2ηN : (0 : ℝ) < 2 * η * n := by positivity
  -- The multiplicity.
  obtain ⟨m, hm_lb, hm_ub⟩ : ∃ m : ℕ,
      (t : ℝ) / (2 * η * n) ≤ (m : ℝ) ∧ (m : ℝ) < (t : ℝ) / (2 * η * n) + 1 :=
    ⟨⌈(t : ℝ) / (2 * η * n)⌉₊, Nat.le_ceil _, Nat.ceil_lt_add_one (by positivity)⟩
  have hm2 : (2 : ℝ) ≤ (m : ℝ) := by
    refine le_trans ?_ hm_lb
    rw [le_div_iff₀ h2ηN]
    nlinarith
  have hm1 : 1 ≤ m := by exact_mod_cast le_trans (by norm_num : (1:ℝ) ≤ 2) hm2
  have ht1 : 1 ≤ t := by exact_mod_cast le_trans (by norm_num : (1:ℝ) ≤ 4) hT4
  have hmt1 : 1 ≤ m * t := Nat.one_le_iff_ne_zero.mpr
    (Nat.mul_ne_zero (by omega) (by omega))
  -- The weighted degree.
  obtain ⟨D, hDdef⟩ : ∃ D : ℕ, D = m * t - 1 := ⟨_, rfl⟩
  have hDlt : D < m * t := by omega
  have hD1 : (D : ℝ) = (m : ℝ) * t - 1 := by
    rw [hDdef]
    push_cast [Nat.cast_sub hmt1]
    ring
  -- The `Y`-degree.
  obtain ⟨dY, hdYdef⟩ : ∃ dY : ℕ, dY = D / k := ⟨_, rfl⟩
  have hkdY : k * dY ≤ D := by
    rw [hdYdef, mul_comm]
    exact Nat.div_mul_le_self D k
  have hkdY1 : D + 1 ≤ k * (dY + 1) := by
    have h1 := Nat.div_add_mod D k
    have h2 : D % k < k := Nat.mod_lt _ (by omega)
    have h3 : k * (D / k + 1) = k * (D / k) + k := by ring
    rw [hdYdef, h3]
    omega
  -- `t ≥ k + 4ηn`, hence `D ≥ k` and `dY ≥ 1`.
  have hTk : (k : ℝ) + 4 * η * n ≤ (t : ℝ) := by
    have h1 : (k : ℝ) ≤ (t : ℝ) - 4 * η * n := by
      nlinarith [hJ, hK0, hKN, hsub0, sq_nonneg ((t : ℝ) - 4 * η * n - k),
        sq_nonneg ((t : ℝ) - 4 * η * n + k)]
    linarith
  have hDk : k ≤ D := by
    have h1 : (k : ℝ) + 1 ≤ (m : ℝ) * t := by
      have h1a : 2 * (t : ℝ) ≤ (m : ℝ) * t :=
        mul_le_mul_of_nonneg_right hm2 (le_of_lt hT0)
      nlinarith [hTk, hηn]
    have h2 : (k : ℝ) ≤ (D : ℝ) := by rw [hD1]; linarith
    exact_mod_cast h2
  have hdY1 : 1 ≤ dY := by
    rw [hdYdef]
    exact (Nat.one_le_div_iff (by omega)).mpr hDk
  -- The `Z`-degree.
  obtain ⟨dZ, hdZdef⟩ : ∃ dZ : ℕ, dZ = (m + 1) * (dY + 1) := ⟨_, rfl⟩
  -- ### The counting inequality.
  have hcnt : n * (m * (m + 1)) * (dZ + dY + 1)
      < ((dY + 1) * (2 * (D + 1)) - k * (dY * (dY + 1))) * (dZ + 1) := by
    have hfac : (dY + 1) * (2 * (D + 1)) - k * (dY * (dY + 1))
        = (dY + 1) * (2 * (D + 1) - k * dY) := by
      have h1 : k * (dY * (dY + 1)) = (dY + 1) * (k * dY) := by ring
      rw [h1, ← Nat.mul_sub]
    have hstep : n * m * (m + 2) < (D + 2) * (dY + 1) := by
      have hcast : (k : ℝ) * ((n : ℝ) * m * ((m : ℝ) + 2))
          < (k : ℝ) * (((D : ℝ) + 2) * ((dY : ℝ) + 1)) := by
        have h4m : 2 * (t : ℝ) ≤ 4 * η * n * m := by
          have h5 := hm_lb
          rw [div_le_iff₀ h2ηN] at h5
          nlinarith
        have hkey : ((m : ℝ) + 1) * ((t : ℝ) - 4 * η * n) ≤ (m : ℝ) * t - t := by
          nlinarith
        have hsq : (k : ℝ) * n * ((m : ℝ) + 1) ^ 2 ≤ ((m : ℝ) * t - t) ^ 2 := by
          have h2 : (0 : ℝ) ≤ ((m : ℝ) + 1) * ((t : ℝ) - 4 * η * n) := by positivity
          calc (k : ℝ) * n * ((m : ℝ) + 1) ^ 2
              = ((m : ℝ) + 1) ^ 2 * ((k : ℝ) * n) := by ring
            _ ≤ ((m : ℝ) + 1) ^ 2 * ((t : ℝ) - 4 * η * n) ^ 2 :=
                mul_le_mul_of_nonneg_left hJ (sq_nonneg _)
            _ = (((m : ℝ) + 1) * ((t : ℝ) - 4 * η * n)) ^ 2 := by ring
            _ ≤ ((m : ℝ) * t - t) ^ 2 := pow_le_pow_left₀ h2 hkey 2
        have hmain : (k : ℝ) * n * ((m : ℝ) * ((m : ℝ) + 2)) < ((m : ℝ) * t) ^ 2 := by
          have e1 : (k : ℝ) * n * ((m : ℝ) * ((m : ℝ) + 2))
              = (k : ℝ) * n * ((m : ℝ) + 1) ^ 2 - (k : ℝ) * n := by ring
          have e2 : ((m : ℝ) * t - t) ^ 2
              = ((m : ℝ) * t) ^ 2 - (2 * m - 1) * (t : ℝ) ^ 2 := by ring
          have e4 : (0 : ℝ) < (2 * (m : ℝ) - 1) * (t : ℝ) ^ 2 := by
            have h5 : (3 : ℝ) ≤ 2 * (m : ℝ) - 1 := by linarith
            nlinarith [sq_nonneg (t : ℝ)]
          have e5 : (0 : ℝ) < (k : ℝ) * n := by positivity
          rw [e2] at hsq
          linarith
        have hD1' : ((m : ℝ) * t) = (D : ℝ) + 1 := by rw [hD1]; ring
        have hkdY1' : (D : ℝ) + 1 ≤ (k : ℝ) * ((dY : ℝ) + 1) := by exact_mod_cast hkdY1
        have hDpos : (0 : ℝ) ≤ (D : ℝ) + 1 := by positivity
        calc (k : ℝ) * ((n : ℝ) * m * ((m : ℝ) + 2))
            = (k : ℝ) * n * ((m : ℝ) * ((m : ℝ) + 2)) := by ring
          _ < ((m : ℝ) * t) ^ 2 := hmain
          _ = ((D : ℝ) + 1) * ((D : ℝ) + 1) := by rw [hD1']; ring
          _ ≤ ((D : ℝ) + 1) * ((k : ℝ) * ((dY : ℝ) + 1)) :=
              mul_le_mul_of_nonneg_left hkdY1' hDpos
          _ ≤ ((D : ℝ) + 2) * ((k : ℝ) * ((dY : ℝ) + 1)) := by
              refine mul_le_mul_of_nonneg_right (by linarith) (by positivity)
          _ = (k : ℝ) * (((D : ℝ) + 2) * ((dY : ℝ) + 1)) := by ring
      have h6 := lt_of_mul_lt_mul_left hcast (le_of_lt hK0)
      exact_mod_cast h6
    have hsplit : dZ + dY + 1 = (m + 2) * (dY + 1) := by rw [hdZdef]; ring
    have hZ1 : (m + 1) * (dY + 1) ≤ dZ + 1 := by
      rw [hdZdef]
      exact Nat.le_succ _
    calc n * (m * (m + 1)) * (dZ + dY + 1)
        = (n * m * (m + 2)) * ((m + 1) * (dY + 1)) := by rw [hsplit]; ring
      _ < ((D + 2) * (dY + 1)) * ((m + 1) * (dY + 1)) := by
          have hpos : 0 < (m + 1) * (dY + 1) := by positivity
          exact mul_lt_mul_of_pos_right hstep hpos
      _ ≤ ((dY + 1) * (2 * (D + 1) - k * dY)) * (dZ + 1) := by
          refine Nat.mul_le_mul ?_ hZ1
          calc (D + 2) * (dY + 1) = (dY + 1) * (D + 2) := by ring
            _ ≤ (dY + 1) * (2 * (D + 1) - k * dY) := by
                refine Nat.mul_le_mul_left _ ?_
                omega
      _ = ((dY + 1) * (2 * (D + 1)) - k * (dY * (dY + 1))) * (dZ + 1) := by
          rw [hfac]
  -- ### The size bounds.
  have hmT : (m : ℝ) * t ≤ (t : ℝ) ^ 2 / (2 * η * n) + t := by
    have h2 : (m : ℝ) * t ≤ ((t : ℝ) / (2 * η * n) + 1) * t := by nlinarith
    calc (m : ℝ) * t ≤ ((t : ℝ) / (2 * η * n) + 1) * t := h2
      _ = (t : ℝ) * t / (2 * η * n) + t := by ring
      _ = (t : ℝ) ^ 2 / (2 * η * n) + t := by ring
  have hDreal : (D : ℝ) ≤ 3 * n / (4 * η) := by
    have h1 : (t : ℝ) ^ 2 / (2 * η * n) ≤ (n : ℝ) / (2 * η) := by
      rw [div_le_div_iff₀ (by positivity) (by positivity)]
      nlinarith [mul_le_mul hTN hTN (le_of_lt hT0) (le_of_lt hN0), hη, hT0]
    have h2 : (t : ℝ) ≤ (n : ℝ) / (4 * η) := by
      rw [le_div_iff₀ (by positivity)]
      nlinarith
    have h3 : (D : ℝ) ≤ (m : ℝ) * t := by rw [hD1]; linarith
    calc (D : ℝ) ≤ (m : ℝ) * t := h3
      _ ≤ (t : ℝ) ^ 2 / (2 * η * n) + t := hmT
      _ ≤ (n : ℝ) / (2 * η) + (n : ℝ) / (4 * η) := by linarith
      _ = 3 * n / (4 * η) := by ring
  have hdYreal : (dY : ℝ) ≤ 3 * n / (4 * k * η) := by
    have h1 : (dY : ℝ) ≤ (D : ℝ) / k := by
      rw [hdYdef]
      exact_mod_cast Nat.cast_div_le
    have h2 : (D : ℝ) / k ≤ (3 * n / (4 * η)) / k := by gcongr
    calc (dY : ℝ) ≤ (D : ℝ) / k := h1
      _ ≤ (3 * n / (4 * η)) / k := h2
      _ = 3 * n / (4 * k * η) := by
          field_simp
  have hdZreal : (dZ : ℝ) ≤ (n : ℝ) / (k * η ^ 2) := by
    have hmub : (m : ℝ) + 1 ≤ 1 / η := by
      have h1 : (t : ℝ) / (2 * η * n) ≤ 1 / (2 * η) := by
        rw [div_le_div_iff₀ h2ηN (by positivity)]
        nlinarith [mul_le_mul_of_nonneg_left hTN (by positivity : (0:ℝ) ≤ 2 * η)]
      have h2 : (2 : ℝ) ≤ 1 / (2 * η) := by
        rw [le_div_iff₀ (by positivity)]
        nlinarith
      have h3 : (m : ℝ) + 1 < 1 / (2 * η) + 2 := by linarith
      have h4 : 1 / (2 * η) + 2 ≤ 1 / (2 * η) + 1 / (2 * η) := by linarith
      have h5 : 1 / (2 * η) + 1 / (2 * η) = 1 / η := by
        field_simp
        ring
      linarith
    have hdYub : (dY : ℝ) + 1 ≤ (n : ℝ) / (k * η) := by
      have h1 : (1 : ℝ) ≤ (n : ℝ) / (4 * k * η) := by
        rw [le_div_iff₀ (by positivity)]
        nlinarith
      have h2 : 3 * (n : ℝ) / (4 * k * η) + (n : ℝ) / (4 * k * η) = (n : ℝ) / (k * η) := by
        field_simp
        ring
      linarith
    have hcast : (dZ : ℝ) = ((m : ℝ) + 1) * ((dY : ℝ) + 1) := by
      rw [hdZdef]
      push_cast
      ring
    have hm0 : (0 : ℝ) ≤ (m : ℝ) + 1 := by positivity
    have hdY0 : (0 : ℝ) ≤ (dY : ℝ) + 1 := by positivity
    calc (dZ : ℝ) = ((m : ℝ) + 1) * ((dY : ℝ) + 1) := hcast
      _ ≤ (1 / η) * ((n : ℝ) / (k * η)) := by
          refine mul_le_mul hmub hdYub hdY0 (by positivity)
      _ = (n : ℝ) / (k * η ^ 2) := by
          field_simp
  exact ⟨m, D, dY, dZ, hm1, hkdY, hDlt, hdY1, hdZdef, hcnt, hdYreal, hdZreal, hDreal,
    le_of_lt hm_ub⟩

end Johnson

/-- The explicit `|S|`-threshold of the Johnson-regime theorem.  It mirrors the
weighted factor-selection bound: the incidence term contains one `dY·dZ` factor,
not the old uniform-bucket `dY²·dZ` factor.  For constant rate and slack this is
`O_ρ(n/η³)`; see `johnsonThreshold_le`. -/
noncomputable def johnsonThreshold (k n e : ℕ) (η : ℝ) : ℝ :=
  (3 * n / (4 * k * η)) * ((e : ℝ) + 2) +
    (n - k : ℕ) * (4 * k * (3 * n / (4 * k * η) * (n / (k * η ^ 2)))
      + 3 * n / (4 * k * η)) / ((n - e - k : ℕ) : ℝ)
    + n / (k * η ^ 2) + 3 * (3 * n / (4 * k * η) * (n / (k * η ^ 2))) + 1

section Final

variable {F : Type*} [Field F] [Fintype F] [DecidableEq F]
variable {ι : Type*} [Fintype ι] [DecidableEq ι]

set_option maxHeartbeats 1600000 in
/-- **The Johnson numeric package.**  From the real-parameter Johnson hypotheses and
the threshold bound, all sharp `ℕ`-side conditions (with `n` the domain size and
`cS` the parameter-set size).  Shared by the plain and strong mutual variants. -/
theorem johnson_numeric (k n e cS : ℕ) (η : ℝ)
    (hk1 : 1 ≤ k) (hη : 0 < η) (hη4 : η ≤ 1/4)
    (hηn : 1 ≤ η * n)
    (ht4 : 4 * η * n ≤ ((n - e : ℕ) : ℝ))
    (hJ : (k : ℝ) * n ≤ (((n - e : ℕ) : ℝ) - 4 * η * n) ^ 2)
    (hS : johnsonThreshold k n e η ≤ (cS : ℝ)) :
    ∃ m D dY dZ : ℕ,
      k * dY ≤ D ∧
      (n * (m * (m + 1)) * (dZ + dY + 1)
        < ((dY + 1) * (2 * (D + 1)) - k * (dY * (dY + 1))) * (dZ + 1)) ∧
      D < m * (n - e) ∧ 1 ≤ n - e - k ∧
      dY * (e + 2) + (n - k) * (4 * k * (dY * dZ) + dY) / (n - e - k) +
        dZ + 3 * (dY * dZ) < cS := by
  -- Notation.
  have htn : n - e ≤ n := Nat.sub_le _ _
  -- The Guruswami–Sudan parameters.
  obtain ⟨m, D, dY, dZ, hm1, hkdY, hDlt, hdY1, hdZdef, hcnt, hdYreal, hdZreal, hDreal, -⟩ :=
    johnson_params k (n) (n - e) η hk1 hη hη4 hηn ht4 htn hJ
  -- Real abbreviations and positivity.
  have hK1 : (1 : ℝ) ≤ (k : ℝ) := by exact_mod_cast hk1
  have hK0 : (0 : ℝ) < (k : ℝ) := by linarith
  have hN4 : (4 : ℝ) ≤ (n : ℝ) := by nlinarith
  have hN0 : (0 : ℝ) < (n : ℝ) := by linarith
  have hT4 : (4 : ℝ) ≤ ((n - e : ℕ) : ℝ) := by nlinarith
  -- `n - e ≥ k + 4`, so `s ≥ 4`.
  have hsub0 : (0 : ℝ) ≤ ((n - e : ℕ) : ℝ) - 4 * η * (n) := by
    linarith
  have hKN : (k : ℝ) ≤ (n : ℝ) := by
    have hTN' : ((n - e : ℕ) : ℝ) ≤ (n : ℝ) := by
      exact_mod_cast htn
    have h2 : ((n - e : ℕ) : ℝ) - 4 * η * (n)
        ≤ (n : ℝ) := by nlinarith
    have h3 : (((n - e : ℕ) : ℝ) - 4 * η * (n)) ^ 2
        ≤ (n : ℝ) ^ 2 := by nlinarith
    nlinarith
  have hTk : (k : ℝ) + 4 * η * (n) ≤ ((n - e : ℕ) : ℝ) := by
    have h1 : (k : ℝ) ≤ ((n - e : ℕ) : ℝ) - 4 * η * (n) := by
      nlinarith [sq_nonneg (((n - e : ℕ) : ℝ)
        - 4 * η * (n) - k),
        sq_nonneg (((n - e : ℕ) : ℝ)
        - 4 * η * (n) + k)]
    linarith
  have hs4 : k + 4 ≤ n - e := by
    have h1 : (k : ℝ) + 4 ≤ ((n - e : ℕ) : ℝ) := by nlinarith
    exact_mod_cast h1
  set s : ℕ := n - e - k with hsdef
  have hs1 : 4 ≤ s := by omega
  have hsR : (s : ℝ) = ((n - e : ℕ) : ℝ) - k := by
    rw [hsdef]
    push_cast [Nat.cast_sub (by omega : k ≤ n - e)]
    ring
  have hs0 : (0 : ℝ) < (s : ℝ) := by
    have : (4 : ℝ) ≤ (s : ℝ) := by exact_mod_cast hs1
    linarith
  -- The real bounds on the weighted threshold.
  have hY0 : (0 : ℝ) ≤ 3 * (n : ℝ) / (4 * k * η) := by positivity
  have hZ0 : (0 : ℝ) ≤ (n : ℝ) / (k * η ^ 2) := by positivity
  have hdY0 : (0 : ℝ) ≤ (dY : ℝ) := Nat.cast_nonneg _
  have hdZ0 : (0 : ℝ) ≤ (dZ : ℝ) := Nat.cast_nonneg _
  have hYZ : (dY : ℝ) * dZ ≤ 3 * (n : ℝ) / (4 * k * η)
        * ((n : ℝ) / (k * η ^ 2)) :=
    mul_le_mul hdYreal hdZreal hdZ0 hY0
  have hCap : ((4 * k * (dY * dZ) + dY : ℕ) : ℝ) ≤
      4 * k * (3 * (n : ℝ) / (4 * k * η)
        * ((n : ℝ) / (k * η ^ 2))) + 3 * (n : ℝ) / (4 * k * η) := by
    push_cast
    have hk : (0 : ℝ) ≤ 4 * k := by positivity
    exact add_le_add (mul_le_mul_of_nonneg_left hYZ hk) hdYreal
  -- The real threshold dominates the exact natural weighted threshold.
  have hSnat : dY * (e + 2) + (n - k) * (4 * k * (dY * dZ) + dY) / s +
      dZ + 3 * (dY * dZ) < cS := by
    have hchain : ((dY * (e + 2) + (n - k) * (4 * k * (dY * dZ) + dY) / s +
          dZ + 3 * (dY * dZ) : ℕ) : ℝ) + 1
        ≤ johnsonThreshold k (n) e η := by
      have hbase : (dY : ℝ) * ((e : ℝ) + 2) ≤
          (3 * (n : ℝ) / (4 * k * η)) * ((e : ℝ) + 2) :=
        mul_le_mul_of_nonneg_right hdYreal (by positivity)
      have hdiv : ((((n - k) * (4 * k * (dY * dZ) + dY)) / s : ℕ) : ℝ) ≤
          ((n - k : ℕ) : ℝ) * (4 * k * (3 * (n : ℝ) / (4 * k * η)
            * ((n : ℝ) / (k * η ^ 2))) + 3 * (n : ℝ) / (4 * k * η)) /
              (s : ℝ) := by
        calc ((((n - k) * (4 * k * (dY * dZ) + dY)) / s : ℕ) : ℝ)
            ≤ ((((n - k) * (4 * k * (dY * dZ) + dY) : ℕ) : ℝ) / (s : ℝ)) :=
              Nat.cast_div_le
          _ ≤ ((n - k : ℕ) : ℝ) * (4 * k * (3 * (n : ℝ) / (4 * k * η)
              * ((n : ℝ) / (k * η ^ 2))) + 3 * (n : ℝ) / (4 * k * η)) /
                (s : ℝ) := by
            push_cast
            gcongr
      have htail : (dZ : ℝ) + 3 * ((dY : ℝ) * dZ) ≤
          (n : ℝ) / (k * η ^ 2) + 3 * (3 * (n : ℝ) / (4 * k * η)
            * ((n : ℝ) / (k * η ^ 2))) := by linarith
      rw [johnsonThreshold]
      push_cast
      rw [← hsdef]
      linarith
    have h7 : ((dY * (e + 2) + (n - k) * (4 * k * (dY * dZ) + dY) / s +
        dZ + 3 * (dY * dZ) : ℕ) : ℝ) < (cS : ℝ) := by
      linarith
    exact_mod_cast h7
  -- Conclude.
  have hroot : D < m * (n - e) := hDlt
  exact ⟨m, D, dY, dZ, hkdY, hcnt, hroot, by omega, by simpa [hsdef] using hSnat⟩

set_option maxHeartbeats 1600000 in
/-- **The Johnson-regime correlated agreement theorem, complete.**

Hypotheses:
* `hclose` — for every `z ∈ S` the line point `u₀ + z·u₁` is within distance `e` of
  the degree-`k` Reed–Solomon code (the theorem's premise);
* the Johnson condition `hJ` : `k·n ≤ (n - e - 4ηn)²`, i.e.
  `n - e ≥ √(k·n) + 4ηn`, in `√`-free squared form, with the regularity conditions
  `η ≤ 1/4`, `ηn ≥ 1`, `4ηn ≤ n - e`;
* `hS` — `|S|` exceeds the explicit threshold, of size `O_ρ(n/η³)`.

Conclusion: one pair `(v₀, v₁)` of degree-`≤ k` polynomials achieving **correlated
agreement** (at most `e` coordinates of pair-disagreement) and **mutual correlated
agreement** in Haböck's sense.  Nothing is assumed: Guruswami–Sudan interpolation,
branch selection, the inseparable case, and the finite-jet argument are all proved. -/
theorem correlatedAgreement_johnson_final
    (dom : ι → F) (hdom : Function.Injective dom) (u₀ u₁ : ι → F) (k e : ℕ) (η : ℝ)
    (S : Finset F)
    (hclose : ∀ z ∈ S, ∃ p : F[X], p.natDegree ≤ k ∧
      (disagree (fun x => u₀ x + z * u₁ x) (RSeval dom p)).card ≤ e)
    (hk1 : 1 ≤ k) (hη : 0 < η) (hη4 : η ≤ 1/4)
    (hηn : 1 ≤ η * (Fintype.card ι))
    (ht4 : 4 * η * (Fintype.card ι) ≤ ((Fintype.card ι - e : ℕ) : ℝ))
    (hJ : (k : ℝ) * (Fintype.card ι)
        ≤ (((Fintype.card ι - e : ℕ) : ℝ) - 4 * η * (Fintype.card ι)) ^ 2)
    (hS : johnsonThreshold k (Fintype.card ι) e η ≤ (S.card : ℝ)) :
    ∃ v₀ v₁ : F[X], v₀.degree ≤ (k : ℕ) ∧ v₁.degree ≤ (k : ℕ) ∧
      (pairDisagree u₀ u₁ (RSeval dom v₀) (RSeval dom v₁)).card ≤ e ∧
      (∀ S₂ : Finset F, e + 1 < S₂.card →
        (∀ z ∈ S₂, (disagree (fun x => u₀ x + z * u₁ x)
            (fun x => (v₀ + C z * v₁).eval (dom x))).card ≤ e) →
        (S₂.filter fun z =>
          lineAgree u₀ u₁ (RSeval dom v₀) (RSeval dom v₁) z
            ≠ corrAgree u₀ u₁ (RSeval dom v₀) (RSeval dom v₁)).card ≤ e) := by
  obtain ⟨m, D, dY, dZ, hkdY, hcnt, hroot, hslack, hSnat⟩ :=
    johnson_numeric k (Fintype.card ι) e S.card η
      hk1 hη hη4 hηn ht4 hJ hS
  exact correlatedAgreement_unconditional_sharp_noFieldSize dom hdom u₀ u₁ k e hk1
    S hclose m D dY dZ hkdY hcnt hroot hslack hSnat

end Final


/-! ### The `η³` magnitude of the threshold -/

set_option maxHeartbeats 1600000 in
/-- **The threshold is `O_ρ(n/η³)`.**

For rate bounded below (`ρ·n ≤ k`) and Johnson slack bounded below
(`σ·n ≤ n - e - k`), the explicit threshold of `correlatedAgreement_johnson_final`
is at most `13·n/(ρ²·σ·η³)`.

The weighted factor selection sums the exact fiber capacities before choosing a
factor.  This removes the extra worst-case `dY` multiplier from uniform bucketing;
the mutual statement costs nothing beyond it. -/
theorem johnsonThreshold_le (k n e : ℕ) (η ρ σ : ℝ)
    (hρ0 : 0 < ρ) (hσ0 : 0 < σ)
    (hρ : ρ * n ≤ k) (hσ : σ * n ≤ ((n - e - k : ℕ) : ℝ))
    (hη : 0 < η) (hη4 : η ≤ 1 / 4) (hn1 : 1 ≤ (n : ℝ)) (hk1 : 1 ≤ k)
    (hkn : k ≤ n) :
    johnsonThreshold k n e η ≤ 13 * n / (ρ ^ 2 * σ * η ^ 3) := by
  have hK1 : (1 : ℝ) ≤ (k : ℝ) := by exact_mod_cast hk1
  have hK0 : (0 : ℝ) < (k : ℝ) := by linarith
  have hN0 : (0 : ℝ) < (n : ℝ) := by linarith
  have hKN : (k : ℝ) ≤ (n : ℝ) := by exact_mod_cast hkn
  have hρ1 : ρ ≤ 1 := by nlinarith
  have hsN : ((n - e - k : ℕ) : ℝ) ≤ (n : ℝ) := by
    have : (n - e - k : ℕ) ≤ n := by omega
    exact_mod_cast this
  have hσ1 : σ ≤ 1 := by nlinarith
  have hs0 : (0 : ℝ) < ((n - e - k : ℕ) : ℝ) := lt_of_lt_of_le (by positivity) hσ
  have hη1 : η ≤ 1 := by linarith
  have hρη1 : ρ * η ≤ 1 := by nlinarith
  -- Names for the pieces.
  set Y : ℝ := 3 * n / (4 * k * η) with hYdef
  set Z : ℝ := (n : ℝ) / (k * η ^ 2) with hZdef
  have hY0 : 0 ≤ Y := by rw [hYdef]; positivity
  have hZ0 : 0 ≤ Z := by rw [hZdef]; positivity
  -- Elementary bounds.
  have hY : Y ≤ 1 / (ρ * η) := by
    rw [hYdef, div_le_div_iff₀ (by positivity) (by positivity)]
    nlinarith
  have hZ : Z ≤ 1 / (ρ * η ^ 2) := by
    rw [hZdef, div_le_div_iff₀ (by positivity) (by positivity)]
    have hη2 : (0 : ℝ) < η ^ 2 := by positivity
    nlinarith
  have hYZ : Y * Z ≤ 1 / (ρ ^ 2 * η ^ 3) := by
    have h1 : Y * Z ≤ (1 / (ρ * η)) * (1 / (ρ * η ^ 2)) :=
      mul_le_mul hY hZ hZ0 (by positivity)
    have h2 : (1 / (ρ * η)) * (1 / (ρ * η ^ 2)) = 1 / (ρ ^ 2 * η ^ 3) := by
      field_simp
    linarith
  -- The weighted incidence factor.
  have hG : 4 * (k : ℝ) * (Y * Z) + Y ≤ 5 * n / (ρ ^ 2 * η ^ 3) := by
    have h1 : 4 * (k : ℝ) * (Y * Z) ≤ 4 * n / (ρ ^ 2 * η ^ 3) := by
      have h2 : 4 * (k : ℝ) ≤ 4 * n := by nlinarith
      have h3 := mul_le_mul h2 hYZ (by positivity) (by positivity)
      calc 4 * (k : ℝ) * (Y * Z)
          ≤ (4 * n) * (1 / (ρ ^ 2 * η ^ 3)) := h3
        _ = 4 * n / (ρ ^ 2 * η ^ 3) := by ring
    have h4 : Y ≤ (n : ℝ) / (ρ ^ 2 * η ^ 3) := by
      refine le_trans hY ?_
      rw [div_le_div_iff₀ (by positivity) (by positivity)]
      have hρη2 : ρ * η ^ 2 ≤ 1 := by nlinarith [sq_nonneg η]
      calc 1 * (ρ ^ 2 * η ^ 3) = (ρ * η) * (ρ * η ^ 2) := by ring
        _ ≤ (ρ * η) * 1 := by
            exact mul_le_mul_of_nonneg_left hρη2 (by positivity)
        _ = ρ * η := by ring
        _ ≤ (n : ℝ) * (ρ * η) := le_mul_of_one_le_left (by positivity) hn1
    calc 4 * (k : ℝ) * (Y * Z) + Y
        ≤ 4 * n / (ρ ^ 2 * η ^ 3) + n / (ρ ^ 2 * η ^ 3) := add_le_add h1 h4
      _ = 5 * n / (ρ ^ 2 * η ^ 3) := by ring
  have hnk : ((n - k : ℕ) : ℝ) ≤ (n : ℝ) := by
    exact_mod_cast Nat.sub_le n k
  have hInc : ((n - k : ℕ) : ℝ) * (4 * (k : ℝ) * (Y * Z) + Y) /
      ((n - e - k : ℕ) : ℝ) ≤ 5 * n / (ρ ^ 2 * σ * η ^ 3) := by
    calc ((n - k : ℕ) : ℝ) * (4 * (k : ℝ) * (Y * Z) + Y) /
          ((n - e - k : ℕ) : ℝ)
        ≤ (n : ℝ) * (4 * (k : ℝ) * (Y * Z) + Y) / (σ * n) := by
            gcongr
      _ ≤ (n : ℝ) * (5 * n / (ρ ^ 2 * η ^ 3)) / (σ * n) := by gcongr
      _ = 5 * n / (ρ ^ 2 * σ * η ^ 3) := by field_simp
  have heN : (e : ℝ) + 2 ≤ 3 * n := by
    have he : e ≤ n := by
      apply Nat.le_of_not_lt
      intro hc
      have : (n - e - k : ℕ) = 0 := by omega
      rw [this] at hs0
      norm_num at hs0
    have := show (e : ℝ) ≤ n by exact_mod_cast he
    nlinarith
  have hsmallY : ρ * σ * η ^ 2 ≤ 1 :=
    mul_le_one₀ (mul_le_one₀ hρ1 hσ0.le hσ1)
      (by positivity) (pow_le_one₀ hη.le hη1)
  have hYwide : Y ≤ 1 / (ρ ^ 2 * σ * η ^ 3) := by
    refine le_trans hY ?_
    rw [div_le_div_iff₀ (by positivity) (by positivity)]
    calc 1 * (ρ ^ 2 * σ * η ^ 3) = (ρ * η) * (ρ * σ * η ^ 2) := by ring
      _ ≤ (ρ * η) * 1 := mul_le_mul_of_nonneg_left hsmallY (by positivity)
      _ = 1 * (ρ * η) := by ring
  have hBase : Y * ((e : ℝ) + 2) ≤ 3 * n / (ρ ^ 2 * σ * η ^ 3) := by
    calc Y * ((e : ℝ) + 2)
        ≤ (1 / (ρ ^ 2 * σ * η ^ 3)) * (3 * n) :=
          mul_le_mul hYwide heN (by positivity) (by positivity)
      _ = 3 * n / (ρ ^ 2 * σ * η ^ 3) := by ring
  have hsmallZ : ρ * σ * η ≤ 1 :=
    mul_le_one₀ (mul_le_one₀ hρ1 hσ0.le hσ1) hη.le hη1
  have hZwide : Z ≤ (n : ℝ) / (ρ ^ 2 * σ * η ^ 3) := by
    refine le_trans hZ ?_
    rw [div_le_div_iff₀ (by positivity) (by positivity)]
    calc 1 * (ρ ^ 2 * σ * η ^ 3) = (ρ * η ^ 2) * (ρ * σ * η) := by ring
      _ ≤ (ρ * η ^ 2) * 1 := mul_le_mul_of_nonneg_left hsmallZ (by positivity)
      _ = 1 * (ρ * η ^ 2) := by ring
      _ ≤ (n : ℝ) * (ρ * η ^ 2) := mul_le_mul_of_nonneg_right hn1 (by positivity)
  have hYZwide : 3 * (Y * Z) ≤ 3 * n / (ρ ^ 2 * σ * η ^ 3) := by
    have h1 : Y * Z ≤ (n : ℝ) / (ρ ^ 2 * σ * η ^ 3) := by
      refine le_trans hYZ ?_
      rw [div_le_div_iff₀ (by positivity) (by positivity)]
      calc 1 * (ρ ^ 2 * σ * η ^ 3) = σ * (ρ ^ 2 * η ^ 3) := by ring
        _ ≤ 1 * (ρ ^ 2 * η ^ 3) :=
          mul_le_mul_of_nonneg_right hσ1 (by positivity)
        _ ≤ (n : ℝ) * (ρ ^ 2 * η ^ 3) :=
          mul_le_mul_of_nonneg_right hn1 (by positivity)
    calc 3 * (Y * Z) ≤ 3 * (n / (ρ ^ 2 * σ * η ^ 3)) :=
          mul_le_mul_of_nonneg_left h1 (by norm_num)
      _ = 3 * n / (ρ ^ 2 * σ * η ^ 3) := by ring
  have hone : (1 : ℝ) ≤ (n : ℝ) / (ρ ^ 2 * σ * η ^ 3) := by
    rw [le_div_iff₀ (by positivity)]
    have hsmall : ρ ^ 2 * σ * η ^ 3 ≤ 1 :=
      mul_le_one₀ (mul_le_one₀ (pow_le_one₀ hρ0.le hρ1) hσ0.le hσ1)
        (by positivity) (pow_le_one₀ hη.le hη1)
    linarith
  rw [johnsonThreshold, ← hYdef, ← hZdef]
  have hsum : 3 * (n : ℝ) / (ρ ^ 2 * σ * η ^ 3) +
      5 * n / (ρ ^ 2 * σ * η ^ 3) + n / (ρ ^ 2 * σ * η ^ 3) +
      3 * n / (ρ ^ 2 * σ * η ^ 3) + n / (ρ ^ 2 * σ * η ^ 3) =
        13 * n / (ρ ^ 2 * σ * η ^ 3) := by ring
  linarith


end JBAgreement
