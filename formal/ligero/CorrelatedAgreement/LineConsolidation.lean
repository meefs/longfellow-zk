import CorrelatedAgreement.LineExtraction
import CorrelatedAgreement.Basic
import Mathlib.Tactic.Abel

/-! Candidate-line consolidation to one common error support. -/

namespace CorrelatedAgreement

open AffineAgreement

variable {F : Type*} [Field F] [DecidableEq F]

namespace Internal

/-- A sufficiently populated affine codeword line, together with the exact
two-radius threshold, yields a common radius-`h` explanation. -/
theorem correlated_of_large_affineCodewordLine {n e h d b m : ℕ}
    {C : LinearCode F n} {u v : Word F n}
    (D : DecoderData (e := e) (m := m) C u v)
    (hmin : HasMinimumDistanceAtLeast C d)
    (hS : D.parameters.card = m) (heh : e ≤ h)
    (hb : 3 ≤ b) (B : AffineCodewordLine D)
    (hB : b ≤ (B.followingParameters D).card)
    (hm : m = selectedDecoderCount e h d)
    (hNumeric : 4 * d > n + 5 * e + 2 * (e / (b - 1))) :
    Correlated (e := h) C u v := by
  let S := D.parameters
  let x := u - B.base
  let y := v - B.direction
  let J := jointSupport x y
  let L := nontrivialSupportLowerBound e h d
  let R := nontrivialLineOccupancyBound e h d
  have heL : e < L := by
    dsimp [L, nontrivialSupportLowerBound]
    omega
  have hRpos : 1 ≤ R := by
    dsimp [R, nontrivialLineOccupancyBound]
    exact (Nat.le_div_iff_mul_le (Nat.sub_pos_of_lt heL)).2 (by omega)
  have hlineWeight (t : F) (ht : t ∈ B.followingParameters D) :
      weight (affineWord x y t) ≤ e := by
    have hnear := D.error_card (B.followingParameters_subset D ht)
    have hdec := B.selectedDecoding_eq D ht
    rw [affineWord_sub u v B.base B.direction t, ← hdec]
    exact hnear
  have hBtwo : 2 ≤ (B.followingParameters D).card := by omega
  have hJraw := jointSupport_card_le x y (B.followingParameters D) hBtwo hlineWeight
  have hden : b - 1 ≤ (B.followingParameters D).card - 1 := by omega
  have hdenPos : 0 < b - 1 := by omega
  have hdiv : e / ((B.followingParameters D).card - 1) ≤ e / (b - 1) :=
    Nat.div_le_div_left hden hdenPos
  have hJupper : J.card ≤ e + e / (b - 1) := by
    dsimp [J]
    omega
  by_cases hJh : J.card ≤ h
  · refine ⟨B.base, B.direction, B.base_mem, B.direction_mem, ?_⟩
    simpa [J, x, y]
  have hJlower : h + 1 ≤ J.card := by omega
  let p : F → Word F n := fun t ↦ D.codeword t - affineWord B.base B.direction t
  have hcodewordMem (t : F) : D.codeword t ∈ C := by
    by_cases ht : t ∈ D.parameters
    · exact D.codeword_mem ht
    · simp [DecoderData.codeword, ht]
  have hpMem (t : F) : p t ∈ C :=
    C.sub_mem (hcodewordMem t)
      (C.add_mem B.base_mem (C.smul_mem t B.direction_mem))
  have hresidual (t : F) :
      affineWord x y t - p t = affineWord u v t - D.codeword t := by
    dsimp [x, y, p]
    funext i
    simp [affineWord]
    ring
  have hpError (t : F) (ht : t ∈ S) :
      weight (affineWord x y t - p t) ≤ e := by
    rw [hresidual]
    exact D.error_card ht
  let Z := S.filter fun t ↦ p t = 0
  let N := S.filter fun t ↦ p t ≠ 0
  have hpartition : Z.card + N.card = S.card := by
    simpa [Z, N] using Finset.card_filter_add_card_filter_not
      (s := S) (fun t ↦ p t = 0)
  have hBZ : B.followingParameters D ⊆ Z := by
    intro t ht
    have htS := B.followingParameters_subset D ht
    have htEq := B.selectedDecoding_eq D ht
    exact Finset.mem_filter.mpr ⟨htS, by simp [p, htEq]⟩
  have hZthree : 3 ≤ Z.card :=
    hb.trans (hB.trans (Finset.card_le_card hBZ))
  have hzeroWeight (t : F) (ht : t ∈ Z) :
      weight (affineWord x y t) ≤ e := by
    have htS := (Finset.mem_filter.mp ht).1
    have ht0 := (Finset.mem_filter.mp ht).2
    simpa [ht0] using hpError t htS
  by_cases hNempty : N = ∅
  · have hZcard : Z.card = m := by
      have : S.card = m := by simpa [S] using hS
      simp [hNempty] at hpartition
      omega
    have hZbound := affineLine_card_le_of_support_lower x y Z
      (by omega) (by omega : e < h + 1) hJlower hzeroWeight
    have hQle : (h + 1) / (h + 1 - e) ≤ agreementBound e h d :=
      Nat.le_max_left _ _
    rw [hZcard, hm] at hZbound
    dsimp [directLineOccupancyBound, selectedDecoderCount] at hZbound
    omega
  have hNnonempty : N.Nonempty := Finset.nonempty_iff_ne_empty.mpr hNempty
  obtain ⟨t₀, ht₀N⟩ := hNnonempty
  have ht₀S := (Finset.mem_filter.mp ht₀N).1
  have ht₀p : p t₀ ≠ 0 := (Finset.mem_filter.mp ht₀N).2
  have hdJ : d - e ≤ J.card := by
    have := distance_le_active_add_error hmin x y (p t₀) t₀
      (hpMem t₀) ht₀p (hpError t₀ ht₀S)
    exact Nat.sub_le_iff_le_add.mpr (by simpa [Nat.add_comm] using this)
  have hLJ : L ≤ J.card := by
    dsimp [L, nontrivialSupportLowerBound]
    exact max_le hJlower hdJ
  have hZbound : Z.card ≤ R := by
    have hz := affineLine_card_le_of_support_lower x y Z
      (by omega) heL hLJ hzeroWeight
    simpa [R, nontrivialLineOccupancyBound, L] using hz
  by_cases hNone : N.card ≤ 1
  · have hScard : S.card = m := by simpa [S] using hS
    have hmle : m ≤ 2 * R := by
      rw [hScard] at hpartition
      omega
    rw [hm] at hmle
    dsimp [selectedDecoderCount] at hmle
    have hRle : 2 * R ≤ agreementBound e h d := Nat.le_max_right _ _
    omega
  have hNtwo : 1 < N.card := by omega
  have hNFintype : 1 < Fintype.card N := by simpa using hNtwo
  obtain ⟨a, c, hac⟩ := Fintype.one_lt_card_iff.mp hNFintype
  have haN : a.1 ∈ N := a.2
  have hcN : c.1 ∈ N := c.2
  have hlocal (t : F) (ht : t ∈ N) :
      (supportOn J (affineWord x y t - p t)).card ≤ J.card + e - d := by
    exact residual_inside_error_bound hmin x y (p t) t
      (hpMem t) (Finset.mem_filter.mp ht).2
      (hpError t (Finset.mem_filter.mp ht).1)
  let localRadius := J.card + e - d
  have hRigidity : n + 3 * localRadius < d + J.card := by
    dsimp [localRadius]
    omega
  let p₁ : Word F n := fun i ↦ (c.1 - a.1)⁻¹ * (p c.1 i - p a.1 i)
  let p₀ : Word F n := p a.1 - fun i ↦ a.1 * p₁ i
  have hp₁Mem : p₁ ∈ C := by
    dsimp [p₁]
    exact C.smul_mem _ (C.sub_mem (hpMem c.1) (hpMem a.1))
  have hp₀Mem : p₀ ∈ C := by
    dsimp [p₀]
    exact C.sub_mem (hpMem a.1) (C.smul_mem _ hp₁Mem)
  have hline (t : F) (ht : t ∈ N) : affineWord p₀ p₁ t = p t := by
    exact third_decoder_on_secant hmin J x y p hpMem a.1 c.1 t
      (fun h ↦ hac (Subtype.ext h))
      (hlocal a.1 haN) (hlocal c.1 hcN) (hlocal t ht) hRigidity
  let x' := x - p₀
  let y' := y - p₁
  let K := jointSupport x' y'
  have hfinalWeight (t : F) (ht : t ∈ N) :
      weight (affineWord x' y' t) ≤ e := by
    have herr := hpError t (Finset.mem_filter.mp ht).1
    rw [← hline t ht] at herr
    simpa [x', y', affineWord_sub] using herr
  by_cases hKh : K.card ≤ h
  · refine ⟨B.base + p₀, B.direction + p₁,
      C.add_mem B.base_mem hp₀Mem, C.add_mem B.direction_mem hp₁Mem, ?_⟩
    have hx : u - (B.base + p₀) = x' := by
      dsimp [x', x]
      abel
    have hy : v - (B.direction + p₁) = y' := by
      dsimp [y', y]
      abel
    simpa [K, hx, hy]
  have hKlower : h + 1 ≤ K.card := by omega
  have hZFintype : 1 < Fintype.card Z := by simpa using (show 1 < Z.card by omega)
  obtain ⟨z₁, z₂, hzneq⟩ := Fintype.one_lt_card_iff.mp hZFintype
  have hz₁ : z₁.1 ∈ Z := z₁.2
  have hz₂ : z₂.1 ∈ Z := z₂.2
  have hpLineNonzero :
      affineWord p₀ p₁ z₁.1 ≠ 0 ∨ affineWord p₀ p₁ z₂.1 ≠ 0 := by
    by_contra hall
    push Not at hall
    have hp₁zero : p₁ = 0 := by
      funext i
      have h₁ := congrFun hall.1 i
      have h₂ := congrFun hall.2 i
      simp only [affineWord_apply, Pi.zero_apply] at h₁ h₂
      have hmul : (z₂.1 - z₁.1) * p₁ i = 0 := by
        calc
          (z₂.1 - z₁.1) * p₁ i =
              (p₀ i + z₂.1 * p₁ i) - (p₀ i + z₁.1 * p₁ i) := by ring
          _ = 0 := by rw [h₂, h₁, sub_self]
      exact (mul_eq_zero.mp hmul).resolve_left
        (sub_ne_zero.mpr (fun h ↦ hzneq (Subtype.ext h.symm)))
    have hp₀zero : p₀ = 0 := by
      funext i
      have h₁ := congrFun hall.1 i
      simp [affineWord, hp₁zero] at h₁
      exact h₁
    have hpa0 : p a.1 = 0 := by
      rw [← hline a.1 haN, hp₀zero, hp₁zero]
      funext i
      simp [affineWord]
    exact (Finset.mem_filter.mp haN).2 hpa0
  obtain ⟨z, hzZ, hpz⟩ :
      ∃ z ∈ Z, affineWord p₀ p₁ z ≠ 0 := by
    rcases hpLineNonzero with hz | hz
    · exact ⟨z₁.1, hz₁, hz⟩
    · exact ⟨z₂.1, hz₂, hz⟩
  have hpLineMem : -(affineWord p₀ p₁ z) ∈ C :=
    C.neg_mem (C.add_mem hp₀Mem (C.smul_mem z hp₁Mem))
  have holdAsError :
      affineWord x' y' z - (-(affineWord p₀ p₁ z)) = affineWord x y z := by
    dsimp [x', y']
    funext i
    simp [affineWord]
    ring
  have hdK : d - e ≤ K.card := by
    have hdist := distance_le_active_add_error hmin x' y'
      (-(affineWord p₀ p₁ z)) z hpLineMem (neg_ne_zero.mpr hpz)
      (by simpa [holdAsError] using hzeroWeight z hzZ)
    have hsub : d - e ≤ (jointSupport x' y').card :=
      Nat.sub_le_iff_le_add.mpr (by simpa [Nat.add_comm] using hdist)
    simpa [K] using hsub
  have hLK : L ≤ K.card := by
    dsimp [L, nontrivialSupportLowerBound]
    exact max_le hKlower hdK
  have hNbound : N.card ≤ R := by
    have hn := affineLine_card_le_of_support_lower x' y' N
      (by omega) heL hLK hfinalWeight
    simpa [R, nontrivialLineOccupancyBound, L] using hn
  have hScard : S.card = m := by simpa [S] using hS
  have hmle : m ≤ 2 * R := by
    rw [hScard] at hpartition
    omega
  rw [hm] at hmle
  dsimp [selectedDecoderCount] at hmle
  have hRle : 2 * R ≤ agreementBound e h d := Nat.le_max_right _ _
  omega

end Internal

end CorrelatedAgreement
