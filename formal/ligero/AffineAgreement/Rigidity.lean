import AffineAgreement.AffineSupport
import Mathlib.Tactic.FieldSimp

/-!
# Residual rigidity for affine word lines

This module contains the distance-rigidity geometry used by the arbitrary-code
CA proof. It is independent of affine codeword-line extraction and the
triple-counting engine.
-/

namespace AffineAgreement

variable {F : Type*} [Field F] [DecidableEq F]

namespace Internal

/-- A nonzero codeword within radius `e` of an affine line is supported by
the active coordinates of that line together with at most `e` errors. -/
theorem distance_le_active_add_error {n e d : ℕ}
    {C : LinearCode F n} (hmin : HasMinimumDistanceAtLeast C d)
    (x y p : Word F n) (a : F) (hp : p ∈ C) (hp0 : p ≠ 0)
    (herror : weight (affineWord x y a - p) ≤ e) :
    d ≤ (jointSupport x y).card + e := by
  let J := jointSupport x y
  have hpweight : d ≤ weight p := hmin.weight_ge_distance p hp hp0
  have hsupp : supportOn Finset.univ p ⊆
      J ∪ supportOn Finset.univ (affineWord x y a - p) := by
    intro i hi
    by_cases hiJ : i ∈ J
    · exact Finset.mem_union_left _ hiJ
    · apply Finset.mem_union_right _
      have hx : x i = 0 := by
        exact not_ne_iff.mp fun hne ↦ hiJ <|
          Finset.mem_union_left _
            ((mem_supportOn Finset.univ x i).mpr ⟨Finset.mem_univ i, hne⟩)
      have hy : y i = 0 := by
        exact not_ne_iff.mp fun hne ↦ hiJ <|
          Finset.mem_union_right _
            ((mem_supportOn Finset.univ y i).mpr ⟨Finset.mem_univ i, hne⟩)
      have hpne : p i ≠ 0 := (mem_supportOn Finset.univ p i).mp hi |>.2
      apply (mem_supportOn Finset.univ (affineWord x y a - p) i).mpr
      refine ⟨Finset.mem_univ i, ?_⟩
      simp [affineWord, hx, hy, hpne]
  have hcard := Finset.card_le_card hsupp
  have hunion := Finset.card_union_le J
    (supportOn Finset.univ (affineWord x y a - p))
  change d ≤ J.card + e
  calc
    d ≤ weight p := hpweight
    _ ≤ (J ∪ supportOn Finset.univ (affineWord x y a - p)).card := hcard
    _ ≤ J.card + weight (affineWord x y a - p) := hunion
    _ ≤ J.card + e := Nat.add_le_add_left herror _

omit [DecidableEq F] in
theorem received_secant {n : ℕ} (u v : Word F n) (a b c : F)
    (hab : a ≠ b) :
    affineWord u v c =
      affineWord
        (affineWord u v a - fun i ↦
          a * ((b - a)⁻¹ *
            (affineWord u v b i - affineWord u v a i)))
        (fun i ↦ (b - a)⁻¹ *
          (affineWord u v b i - affineWord u v a i)) c := by
  funext i
  simp only [affineWord, Pi.sub_apply]
  field_simp [sub_ne_zero.mpr hab.symm]
  ring

private theorem support_partition {n : ℕ} (J : Finset (Fin n))
    (w : Word F n) :
    supportOn Finset.univ w =
      supportOn J w ∪ supportOn (Finset.univ \ J) w := by
  ext i
  by_cases hi : i ∈ J <;> simp [supportOn, hi]

private theorem support_partition_card {n : ℕ} (J : Finset (Fin n))
    (w : Word F n) :
    weight w = (supportOn J w).card +
      (supportOn (Finset.univ \ J) w).card := by
  rw [weight, support_partition J w]
  rw [Finset.card_union_of_disjoint]
  exact Finset.disjoint_left.mpr (by
    intro i hiJ hiC
    exact (Finset.mem_sdiff.mp (mem_supportOn _ w i |>.mp hiC).1).2
      (mem_supportOn J w i |>.mp hiJ).1)

private theorem outside_error_eq_codeword {n : ℕ}
    (x y p : Word F n) (t : F) :
    supportOn (Finset.univ \ jointSupport x y) (affineWord x y t - p) =
      supportOn (Finset.univ \ jointSupport x y) p := by
  ext i
  simp only [mem_supportOn, Finset.mem_sdiff, Finset.mem_univ, true_and]
  have hzero (hi : i ∉ jointSupport x y) : affineWord x y t i = 0 := by
    have hx : x i = 0 := by
      exact not_ne_iff.mp fun hx ↦
        hi (Finset.mem_union_left _ (mem_supportOn Finset.univ x i |>.mpr
          ⟨Finset.mem_univ i, hx⟩))
    have hy : y i = 0 := by
      exact not_ne_iff.mp fun hy ↦
        hi (Finset.mem_union_right _ (mem_supportOn Finset.univ y i |>.mpr
          ⟨Finset.mem_univ i, hy⟩))
    simp [affineWord, hx, hy]
  constructor
  · rintro ⟨hi, herr⟩
    refine ⟨hi, ?_⟩
    change affineWord x y t i - p i ≠ 0 at herr
    rw [hzero hi, zero_sub] at herr
    exact neg_ne_zero.mp herr
  · rintro ⟨hi, hp⟩
    refine ⟨hi, ?_⟩
    change affineWord x y t i - p i ≠ 0
    rw [hzero hi, zero_sub]
    exact neg_ne_zero.mpr hp

/-- A nonzero residual codeword has at most radius `|J|+e-d` inside the
active support `J`. -/
theorem residual_inside_error_bound {n e d : ℕ}
    {C : LinearCode F n} (hmin : HasMinimumDistanceAtLeast C d)
    (x y p : Word F n) (t : F) (hp : p ∈ C) (hp0 : p ≠ 0)
    (herror : weight (affineWord x y t - p) ≤ e) :
    (supportOn (jointSupport x y) (affineWord x y t - p)).card ≤
      (jointSupport x y).card + e - d := by
  let J := jointSupport x y
  let q := (supportOn (Finset.univ \ J) p).card
  have hpweight := hmin.weight_ge_distance p hp hp0
  have hpPart : weight p = (supportOn J p).card + q := by
    simpa [q] using support_partition_card J p
  have hpInside : (supportOn J p).card ≤ J.card :=
    Finset.card_le_card (supportOn_subset J p)
  have hqLower : d ≤ J.card + q := by
    omega
  have herrPart : weight (affineWord x y t - p) =
      (supportOn J (affineWord x y t - p)).card +
        (supportOn (Finset.univ \ J) (affineWord x y t - p)).card :=
    support_partition_card J (affineWord x y t - p)
  have houtside :
      (supportOn (Finset.univ \ J) (affineWord x y t - p)).card = q := by
    simpa [J, q] using congrArg Finset.card (outside_error_eq_codeword x y p t)
  have hinside :
      (supportOn J (affineWord x y t - p)).card + q ≤ e := by
    rw [houtside] at herrPart
    omega
  change (supportOn J (affineWord x y t - p)).card ≤ J.card + e - d
  omega

/-- Three locally close decoder points are affine-collinear once the union
of their local errors leaves more than `n-d` coordinates. -/
theorem third_decoder_on_secant {n d R : ℕ}
    {C : LinearCode F n} (hmin : HasMinimumDistanceAtLeast C d)
    (J : Finset (Fin n)) (x y : Word F n)
    (p : F → Word F n) (hp : ∀ t, p t ∈ C)
    (a b c : F) (hab : a ≠ b)
    (ha : (supportOn J (affineWord x y a - p a)).card ≤ R)
    (hb : (supportOn J (affineWord x y b - p b)).card ≤ R)
    (hc : (supportOn J (affineWord x y c - p c)).card ≤ R)
    (hnumeric : n + 3 * R < d + J.card) :
    affineWord
      (p a - fun i ↦ a * ((b - a)⁻¹ * (p b i - p a i)))
      (fun i ↦ (b - a)⁻¹ * (p b i - p a i)) c = p c := by
  let E := supportOn J (affineWord x y a - p a) ∪
    supportOn J (affineWord x y b - p b) ∪
    supportOn J (affineWord x y c - p c)
  let I := J \ E
  have hEsub : E ⊆ J := by
    exact Finset.union_subset
      (Finset.union_subset (supportOn_subset _ _) (supportOn_subset _ _))
      (supportOn_subset _ _)
  have hEcard : E.card ≤ 3 * R := by
    dsimp [E]
    have hu₁ := Finset.card_union_le
      (supportOn J (affineWord x y a - p a))
      (supportOn J (affineWord x y b - p b))
    have hu₂ := Finset.card_union_le
      (supportOn J (affineWord x y a - p a) ∪
        supportOn J (affineWord x y b - p b))
      (supportOn J (affineWord x y c - p c))
    calc
      _ ≤ (supportOn J (affineWord x y a - p a)).card +
          (supportOn J (affineWord x y b - p b)).card +
          (supportOn J (affineWord x y c - p c)).card := by omega
      _ ≤ 3 * R := by omega
  have hIcard : n - d < I.card := by
    dsimp [I]
    rw [Finset.card_sdiff, Finset.inter_eq_left.mpr hEsub]
    have hdn := hmin.distance_le_length
    have hEJ : E.card ≤ J.card := Finset.card_le_card hEsub
    omega
  let p₁ : Word F n := fun i ↦ (b - a)⁻¹ * (p b i - p a i)
  let p₀ : Word F n := p a - fun i ↦ a * p₁ i
  have hp₁ : p₁ ∈ C := by
    dsimp [p₁]
    exact C.smul_mem _ (C.sub_mem (hp b) (hp a))
  have hp₀ : p₀ ∈ C := by
    dsimp [p₀]
    exact C.sub_mem (hp a) (C.smul_mem _ hp₁)
  apply eq_of_agree_on hmin (C.add_mem hp₀ (C.smul_mem c hp₁))
    (hp c) I hIcard
  intro i hiI
  have hiJ : i ∈ J := (Finset.mem_sdiff.mp hiI).1
  have hiE : i ∉ E := (Finset.mem_sdiff.mp hiI).2
  have hnotA : i ∉ supportOn J (affineWord x y a - p a) :=
    fun h ↦ hiE (Finset.mem_union_left _ (Finset.mem_union_left _ h))
  have hnotB : i ∉ supportOn J (affineWord x y b - p b) :=
    fun h ↦ hiE (Finset.mem_union_left _ (Finset.mem_union_right _ h))
  have hnotC : i ∉ supportOn J (affineWord x y c - p c) :=
    fun h ↦ hiE (Finset.mem_union_right _ h)
  have hea : affineWord x y a i = p a i := by
    simpa [supportOn, hiJ, sub_eq_zero] using hnotA
  have heb : affineWord x y b i = p b i := by
    simpa [supportOn, hiJ, sub_eq_zero] using hnotB
  have hec : affineWord x y c i = p c i := by
    simpa [supportOn, hiJ, sub_eq_zero] using hnotC
  calc
    affineWord p₀ p₁ c i =
        affineWord
          (affineWord x y a - fun j ↦
            a * ((b - a)⁻¹ * (affineWord x y b j - affineWord x y a j)))
          (fun j ↦ (b - a)⁻¹ *
            (affineWord x y b j - affineWord x y a j)) c i := by
      simp only [p₀, p₁, affineWord, Pi.sub_apply]
      rw [← hea, ← heb]
      rfl
    _ = affineWord x y c i := congrFun (received_secant x y a b c hab).symm i
    _ = p c i := hec

end Internal

export Internal (distance_le_active_add_error received_secant
  residual_inside_error_bound third_decoder_on_secant)

end AffineAgreement
