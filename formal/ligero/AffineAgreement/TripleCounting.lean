import AffineAgreement.AffineSupport
import AffineAgreement.DecoderData
import AffineAgreement.Moments
import Mathlib.Tactic.Linarith

/-! Exact triple-intersection counting for padded decoder errors. -/

namespace AffineAgreement

open scoped BigOperators

variable {F : Type*} [Field F] [DecidableEq F]

namespace Internal

/-- A simultaneous enlargement of all actual error sets to cardinality `e`. -/
structure PaddedErrorFamily {n e m : ℕ} {C : LinearCode F n}
    {u v : Word F n} (D : DecoderData (e := e) (m := m) C u v) where
  error : F → Finset (Fin n)
  actual_subset : ∀ {a}, a ∈ D.parameters →
    supportOn Finset.univ (affineWord u v a - D.codeword a) ⊆ error a
  card_eq : ∀ {a}, a ∈ D.parameters → (error a).card = e

theorem paddedErrorFamily_nonempty {n e m : ℕ} {C : LinearCode F n}
    {u v : Word F n} (D : DecoderData (e := e) (m := m) C u v)
    (hen : e ≤ n) : Nonempty (PaddedErrorFamily (e := e) D) := by
  classical
  have hexists (a : F) (ha : a ∈ D.parameters) :
      ∃ P : Finset (Fin n),
        supportOn Finset.univ (affineWord u v a - D.codeword a) ⊆ P ∧
          P.card = e := by
    exact Finset.exists_superset_card_eq (D.error_card ha) (by simpa using hen)
  let padded (a : F) : Finset (Fin n) :=
    if ha : a ∈ D.parameters then (hexists a ha).choose else ∅
  refine ⟨{
    error := padded
    actual_subset := ?_
    card_eq := ?_ }⟩
  · intro a ha
    simpa only [padded, dif_pos ha] using (hexists a ha).choose_spec.1
  · intro a ha
    simpa only [padded, dif_pos ha] using (hexists a ha).choose_spec.2

/-- Coordinates on which every decoder indexed by `t` agrees with its word. -/
def agreementIntersection {n : ℕ} (E : F → Finset (Fin n))
    (t : Finset F) : Finset (Fin n) :=
  Finset.univ.filter fun i ↦ ∀ a ∈ t, i ∉ E a

omit [Field F] [DecidableEq F] in
@[simp] theorem mem_agreementIntersection {n : ℕ}
    (E : F → Finset (Fin n)) (t : Finset F) (i : Fin n) :
    i ∈ agreementIntersection E t ↔ ∀ a ∈ t, i ∉ E a := by
  simp [agreementIntersection]

/-- Number of padded agreement sets containing coordinate `i`.  This is the
complement-set specialization of `setMembershipDegree`. -/
def agreementDegree {n : ℕ} (S : Finset F)
    (E : F → Finset (Fin n)) (i : Fin n) : ℕ :=
  (S.filter fun a ↦ i ∉ E a).card

private theorem choose_three_add_lower (q k : ℕ) :
    q.choose 3 + k * q.choose 2 ≤ (q + k).choose 3 := by
  induction k with
  | zero => simp
  | succ k ih =>
      have hmono : q.choose 2 ≤ (q + k).choose 2 :=
        Nat.choose_mono 2 (Nat.le_add_right q k)
      have hrec : ((q + k) + 1).choose 3 =
          (q + k).choose 3 + (q + k).choose 2 := by
        simpa [add_comm] using (Nat.choose_succ_succ (q + k) 2)
      calc
        q.choose 3 + (k + 1) * q.choose 2 =
            (q.choose 3 + k * q.choose 2) + q.choose 2 := by ring
        _ ≤ (q + k).choose 3 + (q + k).choose 2 :=
          Nat.add_le_add ih hmono
        _ = ((q + k) + 1).choose 3 := hrec.symm
        _ = (q + (k + 1)).choose 3 := by simp [Nat.add_assoc]

private theorem choose_three_add_upper (h k : ℕ) :
    (h + k).choose 3 ≤ h.choose 3 + k * (h + k).choose 2 := by
  induction k with
  | zero => simp
  | succ k ih =>
      have hmono : (h + k).choose 2 ≤ (h + (k + 1)).choose 2 :=
        Nat.choose_mono 2 (by omega)
      have hmul : k * (h + k).choose 2 ≤
          k * (h + (k + 1)).choose 2 := Nat.mul_le_mul_left k hmono
      have hrec : ((h + k) + 1).choose 3 =
          (h + k).choose 3 + (h + k).choose 2 := by
        simpa [add_comm] using (Nat.choose_succ_succ (h + k) 2)
      calc
        (h + (k + 1)).choose 3 = ((h + k) + 1).choose 3 := by
          simp [Nat.add_assoc]
        _ = (h + k).choose 3 + (h + k).choose 2 := hrec
        _ ≤ (h.choose 3 + k * (h + k).choose 2) +
            (h + k).choose 2 := Nat.add_le_add_right ih _
        _ ≤ (h.choose 3 + k * (h + (k + 1)).choose 2) +
            (h + (k + 1)).choose 2 :=
          Nat.add_le_add (Nat.add_le_add_left hmul _) hmono
        _ = h.choose 3 + (k + 1) * (h + (k + 1)).choose 2 := by ring

private theorem choose_three_tangent (h q : ℕ) :
    (q.choose 3 : ℤ) + ((h : ℤ) - q) * q.choose 2 ≤ h.choose 3 := by
  by_cases hqh : q ≤ h
  · have hnat := choose_three_add_lower q (h - q)
    have hadd : q + (h - q) = h := Nat.add_sub_of_le hqh
    rw [hadd] at hnat
    have hcast : ((h - q : ℕ) : ℤ) = (h : ℤ) - q := by
      rw [Nat.cast_sub hqh]
    rw [← hcast]
    exact_mod_cast hnat
  · have hhq : h < q := Nat.lt_of_not_ge hqh
    have hnat := choose_three_add_upper h (q - h)
    have hadd : h + (q - h) = q := Nat.add_sub_of_le (Nat.le_of_lt hhq)
    rw [hadd] at hnat
    have hcast : ((q - h : ℕ) : ℤ) = (q : ℤ) - h := by
      rw [Nat.cast_sub (Nat.le_of_lt hhq)]
    have hnatZ : (q.choose 3 : ℤ) ≤
        h.choose 3 + ((q : ℤ) - h) * q.choose 2 := by
      rw [← hcast]
      exact_mod_cast hnat
    linarith

theorem balanced_choose_three_lower {ι : Type*} [Fintype ι] {total : ℕ}
    (h : ι → ℕ) (hsum : ∑ i, h i = total) :
    balanced_choose_three (Fintype.card ι) total ≤
      ∑ i, (h i).choose 3 := by
  let n := Fintype.card ι
  by_cases hn : n = 0
  · haveI : IsEmpty ι := Fintype.card_eq_zero_iff.mp hn
    have htotal : total = 0 := by simpa using hsum.symm
    subst total
    simp [balanced_choose_three, Nat.choose]
  let q := total / n
  let r := total % n
  have hdiv : total = n * q + r := by
    dsimp [q, r]
    calc
      total = total % n + n * (total / n) := (Nat.mod_add_div total n).symm
      _ = n * (total / n) + total % n := by omega
  have htangent (i : ι) :
      (q.choose 3 : ℤ) + ((h i : ℤ) - q) * q.choose 2 ≤
        (h i).choose 3 := choose_three_tangent (h i) q
  have hsumZ := Finset.sum_le_sum fun i
    (_hi : i ∈ (Finset.univ : Finset ι)) ↦ htangent i
  have hsumInt : ∑ i, (h i : ℤ) = total := by exact_mod_cast hsum
  have hchoose : (q + 1).choose 3 = q.choose 3 + q.choose 2 := by
    simpa [add_comm] using (Nat.choose_succ_succ q 2)
  have hgoalZ :
      (((n - r) * q.choose 3 + r * (q + 1).choose 3 : ℕ) : ℤ) ≤
        ∑ i, ((h i).choose 3 : ℤ) := by
    have hsumLeft :
        (∑ i, ((q.choose 3 : ℤ) +
          ((h i : ℤ) - q) * q.choose 2)) =
        (n : ℤ) * q.choose 3 +
          ((total : ℤ) - n * q) * q.choose 2 := by
      rw [Finset.sum_add_distrib]
      simp only [Finset.sum_const, Finset.card_univ,
        nsmul_eq_mul]
      rw [← Finset.sum_mul]
      rw [Finset.sum_sub_distrib, hsumInt]
      simp only [Finset.sum_const, Finset.card_univ,
        nsmul_eq_mul]
      simp [n]
    rw [hsumLeft] at hsumZ
    have hrle : r ≤ n := (Nat.mod_lt total (Nat.pos_of_ne_zero hn)).le
    have hdivZ : (total : ℤ) = n * q + r := by exact_mod_cast hdiv
    rw [hchoose]
    push_cast
    rw [Nat.cast_sub hrle]
    nlinarith
  have hgoalNat :
      (n - r) * q.choose 3 + r * (q + 1).choose 3 ≤
        ∑ i, (h i).choose 3 := by
    exact_mod_cast hgoalZ
  simpa [balanced_choose_three, q, r] using hgoalNat

/-- Coordinates contained in every member of a parameter-indexed family. -/
def commonSetIntersection {ι : Type*} [Fintype ι] [DecidableEq ι]
    (sets : F → Finset ι) (t : Finset F) : Finset ι :=
  Finset.univ.filter fun i ↦ ∀ a ∈ t, i ∈ sets a

omit [Field F] [DecidableEq F] in
@[simp] theorem mem_commonSetIntersection {ι : Type*}
    [Fintype ι] [DecidableEq ι]
    (sets : F → Finset ι) (t : Finset F) (i : ι) :
    i ∈ commonSetIntersection sets t ↔ ∀ a ∈ t, i ∈ sets a := by
  simp [commonSetIntersection]

/-- Number of sets in a finite family containing a coordinate. -/
def setMembershipDegree {ι : Type*} [Fintype ι] [DecidableEq ι]
    (S : Finset F) (sets : F → Finset ι) (i : ι) : ℕ :=
  (S.filter fun a ↦ i ∈ sets a).card

omit [Field F] [DecidableEq F] in
private theorem sum_setMembershipDegree {ι : Type*}
    [Fintype ι] [DecidableEq ι] {m s : ℕ}
    (S : Finset F) (sets : F → Finset ι)
    (hS : S.card = m) (hsets : ∀ a ∈ S, (sets a).card = s) :
    ∑ i, setMembershipDegree S sets i = m * s := by
  have hfilter (i : ι) : setMembershipDegree S sets i =
      ∑ a ∈ S, if i ∈ sets a then 1 else 0 := by
    exact (Finset.sum_boole (R := ℕ) (fun a ↦ i ∈ sets a) S).symm
  have hcount (a : F) (ha : a ∈ S) :
      ∑ i : ι, (if i ∈ sets a then 1 else 0) = s := by
    rw [Finset.sum_boole (R := ℕ)]
    simpa using hsets a ha
  simp_rw [hfilter]
  rw [Finset.sum_comm]
  calc
    ∑ a ∈ S, ∑ i, (if i ∈ sets a then 1 else 0) =
        ∑ _a ∈ S, s := Finset.sum_congr rfl hcount
    _ = m * s := by simp [hS]

omit [Field F] [DecidableEq F] in
private theorem triples_containing_common_coordinate {ι : Type*}
    [Fintype ι] [DecidableEq ι]
    (S : Finset F) (sets : F → Finset ι) (i : ι) :
    ((S.powersetCard 3).filter fun t ↦
      i ∈ commonSetIntersection sets t).card =
      (setMembershipDegree S sets i).choose 3 := by
  have heq :
      (S.powersetCard 3).filter
          (fun t ↦ i ∈ commonSetIntersection sets t) =
        (S.filter fun a ↦ i ∈ sets a).powersetCard 3 := by
    ext t
    simp only [Finset.mem_filter, Finset.mem_powersetCard,
      mem_commonSetIntersection]
    constructor
    · rintro ⟨⟨htS, htcard⟩, hall⟩
      exact ⟨fun a ha ↦ Finset.mem_filter.mpr ⟨htS ha, hall a ha⟩,
        htcard⟩
    · rintro ⟨ht, htcard⟩
      exact ⟨⟨fun a ha ↦ (Finset.mem_filter.mp (ht ha)).1, htcard⟩,
        fun a ha ↦ (Finset.mem_filter.mp (ht ha)).2⟩
  rw [heq, Finset.card_powersetCard]
  rfl

omit [Field F] [DecidableEq F] in
private theorem sum_commonSetIntersections {ι : Type*}
    [Fintype ι] [DecidableEq ι]
    (S : Finset F) (sets : F → Finset ι) :
    ∑ t ∈ S.powersetCard 3, (commonSetIntersection sets t).card =
      ∑ i, (setMembershipDegree S sets i).choose 3 := by
  have hcard (t : Finset F) : (commonSetIntersection sets t).card =
      ∑ i : ι, if i ∈ commonSetIntersection sets t then 1 else 0 := by
    exact Finset.card_eq_sum_ite (Finset.subset_univ _)
  have hfilter (i : ι) :
      ((S.powersetCard 3).filter fun t ↦
        i ∈ commonSetIntersection sets t).card =
      ∑ t ∈ S.powersetCard 3,
        if i ∈ commonSetIntersection sets t then 1 else 0 := by
    exact (Finset.sum_boole (R := ℕ)
      (fun t ↦ i ∈ commonSetIntersection sets t)
      (S.powersetCard 3)).symm
  calc
    ∑ t ∈ S.powersetCard 3, (commonSetIntersection sets t).card =
        ∑ t ∈ S.powersetCard 3, ∑ i,
          if i ∈ commonSetIntersection sets t then 1 else 0 := by
      exact Finset.sum_congr rfl fun t _ ↦ hcard t
    _ = ∑ i, ∑ t ∈ S.powersetCard 3,
          if i ∈ commonSetIntersection sets t then 1 else 0 := by
      rw [Finset.sum_comm]
    _ = ∑ i, ((S.powersetCard 3).filter fun t ↦
          i ∈ commonSetIntersection sets t).card := by
      exact Finset.sum_congr rfl fun i _ ↦ (hfilter i).symm
    _ = ∑ i, (setMembershipDegree S sets i).choose 3 := by
      exact Finset.sum_congr rfl fun i _ ↦
        triples_containing_common_coordinate S sets i

omit [Field F] [DecidableEq F] in
/-- Exact third-moment lower bound for common intersections of equally-sized
sets in an arbitrary finite coordinate universe. -/
theorem commonSetIntersection_sum_lower {ι : Type*}
    [Fintype ι] [DecidableEq ι] {m s : ℕ}
    (S : Finset F) (sets : F → Finset ι)
    (hS : S.card = m) (hsets : ∀ a ∈ S, (sets a).card = s) :
    balanced_choose_three (Fintype.card ι) (m * s) ≤
      ∑ t ∈ S.powersetCard 3, (commonSetIntersection sets t).card := by
  rw [sum_commonSetIntersections]
  exact balanced_choose_three_lower (setMembershipDegree S sets)
    (sum_setMembershipDegree S sets hS hsets)

omit [Field F] [DecidableEq F] in
theorem triple_intersection_sum_lower {n e m : ℕ} (S : Finset F)
    (E : F → Finset (Fin n)) (hS : S.card = m)
    (hE : ∀ a ∈ S, (E a).card = e) :
    rounded_choose_three n (m * (n - e)) ≤
      ∑ t ∈ S.powersetCard 3, (agreementIntersection E t).card := by
  let agreementSets : F → Finset (Fin n) := fun a ↦ Finset.univ \ E a
  have hsets (a : F) (ha : a ∈ S) :
      (agreementSets a).card = n - e := by
    dsimp [agreementSets]
    rw [Finset.card_sdiff, Finset.inter_eq_left.mpr (Finset.subset_univ _),
      Finset.card_univ, Fintype.card_fin, hE a ha]
  have hintersection (t : Finset F) :
      commonSetIntersection agreementSets t = agreementIntersection E t := by
    ext i
    simp [agreementSets]
  have hbound := commonSetIntersection_sum_lower S agreementSets hS hsets
  simpa [hintersection] using hbound

end Internal

export Internal (PaddedErrorFamily paddedErrorFamily_nonempty
  agreementIntersection mem_agreementIntersection agreementDegree
  balanced_choose_three_lower
  commonSetIntersection mem_commonSetIntersection setMembershipDegree
  commonSetIntersection_sum_lower
  triple_intersection_sum_lower)

end AffineAgreement
