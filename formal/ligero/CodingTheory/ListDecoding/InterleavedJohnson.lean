import CodingTheory.ListDecoding.InterleavedDistance
import Mathlib.Algebra.Order.Chebyshev
import Mathlib.Tactic.Linarith

/-!
# Johnson bound for fixed interleaved lists

This file proves the exact list-cardinality formula used by the general
selected-response analysis.  Each radius-`E` candidate supplies an agreement
set of exactly `n-E` coordinates.  Distinct codeword matrices have agreement
intersection at most `n-d`; finite Cauchy--Schwarz then gives the stated
Johnson denominator.
-/

namespace CodingTheory.InterleavedJohnson

open CodingTheory
open scoped BigOperators

/-- Denominator in the fixed interleaved-list Johnson bound at column
radius `E`. -/
def denominator (n d E : ℕ) : ℤ :=
  (n : ℤ) * d - 2 * n * E + E * E

/-- Exact integer list-size bound, valid when `denominator n d E` is
positive. -/
def listBound (n d E : ℕ) : ℕ :=
  n * (d - E) / (denominator n d E).toNat

/-- On the radius range `E ≤ n`, decreasing the error radius can only
increase the Johnson denominator. -/
theorem denominator_anti_on {n d E E₀ : ℕ}
    (hE : E ≤ E₀) (hE₀ : E₀ ≤ n) :
    denominator n d E₀ ≤ denominator n d E := by
  unfold denominator
  have hE' : (E : ℤ) ≤ E₀ := by exact_mod_cast hE
  have hE₀' : (E₀ : ℤ) ≤ n := by exact_mod_cast hE₀
  nlinarith

theorem denominator_pos_of_le {n d E E₀ : ℕ}
    (hE : E ≤ E₀) (hE₀ : E₀ ≤ n)
    (hpos : 0 < denominator n d E₀) :
    0 < denominator n d E :=
  hpos.trans_le (denominator_anti_on hE hE₀)

namespace Internal

variable {n : ℕ}

private theorem sum_agreementOccurrences (family : Finset (Finset (Fin n))) :
    (∑ j : Fin n, (family.filter fun A ↦ j ∈ A).card) =
      ∑ A ∈ family, A.card := by
  simp_rw [Finset.card_eq_sum_ones, Finset.sum_filter]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro A hA
  simp

private theorem sum_agreementOccurrences_sq
    (family : Finset (Finset (Fin n))) :
    (∑ j : Fin n, (family.filter fun A ↦ j ∈ A).card ^ 2) =
      ∑ A ∈ family, ∑ A' ∈ family, (A ∩ A').card := by
  have hcard (j : Fin n) :
      (family.filter fun A ↦ j ∈ A).card =
        ∑ A ∈ family, if j ∈ A then 1 else 0 := by
    simp_rw [Finset.card_eq_sum_ones, Finset.sum_filter]
  simp_rw [hcard, pow_two]
  simp_rw [Finset.sum_mul]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro A hA
  calc
    (∑ j, (if j ∈ A then 1 else 0) *
        ∑ A' ∈ family, if j ∈ A' then 1 else 0) =
        ∑ j, ∑ A' ∈ family,
          (if j ∈ A then 1 else 0) * (if j ∈ A' then 1 else 0) := by
      apply Finset.sum_congr rfl
      intro j hj
      simp_rw [Finset.mul_sum]
    _ = ∑ A' ∈ family, ∑ j,
          (if j ∈ A then 1 else 0) * (if j ∈ A' then 1 else 0) := by
      rw [Finset.sum_comm]
    _ = ∑ A' ∈ family, (A ∩ A').card := by
      apply Finset.sum_congr rfl
      intro A' hA'
      calc
        (∑ j, (if j ∈ A then 1 else 0) *
            (if j ∈ A' then 1 else 0)) =
            ∑ j ∈ Finset.univ.filter (fun j ↦ j ∈ A ∩ A'), 1 := by
          rw [Finset.sum_filter]
          apply Finset.sum_congr rfl
          intro j hj
          by_cases hjA : j ∈ A <;> by_cases hjA' : j ∈ A' <;>
            simp [hjA, hjA']
        _ = (A ∩ A').card := by
          rw [show Finset.univ.filter (fun j ↦ j ∈ A ∩ A') = A ∩ A' by
            ext j
            simp]
          exact (Finset.card_eq_sum_ones (s := A ∩ A')).symm

/-- Abstract incidence form of the Johnson calculation. -/
private theorem johnson_family_int {E d : ℕ}
    (family : Finset (Finset (Fin n)))
    (hE : E ≤ n) (hEd : E ≤ d) (hd : d ≤ n)
    (hcard : ∀ A ∈ family, A.card = n - E)
    (hinter : ∀ A ∈ family, ∀ A' ∈ family, A ≠ A' →
      (A ∩ A').card ≤ n - d) :
    (family.card : ℤ) * ((n : ℤ) * d - 2 * n * E + E * E) ≤
      (n : ℤ) * (d - E) := by
  by_cases hfamily : family = ∅
  · rw [hfamily]
    simp only [Finset.card_empty, Nat.cast_zero, zero_mul]
    exact mul_nonneg (by positivity) (sub_nonneg.mpr (by exact_mod_cast hEd))
  have hfamilyPos : 0 < family.card := Finset.card_pos.mpr
    (Finset.nonempty_iff_ne_empty.mpr hfamily)
  let occupancy : Fin n → ℕ := fun j ↦
    (family.filter fun A ↦ j ∈ A).card
  have hsum : (∑ j : Fin n, occupancy j) =
      family.card * (n - E) := by
    rw [sum_agreementOccurrences family]
    calc
      (∑ A ∈ family, A.card) = ∑ _A ∈ family, (n - E) :=
        Finset.sum_congr rfl fun A hA ↦ hcard A hA
      _ = _ := by simp
  have hrow (A : Finset (Fin n)) (hA : A ∈ family) :
      (∑ A' ∈ family, (A ∩ A').card) ≤
        (n - E) + (family.card - 1) * (n - d) := by
    calc
      (∑ A' ∈ family, (A ∩ A').card) ≤
          ∑ A' ∈ family, if A' = A then n - E else n - d := by
        apply Finset.sum_le_sum
        intro A' hA'
        by_cases heq : A' = A
        · subst A'
          simp [hcard A hA]
        · simpa [heq] using hinter A hA A' hA' (Ne.symm heq)
      _ = (n - E) + (family.card - 1) * (n - d) := by
        rw [← Finset.add_sum_erase family
          (fun A' ↦ if A' = A then n - E else n - d) hA]
        rw [if_pos rfl]
        congr 1
        calc
          (∑ A' ∈ family.erase A,
              if A' = A then n - E else n - d) =
              ∑ _A' ∈ family.erase A, (n - d) := by
            apply Finset.sum_congr rfl
            intro A' hA'
            rw [if_neg (Finset.ne_of_mem_erase hA')]
          _ = (family.card - 1) * (n - d) := by
            simp [Finset.card_erase_of_mem hA]
  have hsquares : (∑ j : Fin n, occupancy j ^ 2) ≤
      family.card * ((n - E) + (family.card - 1) * (n - d)) := by
    rw [sum_agreementOccurrences_sq family]
    calc
      (∑ A ∈ family, ∑ A' ∈ family, (A ∩ A').card) ≤
          ∑ _A ∈ family,
            ((n - E) + (family.card - 1) * (n - d)) :=
        Finset.sum_le_sum fun A hA ↦ hrow A hA
      _ = _ := by simp
  have hcauchy : (family.card * (n - E)) ^ 2 ≤
      n * (family.card *
        ((n - E) + (family.card - 1) * (n - d))) := by
    rw [← hsum]
    calc
      (∑ j : Fin n, occupancy j) ^ 2 ≤
          (Finset.univ : Finset (Fin n)).card *
            ∑ j : Fin n, occupancy j ^ 2 := by
        simpa using
          (sq_sum_le_card_mul_sum_sq
            (s := (Finset.univ : Finset (Fin n))) (f := occupancy))
      _ ≤ n * (family.card *
          ((n - E) + (family.card - 1) * (n - d))) := by
        simpa using Nat.mul_le_mul_left n hsquares
  have hcauchyInt :
      ((family.card * ((n - E) ^ 2) : ℕ) : ℤ) ≤
        ((n * ((n - E) + (family.card - 1) * (n - d)) : ℕ) : ℤ) := by
    have hcanceled : family.card * ((n - E) ^ 2) ≤
        n * ((n - E) + (family.card - 1) * (n - d)) := by
      apply Nat.le_of_mul_le_mul_left (c := family.card) ?_ hfamilyPos
      simpa [pow_two, mul_assoc, mul_left_comm, mul_comm] using hcauchy
    exact_mod_cast hcanceled
  push_cast at hcauchyInt
  rw [Nat.cast_sub hE, Nat.cast_sub hd,
    Nat.cast_sub (show 1 ≤ family.card by omega)] at hcauchyInt
  ring_nf at hcauchyInt ⊢
  linarith

end Internal

variable {F Row : Type*} [Field F] [DecidableEq F] [Fintype Row]
variable {n E d : ℕ}

/-- The exact Johnson bound for a fixed list of rowwise codeword matrices
within column radius `E` of one received matrix. -/
theorem card_le_listBound
    (C : LinearCode F n) (received : Row → Word F n)
    (candidates : Finset (Row → Word F n))
    (hmin : HasMinimumDistanceAtLeast C d)
    (hcode : ∀ candidate ∈ candidates, ∀ row, candidate row ∈ C)
    (hclose : ∀ candidate ∈ candidates,
      (matrixErrorCoordinates received candidate).card ≤ E)
    (hE : E ≤ n) (hEd : E < d)
    (hden : 0 < denominator n d E) :
    candidates.card ≤ listBound n d E := by
  classical
  have hd : d ≤ n := hmin.distance_le_length
  let agreement : candidates → Finset (Fin n) := fun candidate ↦
    Finset.univ \ matrixErrorCoordinates received candidate.1
  have hagreementCard (candidate : candidates) :
      n - E ≤ (agreement candidate).card := by
    have herror := hclose candidate.1 candidate.2
    have hsub := Nat.sub_le_sub_left herror n
    have hagreementEq : (agreement candidate).card =
        n - (matrixErrorCoordinates received candidate.1).card := by
      simp [agreement, Finset.card_sdiff]
    rw [hagreementEq]
    exact hsub
  choose selected hselected hselectedCard using fun candidate : candidates ↦
    Finset.exists_subset_card_eq (hagreementCard candidate)
  have hpair (first second : candidates) (hne : first ≠ second) :
      (selected first ∩ selected second).card ≤ n - d := by
    let difference := matrixErrorCoordinates first.1 second.1
    have hsubset : selected first ∩ selected second ⊆
        Finset.univ \ difference := by
      intro j hj
      have hjFirst := hselected first (Finset.mem_inter.mp hj).1
      have hjSecond := hselected second (Finset.mem_inter.mp hj).2
      have hjFirstAgreement := Finset.mem_sdiff.mp hjFirst
      have hjSecondAgreement := Finset.mem_sdiff.mp hjSecond
      apply Finset.mem_sdiff.mpr
      refine ⟨Finset.mem_univ _, ?_⟩
      intro hjDifference
      obtain ⟨row, hrow⟩ := (Finset.mem_filter.mp hjDifference).2
      have hfirst (row : Row) : received row j = first.1 row j := by
        apply not_ne_iff.mp
        intro hneRow
        exact hjFirstAgreement.2
          (Finset.mem_filter.mpr ⟨Finset.mem_univ _, row, hneRow⟩)
      have hsecond (row : Row) : received row j = second.1 row j := by
        apply not_ne_iff.mp
        intro hneRow
        exact hjSecondAgreement.2
          (Finset.mem_filter.mpr ⟨Finset.mem_univ _, row, hneRow⟩)
      exact hrow ((hfirst row).symm.trans (hsecond row))
    have hdifference : d ≤ difference.card := by
      apply matrixErrorCoordinates_card_ge_distance C hmin
        (hcode first.1 first.2) (hcode second.1 second.2)
      intro heq
      exact hne (Subtype.ext heq)
    calc
      (selected first ∩ selected second).card ≤
          (Finset.univ \ difference).card := Finset.card_le_card hsubset
      _ = n - difference.card := by
        simp [Finset.card_sdiff]
      _ ≤ n - d := Nat.sub_le_sub_left hdifference n
  have hselectedInjective : Function.Injective selected := by
    intro first second heq
    by_contra hne
    have hbound := hpair first second hne
    rw [heq, Finset.inter_self, hselectedCard second] at hbound
    omega
  let family : Finset (Finset (Fin n)) := Finset.univ.image selected
  have hfamilyCard : family.card = candidates.card := by
    change (Finset.univ.image selected).card = candidates.card
    rw [Finset.card_image_of_injective _ hselectedInjective]
    simp
  have hfamilyMemberCard (A : Finset (Fin n)) (hA : A ∈ family) :
      A.card = n - E := by
    obtain ⟨candidate, _hcandidate, rfl⟩ := Finset.mem_image.mp hA
    exact hselectedCard candidate
  have hfamilyPair (A : Finset (Fin n)) (hA : A ∈ family)
      (A' : Finset (Fin n)) (hA' : A' ∈ family) (hne : A ≠ A') :
      (A ∩ A').card ≤ n - d := by
    obtain ⟨first, _hfirst, rfl⟩ := Finset.mem_image.mp hA
    obtain ⟨second, _hsecond, rfl⟩ := Finset.mem_image.mp hA'
    exact hpair first second (fun heq ↦ hne (congrArg selected heq))
  have hfamilyJohnson := Internal.johnson_family_int family hE
    (Nat.le_of_lt hEd) hd hfamilyMemberCard hfamilyPair
  rw [hfamilyCard] at hfamilyJohnson
  have hfamilyJohnson' :
      (candidates.card : ℤ) * denominator n d E ≤
        ((n * (d - E) : ℕ) : ℤ) := by
    simpa [denominator, Nat.cast_sub (Nat.le_of_lt hEd)] using
      hfamilyJohnson
  have hdenCast : ((denominator n d E).toNat : ℤ) =
      denominator n d E :=
    Int.toNat_of_nonneg (le_of_lt hden)
  have hmul : candidates.card * (denominator n d E).toNat ≤
      n * (d - E) := by
    rw [← hdenCast] at hfamilyJohnson'
    exact_mod_cast hfamilyJohnson'
  have hdenNat : 0 < (denominator n d E).toNat := by
    rw [← hdenCast] at hden
    exact_mod_cast hden
  apply (Nat.le_div_iff_mul_le hdenNat).2
  simpa [listBound] using hmul

end CodingTheory.InterleavedJohnson
