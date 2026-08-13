import Mathlib.Algebra.BigOperators.Ring.Finset
import Mathlib.Algebra.Order.BigOperators.Group.Finset
import Mathlib.Algebra.Order.Field.Rat
import CodingTheory.Proximity
import CodingTheory.AffineCounting

/-!
# Finite double averaging

This is the protocol-order-independent counting step in selected MCA.  A bad
proximity challenge has many witnessing row directions, while every fixed
direction witnesses only few bad challenges.  Counting the same pairs in the
two orders gives the required bound.
-/

namespace SelectedMCA

open scoped BigOperators

variable {Challenge : Type*} [Fintype Challenge]

/-- Double-count bad challenge/direction pairs. -/
theorem double_averaging_card
    (bad : Finset Challenge)
    (witnesses : Challenge → Challenge → Prop)
    [DecidableRel witnesses] (missing perDirection : ℕ)
    (hmany : ∀ x ∈ bad,
      Fintype.card Challenge - missing ≤
        (Finset.univ.filter fun y ↦ witnesses x y).card)
    (hfew : ∀ y,
      (bad.filter fun x ↦ witnesses x y).card ≤ perDirection) :
    bad.card * (Fintype.card Challenge - missing) ≤
      Fintype.card Challenge * perDirection := by
  let pairCount := ∑ x ∈ bad,
    (Finset.univ.filter fun y ↦ witnesses x y).card
  have hlower : bad.card * (Fintype.card Challenge - missing) ≤ pairCount := by
    calc
      bad.card * (Fintype.card Challenge - missing) =
          ∑ _x ∈ bad, (Fintype.card Challenge - missing) := by simp
      _ ≤ pairCount := Finset.sum_le_sum fun x hx ↦ hmany x hx
  have hswap : pairCount =
      ∑ y, (bad.filter fun x ↦ witnesses x y).card := by
    dsimp [pairCount]
    calc
      ∑ x ∈ bad, (Finset.univ.filter fun y ↦ witnesses x y).card =
          ∑ x ∈ bad, ∑ y, if witnesses x y then 1 else 0 := by
        apply Finset.sum_congr rfl
        intro x hx
        exact (Finset.sum_boole (R := ℕ) (witnesses x) Finset.univ).symm
      _ = ∑ y, ∑ x ∈ bad, if witnesses x y then 1 else 0 := by
        rw [Finset.sum_comm]
      _ = ∑ y, (bad.filter fun x ↦ witnesses x y).card := by
        apply Finset.sum_congr rfl
        intro y _
        exact Finset.sum_boole (R := ℕ) (fun x ↦ witnesses x y) bad
  have hupper : pairCount ≤ Fintype.card Challenge * perDirection := by
    rw [hswap]
    calc
      ∑ y, (bad.filter fun x ↦ witnesses x y).card ≤
          ∑ _y : Challenge, perDirection :=
        Finset.sum_le_sum fun y _ ↦ hfew y
      _ = Fintype.card Challenge * perDirection := by simp
  exact hlower.trans hupper

/-- Probability form of `double_averaging_card`. -/
theorem double_averaging_ratio
    (bad : Finset Challenge)
    (witnesses : Challenge → Challenge → Prop)
    [DecidableRel witnesses] (missing perDirection : ℕ)
    (hmissing : missing < Fintype.card Challenge)
    (hmany : ∀ x ∈ bad,
      Fintype.card Challenge - missing ≤
        (Finset.univ.filter fun y ↦ witnesses x y).card)
    (hfew : ∀ y,
      (bad.filter fun x ↦ witnesses x y).card ≤ perDirection) :
    (bad.card : ℚ) / Fintype.card Challenge ≤
      (perDirection : ℚ) /
        ((Fintype.card Challenge - missing : ℕ) : ℚ) := by
  have hcount := double_averaging_card bad witnesses missing perDirection
    hmany hfew
  have hcard : 0 < Fintype.card Challenge := by omega
  have hcardQ : (0 : ℚ) < Fintype.card Challenge := by exact_mod_cast hcard
  have hremaining : 0 < Fintype.card Challenge - missing := by omega
  have hremainingQ :
      (0 : ℚ) < ((Fintype.card Challenge - missing : ℕ) : ℚ) := by
    exact_mod_cast hremaining
  rw [div_le_div_iff₀ hcardQ hremainingQ]
  have hcountQ :
      (bad.card : ℚ) *
          ((Fintype.card Challenge - missing : ℕ) : ℚ) ≤
        (Fintype.card Challenge : ℚ) * perDirection := by
    exact_mod_cast hcount
  calc
    (bad.card : ℚ) *
        ((Fintype.card Challenge - missing : ℕ) : ℚ) ≤
        (Fintype.card Challenge : ℚ) * perDirection := hcountQ
    _ = (perDirection : ℚ) * Fintype.card Challenge := by rw [mul_comm]

/-- A denominator-cleared density estimate holding in every fiber also holds
on the whole finite product. -/
theorem fiberwise_density_sum
    {X Y : Type*} [Fintype X] [Fintype Y]
    (bad : Y → Finset X) (numerator denominator : ℕ)
    (hfiber : ∀ y, denominator * (bad y).card ≤
      numerator * Fintype.card X) :
    denominator * (∑ y, (bad y).card) ≤
      numerator * Fintype.card (X × Y) := by
  calc
    denominator * (∑ y, (bad y).card) =
        ∑ y, denominator * (bad y).card := by rw [Finset.mul_sum]
    _ ≤ ∑ _y : Y, numerator * Fintype.card X :=
      Finset.sum_le_sum fun y _ ↦ hfiber y
    _ = numerator * Fintype.card (X × Y) := by
      simp [Fintype.card_prod]
      ring

end SelectedMCA
