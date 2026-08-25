import Bcs.RoundByRound
import Mathlib.Tactic.FieldSimp
import Mathlib.Order.Interval.Finset.Nat

/-!
# Graded round-by-round soundness: the two-ascent count with a clamp

`Bcs.RbrCore` is the ungraded count: a per-slot bad event, a per-slot budget, and one union
bound.  Its state is a *bit*, so an accepting-and-failing tape is charged once, at whichever
slot shed doom.  This file grades the state and charges a *pair* of slots -- the ascent from
`⊥` to an intermediate level `v`, and the ascent from `v` to `⊤`.

## Why a pair, and what it costs

The two grinding strategies a Fiat--Shamir prover can run against a two-round protocol are
the endpoints of one budget split.  With `T₁` queries aimed at the first ascent and `T₂` at
the second, its success at level `v` is `T₁ · beta1 v / |C| · min(T₂, ...) · beta2 v / |C|`,
so the ungraded bound (which knows only "some slot shed doom") has to charge `T` at each
round separately and take the worse.  The pair count keeps the level, hence keeps the
product.

The price is one extra factor of `T`: `pair_slot_card_le` is a statement about a *fixed*
pair of slots, and there are `T²` of them.  That is not slack -- query slots are additive,
so an adversary really does get `T₁ · T₂ ≈ T²/4` distinct (first ascent, second ascent)
attempts.  It is exactly why a level whose second ascent has unbounded fan-out must be
charged the other way.

## The clamp, and why it is a `Finset` and not a `min`

At levels reached with probability one -- in Ligero, every agreement below the proximity
radius -- the pair bound is vacuous: `beta1 v = |C|`, and `T² · beta1 v · beta2 v / |C|²`
exceeds `T · beta2 v / |C|`.  The repair is to *forget the first ascent* at those levels,
which costs one factor of `T` and no level information.

`graded_card_le` takes the set `saturated` of levels handled that way as a parameter, and
proves the bound for **every** choice.  So the floor is not assumed: a caller optimizes over
`saturated`, and `graded_ratio_le_of_clamp` is the density form it consumes.  In
`Bcs.ResponseRigid` the same split is performed by hand at one point (`caseAFloorBudget`
against `caseAListedBudget`, with the crossing supplied as `responseFloor`); this is that
split as a theorem.
-/

set_option autoImplicit false
set_option relaxedAutoImplicit false

namespace Bcs

open Finset
open scoped Classical

/-! ## Abel summation for level-indexed budgets

The pair term of `graded_card_le` is a sum over levels of (how many answers reach that level) times
(how many answers then accept).  The first factor is a **differential** -- the count at level
exactly `v` -- and a proximity theorem proves **tails**.  A differential bound does not follow from
tail bounds pointwise: `#{= v} = #{≥ v} - #{≥ v+1}`, and subtracting one upper bound from another
yields nothing.  Substituting the tail for the differential is sound but costs a factor
`(n+1)/(r+1)` and *saturates* -- at `n = 8192, r = 130` that is six bits, and no number of openings
recovers it, because without increment damping the sum is dominated by levels where the cover is
one.

Abel summation is the repair, and it is an identity, not an inequality: the same sum equals the
budget's *increments* against the tails.  `AgreementProfile.contribution` is already written in that
form, which is why the numerics were right while the theorem could not produce them.
-/

section Abel

/-- The increment of a budget.  `inc beta 0 = beta 0`, so the sum of increments telescopes to the
budget itself rather than to a difference. -/
def inc (beta : ℕ → ℕ) : ℕ → ℕ
  | 0 => beta 0
  | (v + 1) => beta (v + 1) - beta v

/-- A monotone budget is the sum of its increments. -/
theorem sum_inc_eq (beta : ℕ → ℕ) (hmono : Monotone beta) (v : ℕ) :
    ∑ u ∈ Finset.range (v + 1), inc beta u = beta v := by
  induction v with
  | zero => simp [inc]
  | succ m ih =>
    rw [Finset.sum_range_succ, ih]
    have h : beta m ≤ beta (m + 1) := hmono (Nat.le_succ m)
    simp only [inc]
    omega

/--
**Abel summation over levels.**  The level-indexed sum against a monotone budget *equals* the sum
of the budget's increments against the tails of the level counts.

This is the identity that makes the tight bound expressible: the left side needs differentials,
which a proximity theorem does not give; the right side needs tails, which is exactly what it does
give.
-/
theorem abel_sum (N : ℕ) (levelCount beta : ℕ → ℕ) (hmono : Monotone beta) :
    ∑ v ∈ Finset.range (N + 1), levelCount v * beta v
      = ∑ u ∈ Finset.range (N + 1),
          (∑ v ∈ Finset.Ico u (N + 1), levelCount v) * inc beta u := by
  have hleft : ∀ v ∈ Finset.range (N + 1),
      levelCount v * beta v
        = ∑ u ∈ Finset.range (v + 1), levelCount v * inc beta u := by
    intro v _
    rw [← Finset.mul_sum, sum_inc_eq beta hmono v]
  rw [Finset.sum_congr rfl hleft]
  rw [Finset.sum_comm' (s := Finset.range (N + 1)) (t := fun v => Finset.range (v + 1))
    (t' := Finset.range (N + 1)) (s' := fun u => Finset.Ico u (N + 1))
    (f := fun v u => levelCount v * inc beta u) ?_]
  · exact Finset.sum_congr rfl fun u _ => by rw [Finset.sum_mul]
  · intro v u
    simp only [Finset.mem_range, Finset.mem_Ico]
    omega

/--
**The tight pair bound, from tails.**  Substituting a tail bound for each level count in the Abel
form gives an upper bound that keeps the increment damping -- unlike substituting it for the
differential, which does not.
-/
theorem abel_sum_le (N : ℕ) (levelCount beta tail : ℕ → ℕ) (hmono : Monotone beta)
    (htail : ∀ u ≤ N, (∑ v ∈ Finset.Ico u (N + 1), levelCount v) ≤ tail u) :
    ∑ v ∈ Finset.range (N + 1), levelCount v * beta v
      ≤ ∑ u ∈ Finset.range (N + 1), tail u * inc beta u := by
  rw [abel_sum N levelCount beta hmono]
  refine Finset.sum_le_sum ?_
  intro u hu
  exact Nat.mul_le_mul_right _ (htail u (Nat.lt_succ_iff.mp (Finset.mem_range.mp hu)))

end Abel

/-! ## Restricting a prefix -/

section Restrict

variable {C : Type} {T : ℕ}

/-- Truncating a longer prefix to a shorter slot is truncating the tape. -/
theorem extract_prefix_restrict (tape : Fin T → C) (i j : Fin T) (hij : i.val < j.val) :
    Sumcheck.extract_prefix (Sumcheck.extract_prefix tape j) ⟨i.val, hij⟩
      = Sumcheck.extract_prefix tape i := rfl

/-- Reading slot `i` off the prefix at a later slot `j`. -/
theorem apply_restrict (tape : Fin T → C) (i j : Fin T) (hij : i.val < j.val) :
    (Sumcheck.extract_prefix tape j) ⟨i.val, hij⟩ = tape i := rfl

end Restrict

/-! ## Two nested ascents at a fixed pair of slots -/

/--
**The pair count.**  Two prefix-measurable events at slots `i < j`, with per-prefix budgets
`b1` and `b2`, hold together on at most `b1 * b2 * |C|^(T-2)` tapes.

The proof is `Sumcheck.card_filter_prefix_r` at the *later* slot -- the earlier event is a
function of that slot's prefix, so it can be absorbed into the pair predicate -- and then
`Sumcheck.slot_bad_card_le` at length `j` to count the prefixes.
-/
theorem pair_slot_card_le {C : Type} [Fintype C] [DecidableEq C] {T : ℕ}
    (i j : Fin T) (hij : i.val < j.val) (b1 b2 : ℕ)
    (P1 : (Fin i.val → C) → C → Prop) (P2 : (Fin j.val → C) → C → Prop)
    (h1 : ∀ pref : Fin i.val → C, (univ.filter fun c => P1 pref c).card ≤ b1)
    (h2 : ∀ pref : Fin j.val → C, (univ.filter fun c => P2 pref c).card ≤ b2) :
    (univ.filter fun tape : Fin T → C =>
        P1 (Sumcheck.extract_prefix tape i) (tape i) ∧
          P2 (Sumcheck.extract_prefix tape j) (tape j)).card
      ≤ b1 * b2 * Fintype.card C ^ (T - 2) := by
  classical
  set i' : Fin j.val := ⟨i.val, hij⟩ with hi'
  set R : (Fin j.val → C) → C → Prop :=
    fun pref c => P1 (Sumcheck.extract_prefix pref i') (pref i') ∧ P2 pref c with hR
  -- count the good `(prefix, slot j)` pairs
  have hprefix : (univ.filter fun pref : Fin j.val → C =>
      P1 (Sumcheck.extract_prefix pref i') (pref i')).card
        ≤ b1 * Fintype.card C ^ (j.val - 1) :=
    le_trans (Finset.card_le_card (fun pref hpref => by
      simp only [mem_filter, mem_univ, true_and] at hpref ⊢; exact hpref))
      (Sumcheck.slot_bad_card_le i' b1 P1 h1)
  have hpairs : (univ.filter fun pr : (Fin j.val → C) × C => R pr.1 pr.2).card
      ≤ (b1 * Fintype.card C ^ (j.val - 1)) * b2 := by
    rw [Bcs.card_filter_prod_fst (fun pr : (Fin j.val → C) × C => R pr.1 pr.2)]
    calc ∑ pref : Fin j.val → C, (univ.filter fun c => R pref c).card
        ≤ ∑ _pref : Fin j.val → C,
            (if P1 (Sumcheck.extract_prefix _pref i') (_pref i') then b2 else 0) := by
          refine Finset.sum_le_sum ?_
          intro pref _
          by_cases hp : P1 (Sumcheck.extract_prefix pref i') (pref i')
          · rw [if_pos hp]
            refine le_trans (Finset.card_le_card ?_) (h2 pref)
            intro c hc
            simp only [mem_filter, mem_univ, true_and] at hc ⊢
            exact hc.2
          · rw [if_neg hp]
            simp only [Nat.le_zero, Finset.card_eq_zero]
            exact Finset.filter_false_of_mem fun c _ hcon => hp hcon.1
      _ = ∑ _pref ∈ univ.filter (fun pref : Fin j.val → C =>
              P1 (Sumcheck.extract_prefix pref i') (pref i')), b2 :=
          (Finset.sum_filter _ _).symm
      _ = (univ.filter fun pref : Fin j.val → C =>
              P1 (Sumcheck.extract_prefix pref i') (pref i')).card * b2 := by
          simp [Finset.sum_const, mul_comm]
      _ ≤ (b1 * Fintype.card C ^ (j.val - 1)) * b2 := by gcongr
  have hexp : (j.val - 1) + (T - 1 - j.val) = T - 2 := by omega
  have hstep : (univ.filter fun pr : (Fin j.val → C) × C => R pr.1 pr.2).card *
      Fintype.card C ^ (T - 1 - j.val) ≤ b1 * b2 * Fintype.card C ^ (T - 2) := by
    refine le_trans (Nat.mul_le_mul hpairs (le_refl (Fintype.card C ^ (T - 1 - j.val))))
      (le_of_eq ?_)
    calc (b1 * Fintype.card C ^ (j.val - 1)) * b2 * Fintype.card C ^ (T - 1 - j.val)
        = b1 * b2 * (Fintype.card C ^ (j.val - 1) * Fintype.card C ^ (T - 1 - j.val)) := by ring
      _ = b1 * b2 * Fintype.card C ^ ((j.val - 1) + (T - 1 - j.val)) := by rw [← pow_add]
      _ = b1 * b2 * Fintype.card C ^ (T - 2) := by rw [hexp]
  -- the earlier event is a function of the later prefix, definitionally
  refine le_trans (le_trans (Finset.card_le_card ?_)
    (le_of_eq (Sumcheck.card_filter_prefix_r T j R))) ?_
  · intro tape htape
    simp only [mem_filter, mem_univ, true_and] at htape ⊢
    exact htape
  · exact le_trans (Nat.mul_le_mul (Finset.card_le_card (fun pr hpr => by
      simp only [mem_filter, mem_univ, true_and] at hpr ⊢; exact hpr)) (le_refl _)) hstep

/--
**The fan-out-free pair count.**  Unioning over all `T` candidate second slots discharges
`GradedPair.pair_card` at `pairFactor := fun _ => T`.  Sound, and what `pair_slot_card_le` gives
directly -- but numerically useless wherever the second ascent's budget is large at high levels,
because it charges the adversary's whole query budget at a level whose real fan-out is one.
-/
theorem pair_card_of_fanout_free {C : Type} [Fintype C] [DecidableEq C] {V : Type} {T : ℕ}
    (ascend1 ascend2 : ∀ m : ℕ, (Fin m → C) → C → V → Prop)
    (Linked : ∀ m₁ m₂ : ℕ, (Fin m₁ → C) → (Fin m₂ → C) → V → Prop) (beta1 beta2 : V → ℕ)
    (h1 : ∀ (m : ℕ) (pref : Fin m → C) (v : V),
      (univ.filter fun c => ascend1 m pref c v).card ≤ beta1 v)
    (h2 : ∀ (m : ℕ) (pref : Fin m → C) (v : V),
      (univ.filter fun c => ascend2 m pref c v).card ≤ beta2 v)
    (v : V) (i : Fin T) :
    (univ.filter fun tape : Fin T → C =>
      ascend1 i.val (Sumcheck.extract_prefix tape i) (tape i) v ∧
        ∃ j : Fin T, i.val < j.val ∧
          Linked i.val j.val (Sumcheck.extract_prefix tape i)
            (Sumcheck.extract_prefix tape j) v ∧
          ascend2 j.val (Sumcheck.extract_prefix tape j) (tape j) v).card
      ≤ T * (beta1 v * beta2 v) * Fintype.card C ^ (T - 2) := by
  classical
  set later : Finset (Fin T) := univ.filter (fun j : Fin T => i.val < j.val) with hlater
  calc (univ.filter fun tape : Fin T → C =>
        ascend1 i.val (Sumcheck.extract_prefix tape i) (tape i) v ∧
          ∃ j : Fin T, i.val < j.val ∧
            Linked i.val j.val (Sumcheck.extract_prefix tape i)
              (Sumcheck.extract_prefix tape j) v ∧
            ascend2 j.val (Sumcheck.extract_prefix tape j) (tape j) v).card
      ≤ (Finset.biUnion later fun j =>
          univ.filter fun tape : Fin T → C =>
            ascend1 i.val (Sumcheck.extract_prefix tape i) (tape i) v ∧
              ascend2 j.val (Sumcheck.extract_prefix tape j) (tape j) v).card := by
        apply Finset.card_le_card
        intro tape htape
        simp only [mem_filter, mem_univ, true_and] at htape
        obtain ⟨ha1, j, hij, -, ha2⟩ := htape
        refine Finset.mem_biUnion.mpr ⟨j, ?_, mem_filter.mpr ⟨mem_univ _, ha1, ha2⟩⟩
        simp only [hlater, mem_filter, mem_univ, true_and]
        exact hij
    _ ≤ ∑ j ∈ later, (univ.filter fun tape : Fin T → C =>
          ascend1 i.val (Sumcheck.extract_prefix tape i) (tape i) v ∧
            ascend2 j.val (Sumcheck.extract_prefix tape j) (tape j) v).card :=
        Finset.card_biUnion_le
    _ ≤ ∑ _j ∈ later, beta1 v * beta2 v * Fintype.card C ^ (T - 2) := by
        refine Finset.sum_le_sum ?_
        intro j hj
        have hij : i.val < j.val := by
          simp only [hlater, mem_filter, mem_univ, true_and] at hj
          exact hj
        exact pair_slot_card_le i j hij (beta1 v) (beta2 v)
          (fun pref c => ascend1 i.val pref c v) (fun pref c => ascend2 j.val pref c v)
          (fun pref => h1 i.val pref v) (fun pref => h2 j.val pref v)
    _ = later.card * (beta1 v * beta2 v * Fintype.card C ^ (T - 2)) := by
        simp [Finset.sum_const]
    _ ≤ T * (beta1 v * beta2 v) * Fintype.card C ^ (T - 2) := by
        have hcard : later.card ≤ T := by
          rw [hlater]
          calc (univ.filter (fun j : Fin T => i.val < j.val)).card
              ≤ (univ : Finset (Fin T)).card := Finset.card_filter_le _ _
            _ = T := by simp
        calc later.card * (beta1 v * beta2 v * Fintype.card C ^ (T - 2))
            ≤ T * (beta1 v * beta2 v * Fintype.card C ^ (T - 2)) := by gcongr
          _ = T * (beta1 v * beta2 v) * Fintype.card C ^ (T - 2) := by ring

/--
**The pointwise route to `pair_sum`.**  Per-level bounds sum.  This is what a caller with a
per-level product bound supplies, and it is the *lossy* route whenever the first factor is a tail
rather than a differential -- see the Abel section.
-/
theorem pair_sum_of_pointwise {C : Type} [Fintype C] [DecidableEq C] {V : Type} [Fintype V]
    [DecidableEq V] {T : ℕ}
    (ascend1 ascend2 : ∀ m : ℕ, (Fin m → C) → C → V → Prop)
    (Linked : ∀ m₁ m₂ : ℕ, (Fin m₁ → C) → (Fin m₂ → C) → V → Prop)
    (bound : V → ℕ) (saturated : Finset V) (i : Fin T)
    (hpt : ∀ v : V, (univ.filter fun tape : Fin T → C =>
      ascend1 i.val (Sumcheck.extract_prefix tape i) (tape i) v ∧
        ∃ j : Fin T, i.val < j.val ∧
          Linked i.val j.val (Sumcheck.extract_prefix tape i)
            (Sumcheck.extract_prefix tape j) v ∧
          ascend2 j.val (Sumcheck.extract_prefix tape j) (tape j) v).card
      ≤ bound v * Fintype.card C ^ (T - 2)) :
    (∑ v ∈ saturatedᶜ, (univ.filter fun tape : Fin T → C =>
      ascend1 i.val (Sumcheck.extract_prefix tape i) (tape i) v ∧
        ∃ j : Fin T, i.val < j.val ∧
          Linked i.val j.val (Sumcheck.extract_prefix tape i)
            (Sumcheck.extract_prefix tape j) v ∧
          ascend2 j.val (Sumcheck.extract_prefix tape j) (tape j) v).card)
      ≤ (∑ v ∈ saturatedᶜ, bound v) * Fintype.card C ^ (T - 2) := by
  rw [Finset.sum_mul]
  exact Finset.sum_le_sum fun v _ => hpt v

/--
**The summed route to `betaSat`.**  Union-bound over the saturated levels.  Sound, and the lossy
one: it over-counts by `(n+1)/(r+1)` whenever `beta2` grows across the saturated range.
-/
theorem betaSat_of_sum {C : Type} [Fintype C] [DecidableEq C] {V : Type} [Fintype V]
    [DecidableEq V] (ascend2 : ∀ m : ℕ, (Fin m → C) → C → V → Prop) (beta2 : V → ℕ)
    (h2 : ∀ (m : ℕ) (pref : Fin m → C) (v : V),
      (univ.filter fun c => ascend2 m pref c v).card ≤ beta2 v)
    (saturated : Finset V) (m : ℕ) (pref : Fin m → C) :
    (univ.filter fun c : C => ∃ v ∈ saturated, ascend2 m pref c v).card
      ≤ ∑ v ∈ saturated, beta2 v := by
  classical
  calc (univ.filter fun c : C => ∃ v ∈ saturated, ascend2 m pref c v).card
      ≤ (saturated.biUnion fun v => univ.filter fun c : C => ascend2 m pref c v).card := by
        apply Finset.card_le_card
        intro c hc
        simp only [mem_filter, mem_univ, true_and] at hc
        obtain ⟨v, hv, hgc⟩ := hc
        exact Finset.mem_biUnion.mpr ⟨v, hv, mem_filter.mpr ⟨mem_univ _, hgc⟩⟩
    _ ≤ ∑ v ∈ saturated, (univ.filter fun c : C => ascend2 m pref c v).card :=
        Finset.card_biUnion_le
    _ ≤ ∑ v ∈ saturated, beta2 v := Finset.sum_le_sum fun v _ => h2 m pref v

/--
**The tight route to `betaSat`.**  If the second ascents are nested -- an answer accepting at level
`v` also accepts at every higher level, which is what a monotone cover means -- then the union over
a saturated set is the accepting set at its largest element, and one budget suffices.

This is the clamp-side analogue of `abel_sum_le`, and it is the other half of what parity with a
flat analysis needs: it charges the probability-one term **once**.
-/
theorem betaSat_of_nested {C : Type} [Fintype C] [DecidableEq C] {V : Type} [Fintype V]
    [DecidableEq V] (ascend2 : ∀ m : ℕ, (Fin m → C) → C → V → Prop) (top : V) (betaTop : ℕ)
    (saturated : Finset V)
    (hnest : ∀ (m : ℕ) (pref : Fin m → C) (c : C) (v : V), v ∈ saturated →
      ascend2 m pref c v → ascend2 m pref c top)
    (htop : ∀ (m : ℕ) (pref : Fin m → C),
      (univ.filter fun c => ascend2 m pref c top).card ≤ betaTop)
    (m : ℕ) (pref : Fin m → C) :
    (univ.filter fun c : C => ∃ v ∈ saturated, ascend2 m pref c v).card ≤ betaTop := by
  classical
  refine le_trans (Finset.card_le_card ?_) (htop m pref)
  intro c hc
  simp only [mem_filter, mem_univ, true_and] at hc ⊢
  obtain ⟨v, hv, hasc⟩ := hc
  exact hnest m pref c v hv hasc

/-! ## The graded interface -/

/--
**What the graded count needs.**

`ascend1 m pref c v` says: from the length-`m` history `pref`, the answer `c` takes the state
from `⊥` to level `v`.  `ascend2` is the ascent from `v` to `⊤`.  Both are indexed by the
prefix *length* rather than by a slot of the tape, which is what lets the same predicate be
read at a slot of the tape and at a slot of a longer prefix -- see `pair_slot_card_le`.

`escape` is the deterministic content and, as in `RbrCore`, a field: how one proves it is what
distinguishes a sequential reading from a grinding one.
-/
structure GradedPair (C : Type) [Fintype C] (V : Type) [Fintype V] [DecidableEq V] (T : ℕ)
    (Accepts : (Fin T → C) → Prop) (Fails : Prop) where
  /-- The ascent out of `⊥`, to level `v`. -/
  ascend1 : ∀ m : ℕ, (Fin m → C) → C → V → Prop
  /-- The ascent from level `v` to `⊤`. -/
  ascend2 : ∀ m : ℕ, (Fin m → C) → C → V → Prop
  /-- Per-level budget for the first ascent. -/
  beta1 : V → ℕ
  /-- Per-level budget for the second ascent. -/
  beta2 : V → ℕ
  /-- From any history, at most `beta1 v` answers reach level `v`. -/
  ascend1_card : ∀ (m : ℕ) (pref : Fin m → C) (v : V),
    (univ.filter fun c => ascend1 m pref c v).card ≤ beta1 v
  /-- From any history at level `v`, at most `beta2 v` answers reach `⊤`. -/
  ascend2_card : ∀ (m : ℕ) (pref : Fin m → C) (v : V),
    (univ.filter fun c => ascend2 m pref c v).card ≤ beta2 v
  /-- **The link between the two ascents.**  Read off the two slots' prefixes.  Without it the pair
  count is unprovable: the adversary could make arbitrarily many level-`v` second ascents unrelated
  to the first.  Under Fiat--Shamir this is "the second query point is a successor of the first". -/
  Linked : ∀ m₁ m₂ : ℕ, (Fin m₁ → C) → (Fin m₂ → C) → V → Prop
  /-- **The summed pair charge**, as a function of the clamped set.

  A *sum over levels* rather than a per-level bound, because the tight form of that sum is an Abel
  sum (`abel_sum_le`) and not a pointwise product: the per-level form needs differentials, which a
  proximity theorem does not prove.  `pair_sum_of_pointwise` recovers the pointwise route for a
  caller that has per-level bounds; `abel_sum_le` is the route that keeps the increment damping. -/
  pairSum : Finset V → ℕ
  /-- The pair charge at a fixed first-ascent slot, summed over the unclamped levels.  A **field**
  because the interesting instances are not provable from prefix-measurability alone. -/
  pair_sum : ∀ (saturated : Finset V) (i : Fin T),
    (∑ v ∈ saturatedᶜ, (univ.filter fun tape : Fin T → C =>
      ascend1 i.val (Sumcheck.extract_prefix tape i) (tape i) v ∧
        ∃ j : Fin T, i.val < j.val ∧
          Linked i.val j.val (Sumcheck.extract_prefix tape i)
            (Sumcheck.extract_prefix tape j) v ∧
          ascend2 j.val (Sumcheck.extract_prefix tape j) (tape j) v).card)
      ≤ pairSum saturated * Fintype.card C ^ (T - 2)
  /-- **The clamped charge**, as a single budget for the *union* of the saturated levels' second
  ascents -- not a sum over them.

  The union matters for the same reason the Abel form does.  A level-indexed sum
  `∑ v ∈ saturated, beta2 v` over-counts by the same factor `(n+1)/(r+1)`: the second ascents at
  different saturated levels are events about the *same* answer, so with `beta2` monotone their
  union is the accepting set at the largest saturated level, and one budget suffices.
  `betaSat_of_sum` recovers the summed route; `betaSat_of_monotone` is the tight one. -/
  betaSat : Finset V → ℕ
  betaSat_card : ∀ (saturated : Finset V) (m : ℕ) (pref : Fin m → C),
    (univ.filter fun c : C => ∃ v ∈ saturated, ascend2 m pref c v).card ≤ betaSat saturated
  /-- An accepting tape on which extraction failed made both ascents, in order and linked. -/
  escape : ∀ tape : Fin T → C, Accepts tape → Fails →
    ∃ (v : V) (i j : Fin T), i.val < j.val ∧
      ascend1 i.val (Sumcheck.extract_prefix tape i) (tape i) v ∧
      Linked i.val j.val (Sumcheck.extract_prefix tape i)
        (Sumcheck.extract_prefix tape j) v ∧
      ascend2 j.val (Sumcheck.extract_prefix tape j) (tape j) v

namespace GradedPair

variable {C : Type} [Fintype C] [DecidableEq C] {V : Type} [Fintype V] [DecidableEq V]
variable {T : ℕ} {Accepts : (Fin T → C) → Prop} {Fails : Prop}

/-- At the saturated levels the first ascent is forgotten, so the count is the ungraded one over
the union of their second ascents -- charged **once**, via `betaSat`. -/
theorem saturated_card_le (G : GradedPair C V T Accepts Fails) (saturated : Finset V) :
    (univ.filter fun tape : Fin T → C =>
        ∃ (j : Fin T) (v : V), v ∈ saturated ∧
          G.ascend2 j.val (Sumcheck.extract_prefix tape j) (tape j) v).card
      ≤ T * G.betaSat saturated * Fintype.card C ^ (T - 1) := by
  classical
  have h := Sumcheck.tape_bad_card_le_const (n := T) (G.betaSat saturated)
    (fun j pref c => ∃ v : V, v ∈ saturated ∧ G.ascend2 j.val pref c v)
    (fun j pref => le_trans (Finset.card_le_card (fun c hc => by
      simp only [mem_filter, mem_univ, true_and] at hc ⊢; exact hc))
      (G.betaSat_card saturated j.val pref))
  refine le_trans (le_trans (Finset.card_le_card ?_) h) (le_of_eq ?_)
  · intro tape htape
    simp only [mem_filter, mem_univ, true_and] at htape ⊢
    obtain ⟨j, v, hv, hasc⟩ := htape
    exact ⟨j, v, hv, hasc⟩
  · ring

/--
**The graded count with a clamp.**

For every choice of `saturated`, the accepting-and-failing tapes number at most

* `T · (∑ v ∉ saturated, pairFactor v · beta1 v · beta2 v) · |C|^(T-2)`, the pair charge; plus
* `T · (∑ v ∈ saturated, beta2 v) · |C|^(T-1)`, the clamped charge.

**One** factor of `T` on the pair term, for the choice of first-ascent slot; everything else about
the pair is `pairFactor`.  With `pairFactor = fun _ => T` (`pair_card_of_fanout_free`) this is the
`T²` bound, which ceilings uselessly; with a genuine fan-out it is Target 6.1's two-round instance.
-/
theorem graded_card_le (G : GradedPair C V T Accepts Fails) (saturated : Finset V) :
    (univ.filter fun tape : Fin T → C => Accepts tape ∧ Fails).card
      ≤ T * G.pairSum saturated * Fintype.card C ^ (T - 2)
        + T * G.betaSat saturated * Fintype.card C ^ (T - 1) := by
  classical
  set pairs : Finset (Fin T → C) :=
    Finset.biUnion (saturatedᶜ ×ˢ (univ : Finset (Fin T)))
      (fun t => univ.filter fun tape : Fin T → C =>
        G.ascend1 t.2.val (Sumcheck.extract_prefix tape t.2) (tape t.2) t.1 ∧
          ∃ j : Fin T, t.2.val < j.val ∧
            G.Linked t.2.val j.val (Sumcheck.extract_prefix tape t.2)
              (Sumcheck.extract_prefix tape j) t.1 ∧
            G.ascend2 j.val (Sumcheck.extract_prefix tape j) (tape j) t.1)
    with hpairs
  set clamped : Finset (Fin T → C) :=
    univ.filter fun tape : Fin T → C =>
      ∃ (j : Fin T) (v : V), v ∈ saturated ∧
        G.ascend2 j.val (Sumcheck.extract_prefix tape j) (tape j) v
    with hclamped
  have hcover : (univ.filter fun tape : Fin T → C => Accepts tape ∧ Fails)
      ⊆ pairs ∪ clamped := by
    intro tape htape
    simp only [mem_filter, mem_univ, true_and] at htape
    obtain ⟨v, i, j, hij, h1, hlink, h2⟩ := G.escape tape htape.1 htape.2
    by_cases hv : v ∈ saturated
    · refine Finset.mem_union_right _ ?_
      simp only [hclamped, mem_filter, mem_univ, true_and]
      exact ⟨j, v, hv, h2⟩
    · refine Finset.mem_union_left _ ?_
      refine Finset.mem_biUnion.mpr ⟨(v, i), ?_, ?_⟩
      · simp [Finset.mem_product, Finset.mem_compl, hv]
      · simp only [mem_filter, mem_univ, true_and]
        exact ⟨h1, j, hij, hlink, h2⟩
  have hpairsCard : pairs.card
      ≤ T * G.pairSum saturated * Fintype.card C ^ (T - 2) := by
    calc pairs.card
        ≤ ∑ t ∈ saturatedᶜ ×ˢ (univ : Finset (Fin T)),
            (univ.filter fun tape : Fin T → C =>
              G.ascend1 t.2.val (Sumcheck.extract_prefix tape t.2) (tape t.2) t.1 ∧
                ∃ j : Fin T, t.2.val < j.val ∧
                  G.Linked t.2.val j.val (Sumcheck.extract_prefix tape t.2)
                    (Sumcheck.extract_prefix tape j) t.1 ∧
                  G.ascend2 j.val (Sumcheck.extract_prefix tape j) (tape j) t.1).card :=
          Finset.card_biUnion_le
      _ = ∑ i : Fin T, ∑ v ∈ saturatedᶜ,
            (univ.filter fun tape : Fin T → C =>
              G.ascend1 i.val (Sumcheck.extract_prefix tape i) (tape i) v ∧
                ∃ j : Fin T, i.val < j.val ∧
                  G.Linked i.val j.val (Sumcheck.extract_prefix tape i)
                    (Sumcheck.extract_prefix tape j) v ∧
                  G.ascend2 j.val (Sumcheck.extract_prefix tape j) (tape j) v).card := by
          rw [Finset.sum_product]
          exact Finset.sum_comm
      _ ≤ ∑ _i : Fin T, G.pairSum saturated * Fintype.card C ^ (T - 2) :=
          Finset.sum_le_sum fun i _ => G.pair_sum saturated i
      _ = T * G.pairSum saturated * Fintype.card C ^ (T - 2) := by
          simp [Finset.sum_const, mul_assoc]
  calc (univ.filter fun tape : Fin T → C => Accepts tape ∧ Fails).card
      ≤ (pairs ∪ clamped).card := Finset.card_le_card hcover
    _ ≤ pairs.card + clamped.card := Finset.card_union_le _ _
    _ ≤ T * G.pairSum saturated * Fintype.card C ^ (T - 2)
        + T * G.betaSat saturated * Fintype.card C ^ (T - 1) := by
        refine Nat.add_le_add hpairsCard ?_
        exact le_trans (Finset.card_le_card (fun tape htape => by
          simp only [hclamped, mem_filter, mem_univ, true_and] at htape ⊢
          exact htape)) (G.saturated_card_le saturated)

/--
**Degeneracy check: `saturated = univ` is the ungraded bound.**

With every level clamped the pair term vanishes and what is left is one union bound over the
second ascent -- which is what `RbrCore.rbr_card_le` proves, with the level information thrown
away.  So grading is a refinement and never a loss.
-/
theorem graded_card_le_clamp_all (G : GradedPair C V T Accepts Fails)
    (hzero : G.pairSum univ = 0) :
    (univ.filter fun tape : Fin T → C => Accepts tape ∧ Fails).card
      ≤ T * G.betaSat univ * Fintype.card C ^ (T - 1) := by
  have h := G.graded_card_le (univ : Finset V)
  simpa [hzero] using h

/--
**The graded count as a probability.**

`T · pairSum / |C|²  +  T · betaSat / |C|`.
-/
theorem graded_ratio_le [Nonempty C] (G : GradedPair C V T Accepts Fails)
    (saturated : Finset V) (hT : 2 ≤ T) :
    ((univ.filter fun tape : Fin T → C => Accepts tape ∧ Fails).card : ℚ)
        / (Fintype.card C : ℚ) ^ T
      ≤ ((T * G.pairSum saturated : ℕ) : ℚ) / (Fintype.card C : ℚ) ^ 2
        + ((T * G.betaSat saturated : ℕ) : ℚ) / (Fintype.card C : ℚ) := by
  have hCpos : (0 : ℚ) < (Fintype.card C : ℚ) := by
    have : 0 < Fintype.card C := Fintype.card_pos
    exact_mod_cast this
  have hTpow : (0 : ℚ) < (Fintype.card C : ℚ) ^ T := pow_pos hCpos T
  have e2 : (Fintype.card C : ℚ) ^ T
      = (Fintype.card C : ℚ) ^ 2 * (Fintype.card C : ℚ) ^ (T - 2) := by
    rw [← pow_add]; congr 1; omega
  have e1 : (Fintype.card C : ℚ) ^ T
      = (Fintype.card C : ℚ) * (Fintype.card C : ℚ) ^ (T - 1) := by
    rw [← pow_succ']; congr 1; omega
  rw [div_le_iff₀ hTpow]
  have hcast : ((univ.filter fun tape : Fin T → C => Accepts tape ∧ Fails).card : ℚ)
      ≤ ((T * G.pairSum saturated : ℕ) : ℚ) * (Fintype.card C : ℚ) ^ (T - 2)
        + ((T * G.betaSat saturated : ℕ) : ℚ) * (Fintype.card C : ℚ) ^ (T - 1) := by
    exact_mod_cast G.graded_card_le saturated
  refine le_trans hcast (le_of_eq ?_)
  have d2 : (Fintype.card C : ℚ) ^ T / (Fintype.card C : ℚ) ^ 2
      = (Fintype.card C : ℚ) ^ (T - 2) := by
    rw [e2, mul_comm, mul_div_assoc, div_self (ne_of_gt (pow_pos hCpos 2)), mul_one]
  have d1 : (Fintype.card C : ℚ) ^ T / (Fintype.card C : ℚ)
      = (Fintype.card C : ℚ) ^ (T - 1) := by
    rw [e1, mul_comm, mul_div_assoc, div_self (ne_of_gt hCpos), mul_one]
  rw [add_mul, div_mul_eq_mul_div, div_mul_eq_mul_div, mul_div_assoc, mul_div_assoc, d2, d1]

end GradedPair
end Bcs
