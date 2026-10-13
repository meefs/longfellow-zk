import Bcs.ResponseRigid
import Merkle.LazyTape
import Sumcheck.Grinding
import LigeroFamily.Soundness.Hypergeometric

/-!
# Two typed Fiat--Shamir oracles on one lazy-sampling tape

The batching oracle and subset oracle have different answer types.  We model
them with sum-tagged query keys and a paired answer at every lazy-sampling
slot.  An `H₁` query reads the first projection and an `H₂` query reads the
second.  The unused projection is independent and cancels from finite counts,
so this is exactly two independent typed random oracles while retaining the
existing homogeneous `Merkle.RandomOracle.Tree` infrastructure.

This file also performs the operational `Q + 2` augmentation: after an
adversary run, append either defining query if it was not already asked.  The
result is a `FirstOccurrenceTrace` with domain separation and the slot bound
proved, rather than assumed by a downstream rigid ledger.
-/

set_option autoImplicit false
set_option relaxedAutoImplicit false

namespace Bcs.TypedFiatShamir

/-- Domain-separated keys for the two typed random oracles. -/
inductive Query (AlphaKey SubsetKey : Type*) where
  | alpha (key : AlphaKey)
  | subset (key : SubsetKey)
deriving DecidableEq

/-- One homogeneous tape slot contains independent answers for both domains. -/
abbrev Answer (Alpha Subset : Type*) := Alpha × Subset

def alphaAnswer {Alpha Subset : Type*} (answer : Answer Alpha Subset) : Alpha :=
  answer.1

def subsetAnswer {Alpha Subset : Type*} (answer : Answer Alpha Subset) : Subset :=
  answer.2

/-- The unused subset coordinate cancels exactly from any one-slot event that
depends only on the batching answer. -/
theorem alpha_projection_card
    {Alpha Subset : Type*} [Fintype Alpha] [Fintype Subset]
    (event : Alpha → Prop) [DecidablePred event] :
    (Finset.univ.filter (fun answer : Answer Alpha Subset ↦
      event (alphaAnswer answer))).card =
      Fintype.card Subset * (Finset.univ.filter event).card := by
  rw [Bcs.card_filter_prod_fst]
  calc
    ∑ x : Alpha, (Finset.univ.filter fun _answer : Subset ↦ event x).card =
        ∑ x : Alpha, if event x then Fintype.card Subset else 0 := by
      apply Finset.sum_congr rfl
      intro x _
      by_cases hx : event x <;> simp [hx]
    _ = Fintype.card Subset *
          ∑ x : Alpha, if event x then 1 else 0 := by
      rw [Finset.mul_sum]
      apply Finset.sum_congr rfl
      intro x _
      split <;> simp_all
    _ = _ := by simp

/-- Symmetrically, the unused batching coordinate cancels exactly from an
event depending only on the subset-oracle answer. -/
theorem subset_projection_card
    {Alpha Subset : Type*} [Fintype Alpha] [Fintype Subset]
    (event : Subset → Prop) [DecidablePred event] :
    (Finset.univ.filter (fun answer : Answer Alpha Subset ↦
      event (subsetAnswer answer))).card =
      Fintype.card Alpha * (Finset.univ.filter event).card := by
  rw [Bcs.card_filter_prod_snd]
  calc
    ∑ x : Subset, (Finset.univ.filter fun _answer : Alpha ↦ event x).card =
        ∑ x : Subset, if event x then Fintype.card Alpha else 0 := by
      apply Finset.sum_congr rfl
      intro x _
      by_cases hx : event x <;> simp [hx]
    _ = Fintype.card Alpha *
          ∑ x : Subset, if event x then 1 else 0 := by
      rw [Finset.mul_sum]
      apply Finset.sum_congr rfl
      intro x _
      split <;> simp_all
    _ = _ := by simp

/-! ## Two fresh typed coordinates -/

/-- The coordinates of a tape other than two distinguished slots. -/
abbrev TwoSlotRemainder (T : ℕ) (i j : Fin T) (D : Type*) :=
  { k : Fin T // k ≠ i ∧ k ≠ j } → D

/-- All tape information except the two projections used by a typed
`(subset, alpha)` incidence test.  The unused projection at each selected
slot is retained in the first component. -/
abbrev TwoSlotData (Alpha Subset : Type*) (T : ℕ)
    (subsetSlot alphaSlot : Fin T) :=
  Answer Alpha Subset ×
    TwoSlotRemainder T subsetSlot alphaSlot (Answer Alpha Subset)

def twoSlotData {Alpha Subset : Type*} {T : ℕ}
    (subsetSlot alphaSlot : Fin T) (tape : Fin T → Answer Alpha Subset) :
    TwoSlotData Alpha Subset T subsetSlot alphaSlot :=
  ((alphaAnswer (tape subsetSlot), subsetAnswer (tape alphaSlot)),
    fun k => tape k.1)

/-- Removing two distinct coordinates from a `T`-slot tape leaves `T - 2`
coordinates. -/
theorem card_twoSlotRemainder_index {T : ℕ} (i j : Fin T) (hne : i ≠ j) :
    Fintype.card { k : Fin T // k ≠ i ∧ k ≠ j } = T - 2 := by
  classical
  rw [Fintype.card_subtype]
  change (Finset.univ.filter fun k : Fin T => k ≠ i ∧ k ≠ j).card = T - 2
  rw [show Finset.univ.filter (fun k : Fin T => k ≠ i ∧ k ≠ j) =
      Finset.univ \ {i, j} by ext k; simp]
  rw [Finset.card_sdiff]
  simp [hne]

/-- A predicate using the subset projection at one slot and the alpha
projection at a different slot has exactly one full answer coordinate's
worth of unused projections.  Thus a `pairBudget` bound on independent
`(subset, alpha)` pairs lifts to

`pairBudget * |Alpha × Subset|^(T-1)`

full paired-answer tapes.  This is the fixed-two-slot kernel used for Case B
and for the conservative Case-A pair charge; no independence formula is
assumed by callers. -/
theorem two_projection_tape_card_le
    {Alpha Subset : Type*} [Fintype Alpha] [Fintype Subset]
    [DecidableEq Alpha] [DecidableEq Subset]
    {T : ℕ} (i j : Fin T) (hne : i ≠ j)
    (success : Subset → Alpha → Prop) [DecidableRel success] (pairBudget : ℕ)
    (hpairs : (Finset.univ.filter fun pair : Subset × Alpha =>
      success pair.1 pair.2).card ≤ pairBudget) :
    (Finset.univ.filter fun tape : Fin T → Answer Alpha Subset =>
      success (subsetAnswer (tape i)) (alphaAnswer (tape j))).card ≤
        pairBudget * Fintype.card (Answer Alpha Subset) ^ (T - 1) := by
  classical
  let Remainder := TwoSlotRemainder T i j (Answer Alpha Subset)
  let Data := Answer Alpha Subset × Remainder
  let pairOf : (Fin T → Answer Alpha Subset) → Subset × Alpha := fun tape =>
    (subsetAnswer (tape i), alphaAnswer (tape j))
  let dataOf : (Fin T → Answer Alpha Subset) → Data := fun tape =>
    ((alphaAnswer (tape i), subsetAnswer (tape j)), fun k => tape k.1)
  have hsplit : Function.Injective (fun tape => (pairOf tape, dataOf tape)) := by
    intro first second heq
    funext k
    by_cases hki : k = i
    · subst k
      apply Prod.ext
      · exact congrArg (fun value => value.2.1.1) heq
      · exact congrArg (fun value => value.1.1) heq
    · by_cases hkj : k = j
      · subst k
        apply Prod.ext
        · exact congrArg (fun value => value.1.2) heq
        · exact congrArg (fun value => value.2.1.2) heq
      · exact congrFun (congrArg (fun value => value.2.2) heq) ⟨k, hki, hkj⟩
  have hT : 2 ≤ T := by
    have hi := i.isLt
    have hj := j.isLt
    have hv : i.val ≠ j.val := fun h => hne (Fin.ext h)
    omega
  have hdata : Fintype.card Data =
      Fintype.card (Answer Alpha Subset) ^ (T - 1) := by
    dsimp [Data, Remainder, TwoSlotRemainder]
    rw [Fintype.card_prod, Fintype.card_fun,
      card_twoSlotRemainder_index i j hne]
    rw [show T - 1 = (T - 2) + 1 by omega, pow_succ]
    ring
  let pairs : Finset (Subset × Alpha) := Finset.univ.filter fun pair =>
    success pair.1 pair.2
  calc
    (Finset.univ.filter fun tape : Fin T → Answer Alpha Subset =>
        success (subsetAnswer (tape i)) (alphaAnswer (tape j))).card
        ≤ (pairs ×ˢ (Finset.univ : Finset Data)).card := by
          apply Finset.card_le_card_of_injOn (fun tape => (pairOf tape, dataOf tape))
          · intro tape htape
            exact Finset.mem_product.mpr ⟨Finset.mem_filter.mpr
              ⟨Finset.mem_univ _, (Finset.mem_filter.mp htape).2⟩,
                Finset.mem_univ _⟩
          · intro first hfirst second hsecond heq
            exact hsplit heq
    _ = pairs.card * Fintype.card Data := by simp
    _ ≤ pairBudget * Fintype.card Data :=
      Nat.mul_le_mul_right _ (by simpa [pairs] using hpairs)
    _ = pairBudget * Fintype.card (Answer Alpha Subset) ^ (T - 1) := by
      rw [hdata]

/-- The fixed-two-slot kernel with an accepting relation allowed to depend on
every other tape coordinate.  This is the form required for adversarially
selected responses: after the other randomness is fixed, callers prove the
same independent `(subset, alpha)` pair bound for the resulting strategy.
-/
theorem two_projection_dependent_tape_card_le
    {Alpha Subset : Type*} [Fintype Alpha] [Fintype Subset]
    [DecidableEq Alpha] [DecidableEq Subset]
    {T : ℕ} (subsetSlot alphaSlot : Fin T) (hne : subsetSlot ≠ alphaSlot)
    (success : TwoSlotData Alpha Subset T subsetSlot alphaSlot →
      Subset → Alpha → Prop) [∀ data, DecidableRel (success data)]
    (pairBudget : ℕ)
    (hpairs : ∀ data,
      (Finset.univ.filter fun pair : Subset × Alpha =>
        success data pair.1 pair.2).card ≤ pairBudget) :
    (Finset.univ.filter fun tape : Fin T → Answer Alpha Subset =>
      success (twoSlotData subsetSlot alphaSlot tape)
        (subsetAnswer (tape subsetSlot))
        (alphaAnswer (tape alphaSlot))).card ≤
      pairBudget * Fintype.card (Answer Alpha Subset) ^ (T - 1) := by
  classical
  let Data := TwoSlotData Alpha Subset T subsetSlot alphaSlot
  let pairOf : (Fin T → Answer Alpha Subset) → Subset × Alpha := fun tape =>
    (subsetAnswer (tape subsetSlot), alphaAnswer (tape alphaSlot))
  let dataOf : (Fin T → Answer Alpha Subset) → Data :=
    twoSlotData subsetSlot alphaSlot
  have hsplit : Function.Injective (fun tape => (dataOf tape, pairOf tape)) := by
    intro first second heq
    funext k
    by_cases hks : k = subsetSlot
    · subst k
      apply Prod.ext
      · exact congrArg (fun value => value.1.1.1) heq
      · exact congrArg (fun value => value.2.1) heq
    · by_cases hka : k = alphaSlot
      · subst k
        apply Prod.ext
        · exact congrArg (fun value => value.2.2) heq
        · exact congrArg (fun value => value.1.1.2) heq
      · exact congrFun (congrArg (fun value => value.1.2) heq) ⟨k, hks, hka⟩
  let good : Finset (Data × (Subset × Alpha)) := Finset.univ.filter fun value =>
    success value.1 value.2.1 value.2.2
  have hgood : good.card ≤ Fintype.card Data * pairBudget := by
    rw [show good.card = ∑ data : Data,
        (Finset.univ.filter fun pair : Subset × Alpha =>
          success data pair.1 pair.2).card by
      dsimp [good]
      rw [Bcs.card_filter_prod_fst]]
    calc
      ∑ data : Data, (Finset.univ.filter fun pair : Subset × Alpha =>
          success data pair.1 pair.2).card
        ≤ ∑ _data : Data, pairBudget :=
          Finset.sum_le_sum (fun data _ => hpairs data)
      _ = Fintype.card Data * pairBudget := by simp
  have hT : 2 ≤ T := by
    have hs := subsetSlot.isLt
    have ha := alphaSlot.isLt
    have hv : subsetSlot.val ≠ alphaSlot.val := fun h => hne (Fin.ext h)
    omega
  have hdata : Fintype.card Data =
      Fintype.card (Answer Alpha Subset) ^ (T - 1) := by
    dsimp [Data, TwoSlotData, TwoSlotRemainder]
    rw [Fintype.card_prod, Fintype.card_fun,
      card_twoSlotRemainder_index subsetSlot alphaSlot hne]
    rw [show T - 1 = (T - 2) + 1 by omega, pow_succ]
    ring
  calc
    (Finset.univ.filter fun tape : Fin T → Answer Alpha Subset =>
        success (twoSlotData subsetSlot alphaSlot tape)
          (subsetAnswer (tape subsetSlot))
          (alphaAnswer (tape alphaSlot))).card
      ≤ good.card := by
        apply Finset.card_le_card_of_injOn (fun tape => (dataOf tape, pairOf tape))
        · intro tape htape
          exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
            (Finset.mem_filter.mp htape).2⟩
        · intro first hfirst second hsecond heq
          exact hsplit heq
    _ ≤ Fintype.card Data * pairBudget := hgood
    _ = pairBudget * Fintype.card (Answer Alpha Subset) ^ (T - 1) := by
      rw [hdata]
      ring

/-- Probability form of the strategy-dependent fixed-pair kernel.  Callers
may provide a rational density theorem for every fixed remainder, so no
rounding to an assumed integer numerator is needed. -/
theorem two_projection_dependent_tape_ratio_le
    {Alpha Subset : Type*} [Fintype Alpha] [Fintype Subset]
    [DecidableEq Alpha] [DecidableEq Subset]
    [Nonempty Alpha] [Nonempty Subset]
    {T : ℕ} (subsetSlot alphaSlot : Fin T) (hne : subsetSlot ≠ alphaSlot)
    (success : TwoSlotData Alpha Subset T subsetSlot alphaSlot →
      Subset → Alpha → Prop) [∀ data, DecidableRel (success data)]
    (epsilon : ℚ)
    (hpairs : ∀ data,
      ((Finset.univ.filter fun pair : Subset × Alpha =>
        success data pair.1 pair.2).card : ℚ) /
          (Fintype.card Subset * Fintype.card Alpha) ≤ epsilon) :
    ((Finset.univ.filter fun tape : Fin T → Answer Alpha Subset =>
      success (twoSlotData subsetSlot alphaSlot tape)
        (subsetAnswer (tape subsetSlot))
        (alphaAnswer (tape alphaSlot))).card : ℚ) /
      (Fintype.card (Answer Alpha Subset) : ℚ) ^ T ≤ epsilon := by
  classical
  let Data := TwoSlotData Alpha Subset T subsetSlot alphaSlot
  let pairOf : (Fin T → Answer Alpha Subset) → Subset × Alpha := fun tape =>
    (subsetAnswer (tape subsetSlot), alphaAnswer (tape alphaSlot))
  let dataOf : (Fin T → Answer Alpha Subset) → Data :=
    twoSlotData subsetSlot alphaSlot
  have hsplit : Function.Injective (fun tape => (dataOf tape, pairOf tape)) := by
    intro first second heq
    funext k
    by_cases hks : k = subsetSlot
    · subst k
      apply Prod.ext
      · exact congrArg (fun value => value.1.1.1) heq
      · exact congrArg (fun value => value.2.1) heq
    · by_cases hka : k = alphaSlot
      · subst k
        apply Prod.ext
        · exact congrArg (fun value => value.2.2) heq
        · exact congrArg (fun value => value.1.1.2) heq
      · exact congrFun (congrArg (fun value => value.1.2) heq) ⟨k, hks, hka⟩
  let event : Finset (Fin T → Answer Alpha Subset) := Finset.univ.filter fun tape =>
    success (twoSlotData subsetSlot alphaSlot tape)
      (subsetAnswer (tape subsetSlot)) (alphaAnswer (tape alphaSlot))
  let good : Finset (Data × (Subset × Alpha)) := Finset.univ.filter fun value =>
    success value.1 value.2.1 value.2.2
  have hevent : event.card ≤ good.card := by
    apply Finset.card_le_card_of_injOn (fun tape => (dataOf tape, pairOf tape))
    · intro tape htape
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
        (Finset.mem_filter.mp htape).2⟩
    · intro first hfirst second hsecond heq
      exact hsplit heq
  have hpairDen : (0 : ℚ) <
      Fintype.card Subset * Fintype.card Alpha := by
    have hSubset : 0 < Fintype.card Subset := Fintype.card_pos
    have hAlpha : 0 < Fintype.card Alpha := Fintype.card_pos
    exact_mod_cast Nat.mul_pos hSubset hAlpha
  have hanswerCard : (Fintype.card (Answer Alpha Subset) : ℚ) =
      Fintype.card Subset * Fintype.card Alpha := by
    simp [Answer, mul_comm]
  have hpair (data : Data) :
      ((Finset.univ.filter fun pair : Subset × Alpha =>
        success data pair.1 pair.2).card : ℚ) ≤
          epsilon * Fintype.card (Answer Alpha Subset) := by
    have h := (div_le_iff₀ hpairDen).mp (hpairs data)
    rw [hanswerCard]
    exact h
  have hgoodEq : good.card = ∑ data : Data,
      (Finset.univ.filter fun pair : Subset × Alpha =>
        success data pair.1 pair.2).card := by
    dsimp [good]
    rw [Bcs.card_filter_prod_fst]
  have hgood : (good.card : ℚ) ≤
      Fintype.card Data *
        (epsilon * Fintype.card (Answer Alpha Subset)) := by
    rw [hgoodEq]
    push_cast
    calc
      ∑ data : Data, ((Finset.univ.filter fun pair : Subset × Alpha =>
          success data pair.1 pair.2).card : ℚ)
        ≤ ∑ _data : Data,
            epsilon * Fintype.card (Answer Alpha Subset) :=
          Finset.sum_le_sum (fun data _ => hpair data)
      _ = Fintype.card Data *
          (epsilon * Fintype.card (Answer Alpha Subset)) := by simp
  have hT : 2 ≤ T := by
    have hs := subsetSlot.isLt
    have ha := alphaSlot.isLt
    have hv : subsetSlot.val ≠ alphaSlot.val := fun h => hne (Fin.ext h)
    omega
  have hdata : (Fintype.card Data : ℚ) =
      (Fintype.card (Answer Alpha Subset) : ℚ) ^ (T - 1) := by
    have hnat : Fintype.card Data =
        Fintype.card (Answer Alpha Subset) ^ (T - 1) := by
      dsimp [Data, TwoSlotData, TwoSlotRemainder]
      rw [Fintype.card_prod, Fintype.card_fun,
        card_twoSlotRemainder_index subsetSlot alphaSlot hne]
      rw [show T - 1 = (T - 2) + 1 by omega, pow_succ]
      ring
    exact_mod_cast hnat
  have hN : (0 : ℚ) < Fintype.card (Answer Alpha Subset) := by
    exact_mod_cast Fintype.card_pos
  have hpow : (Fintype.card (Answer Alpha Subset) : ℚ) ^ T =
      (Fintype.card (Answer Alpha Subset) : ℚ) ^ (T - 1) *
        Fintype.card (Answer Alpha Subset) := by
    calc
      (Fintype.card (Answer Alpha Subset) : ℚ) ^ T =
          (Fintype.card (Answer Alpha Subset) : ℚ) ^ ((T - 1) + 1) := by
            congr 1
            omega
      _ = _ := pow_succ _ _
  rw [div_le_iff₀ (pow_pos hN T)]
  calc
    ((Finset.univ.filter fun tape : Fin T → Answer Alpha Subset =>
        success (twoSlotData subsetSlot alphaSlot tape)
          (subsetAnswer (tape subsetSlot))
          (alphaAnswer (tape alphaSlot))).card : ℚ)
      ≤ (good.card : ℚ) := by exact_mod_cast hevent
    _ ≤ Fintype.card Data *
        (epsilon * Fintype.card (Answer Alpha Subset)) := hgood
    _ = epsilon * (Fintype.card (Answer Alpha Subset) : ℚ) ^ T := by
      rw [hdata, hpow]
      ring

/-! ## Tight predictable second-slot counts -/

/-- Remove one fixed tape slot and expose the other slots as `(noise, fresh)`
pairs.  If the selected remaining slot is predictable, a uniform independent
pair bound is paid once, even when the successful relation depends on all
retained tape data.

The tape has `N + 2` slots: one fixed charged slot and `N + 1` possible
stopping slots.  Unlike the conservative `later_*_slot` lemmas below, this
theorem has no `N + 1` union factor. -/
theorem predictable_other_slot_tape_card_le
    {D Z A : Type*} [Fintype D] [Fintype Z] [Fintype A]
    [DecidableEq D] [DecidableEq Z] [DecidableEq A]
    {N : ℕ} (fixedSlot : Fin (N + 2)) (split : D ≃ Z × A)
    (select : D → (Fin (N + 1) → Z × A) → Fin (N + 1))
    (hselect : Bcs.IsPredictableSelector select)
    (success : ((Fin (N + 1) → Z) × (Fin N → A)) → D → A → Prop)
    [∀ data, DecidableRel (success data)]
    (event : (Fin (N + 2) → D) → Prop) [DecidablePred event]
    (pairBudget : ℕ)
    (hpairs : ∀ data, (Finset.univ.filter fun pair : D × A ↦
      success data pair.1 pair.2).card ≤ pairBudget)
    (hcover : ∀ tape, event tape →
      let fixed := tape fixedSlot
      let rest := fun k ↦ split (tape (fixedSlot.succAbove k))
      let selected := select fixed rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (selected.succAbove k)).2)
      success data fixed (rest selected).2) :
    (Finset.univ.filter event).card ≤
      pairBudget * Fintype.card Z ^ (N + 1) * Fintype.card A ^ N := by
  classical
  let Seq := Fin (N + 1) → Z × A
  let encode : (Fin (N + 2) → D) → D × Seq := fun tape ↦
    (tape fixedSlot, fun k ↦ split (tape (fixedSlot.succAbove k)))
  have hencode : Function.Injective encode := by
    intro first second heq
    funext k
    by_cases hk : k = fixedSlot
    · subst k
      exact congrArg Prod.fst heq
    · obtain ⟨l, hl⟩ := Fin.exists_succAbove_eq hk
      have hrest := congrFun (congrArg Prod.snd heq) l
      exact split.injective (by simpa [encode, hl] using hrest)
  let good : Finset (D × Seq) := Finset.univ.filter fun input ↦
    let selected := select input.1 input.2
    let data := ((fun k ↦ (input.2 k).1),
      fun k ↦ (input.2 (selected.succAbove k)).2)
    success data input.1 (input.2 selected).2
  have hevent : (Finset.univ.filter event).card ≤ good.card := by
    apply Finset.card_le_card_of_injOn encode
    · intro tape htape
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, by
        simpa [encode] using hcover tape (Finset.mem_filter.mp htape).2⟩
    · intro first _ second _ heq
      exact hencode heq
  have hgood : good.card ≤
      pairBudget * Fintype.card Z ^ (N + 1) * Fintype.card A ^ N := by
    simpa [good, Seq] using Bcs.predictable_stopping_dependent_card_le
      select hselect success pairBudget hpairs
  exact hevent.trans hgood

/-- Order-branch version of `predictable_other_slot_tape_card_le`.  It is
enough that the selector be predictable between tapes in the relevant
first-occurrence branch. -/
theorem predictable_other_slot_tape_on_card_le
    {D Z A : Type*} [Fintype D] [Fintype Z] [Fintype A]
    [DecidableEq D] [DecidableEq Z] [DecidableEq A]
    {N : ℕ} (fixedSlot : Fin (N + 2)) (split : D ≃ Z × A)
    (select : D → (Fin (N + 1) → Z × A) → Fin (N + 1))
    (admissible : D × (Fin (N + 1) → Z × A) → Prop)
    [DecidablePred admissible]
    (hselect : Bcs.IsPredictableSelectorOn admissible select)
    (success : ((Fin (N + 1) → Z) × (Fin N → A)) → D → A → Prop)
    [∀ data, DecidableRel (success data)]
    (event : (Fin (N + 2) → D) → Prop) [DecidablePred event]
    (pairBudget : ℕ)
    (hpairs : ∀ data, (Finset.univ.filter fun pair : D × A ↦
      success data pair.1 pair.2).card ≤ pairBudget)
    (hcover : ∀ tape, event tape →
      let fixed := tape fixedSlot
      let rest := fun k ↦ split (tape (fixedSlot.succAbove k))
      let selected := select fixed rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (selected.succAbove k)).2)
      admissible (fixed, rest) ∧ success data fixed (rest selected).2) :
    (Finset.univ.filter event).card ≤
      pairBudget * Fintype.card Z ^ (N + 1) * Fintype.card A ^ N := by
  classical
  let Seq := Fin (N + 1) → Z × A
  let encode : (Fin (N + 2) → D) → D × Seq := fun tape ↦
    (tape fixedSlot, fun k ↦ split (tape (fixedSlot.succAbove k)))
  have hencode : Function.Injective encode := by
    intro first second heq
    funext k
    by_cases hk : k = fixedSlot
    · subst k
      exact congrArg Prod.fst heq
    · obtain ⟨l, hl⟩ := Fin.exists_succAbove_eq hk
      have hrest := congrFun (congrArg Prod.snd heq) l
      exact split.injective (by simpa [encode, hl] using hrest)
  let good : Finset (D × Seq) := Finset.univ.filter fun input ↦
    admissible input ∧
    let selected := select input.1 input.2
    let data := ((fun k ↦ (input.2 k).1),
      fun k ↦ (input.2 (selected.succAbove k)).2)
    success data input.1 (input.2 selected).2
  have hevent : (Finset.univ.filter event).card ≤ good.card := by
    apply Finset.card_le_card_of_injOn encode
    · intro tape htape
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, by
        simpa [encode] using hcover tape (Finset.mem_filter.mp htape).2⟩
    · intro first _ second _ heq
      exact hencode heq
  have hgood : good.card ≤
      pairBudget * Fintype.card Z ^ (N + 1) * Fintype.card A ^ N := by
    simpa [good, Seq] using Bcs.predictable_stopping_dependent_on_card_le
      select admissible hselect success pairBudget hpairs
  exact hevent.trans hgood

/-- Exact-density form of `predictable_other_slot_tape_on_card_le`. -/
theorem predictable_other_slot_tape_on_ratio_le
    {D Z A : Type*} [Fintype D] [Fintype Z] [Fintype A]
    [DecidableEq D] [DecidableEq Z] [DecidableEq A]
    [Nonempty D] [Nonempty Z] [Nonempty A]
    {N : ℕ} (fixedSlot : Fin (N + 2)) (split : D ≃ Z × A)
    (select : D → (Fin (N + 1) → Z × A) → Fin (N + 1))
    (admissible : D × (Fin (N + 1) → Z × A) → Prop)
    [DecidablePred admissible]
    (hselect : Bcs.IsPredictableSelectorOn admissible select)
    (success : ((Fin (N + 1) → Z) × (Fin N → A)) → D → A → Prop)
    [∀ data, DecidableRel (success data)]
    (event : (Fin (N + 2) → D) → Prop) [DecidablePred event]
    (epsilon : ℚ)
    (hpairs : ∀ data, ((Finset.univ.filter fun pair : D × A ↦
      success data pair.1 pair.2).card : ℚ) /
        (Fintype.card D * Fintype.card A) ≤ epsilon)
    (hcover : ∀ tape, event tape →
      let fixed := tape fixedSlot
      let rest := fun k ↦ split (tape (fixedSlot.succAbove k))
      let selected := select fixed rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (selected.succAbove k)).2)
      admissible (fixed, rest) ∧ success data fixed (rest selected).2) :
    ((Finset.univ.filter event).card : ℚ) /
        Fintype.card (Fin (N + 2) → D) ≤ epsilon := by
  classical
  let Seq := Fin (N + 1) → Z × A
  let encode : (Fin (N + 2) → D) → D × Seq := fun tape ↦
    (tape fixedSlot, fun k ↦ split (tape (fixedSlot.succAbove k)))
  have hencode : Function.Injective encode := by
    intro first second heq
    funext k
    by_cases hk : k = fixedSlot
    · subst k
      exact congrArg Prod.fst heq
    · obtain ⟨l, hl⟩ := Fin.exists_succAbove_eq hk
      have hrest := congrFun (congrArg Prod.snd heq) l
      exact split.injective (by simpa [encode, hl] using hrest)
  let good : Finset (D × Seq) := Finset.univ.filter fun input ↦
    admissible input ∧
    let selected := select input.1 input.2
    let data := ((fun k ↦ (input.2 k).1),
      fun k ↦ (input.2 (selected.succAbove k)).2)
    success data input.1 (input.2 selected).2
  have hevent : (Finset.univ.filter event).card ≤ good.card := by
    apply Finset.card_le_card_of_injOn encode
    · intro tape htape
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, by
        simpa [encode] using hcover tape (Finset.mem_filter.mp htape).2⟩
    · intro first _ second _ heq
      exact hencode heq
  have hgood : (good.card : ℚ) / Fintype.card (D × Seq) ≤ epsilon := by
    simpa [good, Seq] using Bcs.predictable_stopping_dependent_on_ratio_le
      select admissible hselect success epsilon hpairs
  have hsplitCard : Fintype.card D = Fintype.card Z * Fintype.card A := by
    simpa using Fintype.card_congr split
  have hcard : Fintype.card (Fin (N + 2) → D) = Fintype.card (D × Seq) := by
    simp only [Seq, Fintype.card_fun, Fintype.card_fin, Fintype.card_prod]
    rw [hsplitCard, pow_succ']
  rw [hcard]
  exact hgood.trans' (div_le_div_of_nonneg_right
    (by exact_mod_cast hevent)
    (by exact_mod_cast (Nat.zero_le (Fintype.card (D × Seq)))))

/-- Tight Case-B typed-tape count.  The defining subset answer is at the
fixed H₂ slot and the later alpha answer is selected predictably among all
other slots.  Exceptional alphas pay only their increment above the common
good baseline, and there is no inner slot union. -/
theorem ligero_caseB_predictable_tape_card_le
    {Alpha : Type*} [Fintype Alpha] [DecidableEq Alpha]
    {n r N goodCap absoluteCap badCount : ℕ}
    (fixedSlot : Fin (N + 2))
    (select : Answer Alpha (LigeroFamily.QuerySet n r) →
      (Fin (N + 1) → LigeroFamily.QuerySet n r × Alpha) → Fin (N + 1))
    (admissible : Answer Alpha (LigeroFamily.QuerySet n r) ×
      (Fin (N + 1) → LigeroFamily.QuerySet n r × Alpha) → Prop)
    [DecidablePred admissible]
    (hselect : Bcs.IsPredictableSelectorOn admissible select)
    (event : (Fin (N + 2) →
      Answer Alpha (LigeroFamily.QuerySet n r)) → Prop)
    [DecidablePred event]
    (bad : Finset Alpha) (allowed : Alpha → Finset (Fin n))
    (hbad : bad.card ≤ badCount)
    (hgood : ∀ alpha ∉ bad, (allowed alpha).card ≤ goodCap)
    (habsolute : ∀ alpha, (allowed alpha).card ≤ absoluteCap)
    (hcaps : goodCap ≤ absoluteCap)
    (hcover : ∀ tape, event tape →
      let fixed := tape fixedSlot
      let rest := fun k ↦ (tape (fixedSlot.succAbove k)).swap
      let selected := select fixed rest
      admissible (fixed, rest) ∧
        (subsetAnswer fixed).coordinates ⊆ allowed (rest selected).2) :
    (Finset.univ.filter event).card ≤
      (Fintype.card Alpha * goodCap.choose r +
        badCount * (absoluteCap.choose r - goodCap.choose r)) *
      Fintype.card (Answer Alpha (LigeroFamily.QuerySet n r)) ^ (N + 1) := by
  classical
  let pairBudget := Fintype.card Alpha * goodCap.choose r +
    badCount * (absoluteCap.choose r - goodCap.choose r)
  have hbase := Bcs.alpha_last_pair_card_le_tight (r := r)
    bad allowed hbad hgood habsolute hcaps
  let success : ((Fin (N + 1) → LigeroFamily.QuerySet n r) ×
      (Fin N → Alpha)) →
      Answer Alpha (LigeroFamily.QuerySet n r) → Alpha → Prop :=
    fun _data fixed alpha ↦
      (subsetAnswer fixed).coordinates ⊆ allowed alpha
  have hpairs : ∀ data,
      (Finset.univ.filter fun pair :
        Answer Alpha (LigeroFamily.QuerySet n r) × Alpha ↦
        success data pair.1 pair.2).card ≤
          Fintype.card Alpha * pairBudget := by
    intro data
    rw [Bcs.card_filter_prod_fst]
    simp only [Fintype.sum_prod_type]
    calc
      ∑ first : Alpha, ∑ query : LigeroFamily.QuerySet n r,
          (Finset.univ.filter fun alpha : Alpha ↦
            query.coordinates ⊆ allowed alpha).card
        = Fintype.card Alpha *
            ∑ query : LigeroFamily.QuerySet n r,
              (Finset.univ.filter fun alpha : Alpha ↦
                query.coordinates ⊆ allowed alpha).card := by
            simp [Finset.mul_sum]
      _ = Fintype.card Alpha *
          (Finset.univ.filter fun pair :
            LigeroFamily.QuerySet n r × Alpha ↦
              pair.1.coordinates ⊆ allowed pair.2).card := by
            rw [Bcs.card_filter_prod_fst]
      _ ≤ Fintype.card Alpha * pairBudget :=
        Nat.mul_le_mul_left _ (by simpa [pairBudget] using hbase)
  have htight := predictable_other_slot_tape_on_card_le
    fixedSlot (Equiv.prodComm Alpha (LigeroFamily.QuerySet n r))
    select admissible hselect success event
    (Fintype.card Alpha * pairBudget) hpairs (by
      intro tape htape
      simpa [success, subsetAnswer] using hcover tape htape)
  calc
    (Finset.univ.filter event).card ≤
        (Fintype.card Alpha * pairBudget) *
          Fintype.card (LigeroFamily.QuerySet n r) ^ (N + 1) *
          Fintype.card Alpha ^ N := htight
    _ = pairBudget *
        Fintype.card (Answer Alpha (LigeroFamily.QuerySet n r)) ^ (N + 1) := by
      simp only [Answer, Fintype.card_prod]
      rw [mul_pow, pow_succ]
      ring
    _ = _ := rfl

/-- Tight Case-A listed-response count.  The H₁ answer is fixed at the
charged slot, while the later H₂ answer is selected predictably.  The
accepting-pair theorem may depend on every retained tape coordinate, so this
supports an arbitrary fixed response strategy.  Again there is no inner slot
union. -/
theorem ligero_caseA_predictable_tape_card_le
    {Alpha : Type*} [Fintype Alpha] [DecidableEq Alpha]
    {n r N : ℕ} (fixedSlot : Fin (N + 2))
    (select : Answer Alpha (LigeroFamily.QuerySet n r) →
      (Fin (N + 1) → Alpha × LigeroFamily.QuerySet n r) → Fin (N + 1))
    (admissible : Answer Alpha (LigeroFamily.QuerySet n r) ×
      (Fin (N + 1) → Alpha × LigeroFamily.QuerySet n r) → Prop)
    [DecidablePred admissible]
    (hselect : Bcs.IsPredictableSelectorOn admissible select)
    (success : ((Fin (N + 1) → Alpha) ×
      (Fin N → LigeroFamily.QuerySet n r)) →
        LigeroFamily.QuerySet n r → Alpha → Prop)
    [∀ data, DecidableRel (success data)]
    (event : (Fin (N + 2) →
      Answer Alpha (LigeroFamily.QuerySet n r)) → Prop)
    [DecidablePred event]
    (pairBudget : ℕ)
    (hpairs : ∀ data, (Finset.univ.filter fun pair :
      LigeroFamily.QuerySet n r × Alpha ↦
        success data pair.1 pair.2).card ≤ pairBudget)
    (hcover : ∀ tape, event tape →
      let fixed := tape fixedSlot
      let rest := fun k ↦ tape (fixedSlot.succAbove k)
      let selected := select fixed rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (selected.succAbove k)).2)
      admissible (fixed, rest) ∧
        success data (rest selected).2 (alphaAnswer fixed)) :
    (Finset.univ.filter event).card ≤
      pairBudget *
        Fintype.card (Answer Alpha (LigeroFamily.QuerySet n r)) ^ (N + 1) := by
  classical
  let liftedSuccess : ((Fin (N + 1) → Alpha) ×
      (Fin N → LigeroFamily.QuerySet n r)) →
      Answer Alpha (LigeroFamily.QuerySet n r) →
        LigeroFamily.QuerySet n r → Prop :=
    fun data fixed query ↦ success data query (alphaAnswer fixed)
  have hpairsLifted : ∀ data,
      (Finset.univ.filter fun pair :
        Answer Alpha (LigeroFamily.QuerySet n r) ×
          LigeroFamily.QuerySet n r ↦
        liftedSuccess data pair.1 pair.2).card ≤
          Fintype.card (LigeroFamily.QuerySet n r) * pairBudget := by
    intro data
    rw [Bcs.card_filter_prod_fst]
    simp only [Fintype.sum_prod_type]
    calc
      ∑ alpha : Alpha, ∑ _unused : LigeroFamily.QuerySet n r,
          (Finset.univ.filter fun query : LigeroFamily.QuerySet n r ↦
            success data query alpha).card
        = Fintype.card (LigeroFamily.QuerySet n r) *
            ∑ alpha : Alpha,
              (Finset.univ.filter fun query : LigeroFamily.QuerySet n r ↦
                success data query alpha).card := by
            rw [Finset.mul_sum]
            apply Finset.sum_congr rfl
            intro alpha _
            simp
      _ = Fintype.card (LigeroFamily.QuerySet n r) *
          (Finset.univ.filter fun pair :
            LigeroFamily.QuerySet n r × Alpha ↦
              success data pair.1 pair.2).card := by
            rw [Bcs.card_filter_prod_snd]
      _ ≤ Fintype.card (LigeroFamily.QuerySet n r) * pairBudget :=
        Nat.mul_le_mul_left _ (hpairs data)
  have htight := predictable_other_slot_tape_on_card_le
    fixedSlot (Equiv.refl (Answer Alpha (LigeroFamily.QuerySet n r)))
    select admissible hselect liftedSuccess event
    (Fintype.card (LigeroFamily.QuerySet n r) * pairBudget)
    hpairsLifted (by
      intro tape htape
      simpa [liftedSuccess, alphaAnswer] using hcover tape htape)
  calc
    (Finset.univ.filter event).card ≤
        (Fintype.card (LigeroFamily.QuerySet n r) * pairBudget) *
          Fintype.card Alpha ^ (N + 1) *
          Fintype.card (LigeroFamily.QuerySet n r) ^ N := htight
    _ = pairBudget *
        Fintype.card (Answer Alpha (LigeroFamily.QuerySet n r)) ^ (N + 1) := by
      simp only [Answer, Fintype.card_prod]
      rw [mul_pow, pow_succ]
      ring

/-- Alpha-first (Case A) union over the possible later defining `H₂` slot,
with the selected-response relation allowed to depend on the rest of the
tape.  This is a theorem-backed conservative replacement for any unproved
listed-response formula. -/
theorem later_subset_slot_dependent_tape_card_le
    {Alpha Subset : Type*} [Fintype Alpha] [Fintype Subset]
    [DecidableEq Alpha] [DecidableEq Subset]
    {T : ℕ} (alphaSlot : Fin T)
    (success : ∀ subsetSlot : Fin T,
      TwoSlotData Alpha Subset T subsetSlot alphaSlot →
        Subset → Alpha → Prop)
    [∀ subsetSlot data, DecidableRel (success subsetSlot data)]
    (event : (Fin T → Answer Alpha Subset) → Prop) [DecidablePred event]
    (pairBudget : ℕ)
    (hpairs : ∀ subsetSlot (_hne : subsetSlot ≠ alphaSlot) data,
      (Finset.univ.filter fun pair : Subset × Alpha =>
        success subsetSlot data pair.1 pair.2).card ≤ pairBudget)
    (hcover : ∀ tape, event tape → ∃ subsetSlot : Fin T,
      subsetSlot ≠ alphaSlot ∧
        success subsetSlot (twoSlotData subsetSlot alphaSlot tape)
          (subsetAnswer (tape subsetSlot)) (alphaAnswer (tape alphaSlot))) :
    (Finset.univ.filter event).card ≤
      (T - 1) * pairBudget *
        Fintype.card (Answer Alpha Subset) ^ (T - 1) := by
  classical
  let slots : Finset (Fin T) := Finset.univ.erase alphaSlot
  let piece (subsetSlot : Fin T) : Finset (Fin T → Answer Alpha Subset) :=
    Finset.univ.filter fun tape =>
      success subsetSlot (twoSlotData subsetSlot alphaSlot tape)
        (subsetAnswer (tape subsetSlot)) (alphaAnswer (tape alphaSlot))
  have hsubset : Finset.univ.filter event ⊆ slots.biUnion piece := by
    intro tape htape
    obtain ⟨subsetSlot, hne, hsuccess⟩ :=
      hcover tape (Finset.mem_filter.mp htape).2
    exact Finset.mem_biUnion.mpr ⟨subsetSlot,
      Finset.mem_erase.mpr ⟨hne, Finset.mem_univ _⟩,
      Finset.mem_filter.mpr ⟨Finset.mem_univ _, hsuccess⟩⟩
  calc
    (Finset.univ.filter event).card ≤ (slots.biUnion piece).card :=
      Finset.card_le_card hsubset
    _ ≤ ∑ subsetSlot ∈ slots, (piece subsetSlot).card :=
      Finset.card_biUnion_le
    _ ≤ ∑ _subsetSlot ∈ slots,
        pairBudget * Fintype.card (Answer Alpha Subset) ^ (T - 1) := by
      apply Finset.sum_le_sum
      intro subsetSlot hsubsetSlot
      exact two_projection_dependent_tape_card_le subsetSlot alphaSlot
        (Finset.mem_erase.mp hsubsetSlot).1 (success subsetSlot) pairBudget
        (hpairs subsetSlot (Finset.mem_erase.mp hsubsetSlot).1)
    _ = (T - 1) *
        (pairBudget * Fintype.card (Answer Alpha Subset) ^ (T - 1)) := by
      simp [slots]
    _ = (T - 1) * pairBudget *
        Fintype.card (Answer Alpha Subset) ^ (T - 1) := by ring

/-- Tight rational alpha-first union: each possible later subset key is
charged through its proved pair density, giving exactly `(T - 1) * epsilon`
and no rounding slack.  A subsequent stopping-time theorem can remove this
slot union when the response list, rather than the slot layout, is used as
the fixed family. -/
theorem later_subset_slot_dependent_tape_ratio_le
    {Alpha Subset : Type*} [Fintype Alpha] [Fintype Subset]
    [DecidableEq Alpha] [DecidableEq Subset]
    [Nonempty Alpha] [Nonempty Subset]
    {T : ℕ} (alphaSlot : Fin T)
    (success : ∀ subsetSlot : Fin T,
      TwoSlotData Alpha Subset T subsetSlot alphaSlot →
        Subset → Alpha → Prop)
    [∀ subsetSlot data, DecidableRel (success subsetSlot data)]
    (event : (Fin T → Answer Alpha Subset) → Prop) [DecidablePred event]
    (epsilon : ℚ)
    (hpairs : ∀ subsetSlot (_hne : subsetSlot ≠ alphaSlot) data,
      ((Finset.univ.filter fun pair : Subset × Alpha =>
        success subsetSlot data pair.1 pair.2).card : ℚ) /
          (Fintype.card Subset * Fintype.card Alpha) ≤ epsilon)
    (hcover : ∀ tape, event tape → ∃ subsetSlot : Fin T,
      subsetSlot ≠ alphaSlot ∧
        success subsetSlot (twoSlotData subsetSlot alphaSlot tape)
          (subsetAnswer (tape subsetSlot)) (alphaAnswer (tape alphaSlot))) :
    ((Finset.univ.filter event).card : ℚ) /
      (Fintype.card (Answer Alpha Subset) : ℚ) ^ T ≤
        ((T - 1 : ℕ) : ℚ) * epsilon := by
  classical
  let slots : Finset (Fin T) := Finset.univ.erase alphaSlot
  let piece (subsetSlot : Fin T) : Finset (Fin T → Answer Alpha Subset) :=
    Finset.univ.filter fun tape =>
      success subsetSlot (twoSlotData subsetSlot alphaSlot tape)
        (subsetAnswer (tape subsetSlot)) (alphaAnswer (tape alphaSlot))
  have hsubset : Finset.univ.filter event ⊆ slots.biUnion piece := by
    intro tape htape
    obtain ⟨subsetSlot, hne, hsuccess⟩ :=
      hcover tape (Finset.mem_filter.mp htape).2
    exact Finset.mem_biUnion.mpr ⟨subsetSlot,
      Finset.mem_erase.mpr ⟨hne, Finset.mem_univ _⟩,
      Finset.mem_filter.mpr ⟨Finset.mem_univ _, hsuccess⟩⟩
  have hcard : (Finset.univ.filter event).card ≤
      ∑ subsetSlot ∈ slots, (piece subsetSlot).card :=
    (Finset.card_le_card hsubset).trans Finset.card_biUnion_le
  have hpiece (subsetSlot : Fin T) (hsubsetSlot : subsetSlot ∈ slots) :
      ((piece subsetSlot).card : ℚ) /
        (Fintype.card (Answer Alpha Subset) : ℚ) ^ T ≤ epsilon := by
    have h := two_projection_dependent_tape_ratio_le subsetSlot alphaSlot
      (Finset.mem_erase.mp hsubsetSlot).1 (success subsetSlot) epsilon
      (hpairs subsetSlot (Finset.mem_erase.mp hsubsetSlot).1)
    exact h
  have hden : (0 : ℚ) <
      (Fintype.card (Answer Alpha Subset) : ℚ) ^ T := by
    have hN : (0 : ℚ) < Fintype.card (Answer Alpha Subset) := by
      exact_mod_cast Fintype.card_pos
    exact pow_pos hN T
  calc
    ((Finset.univ.filter event).card : ℚ) /
        (Fintype.card (Answer Alpha Subset) : ℚ) ^ T
      ≤ ((∑ subsetSlot ∈ slots, (piece subsetSlot).card : ℕ) : ℚ) /
          (Fintype.card (Answer Alpha Subset) : ℚ) ^ T :=
        div_le_div_of_nonneg_right (by exact_mod_cast hcard) (le_of_lt hden)
    _ = ∑ subsetSlot ∈ slots,
        ((piece subsetSlot).card : ℚ) /
          (Fintype.card (Answer Alpha Subset) : ℚ) ^ T := by
      push_cast
      simp only [div_eq_mul_inv, Finset.sum_mul]
    _ ≤ ∑ _subsetSlot ∈ slots, epsilon :=
      Finset.sum_le_sum (fun subsetSlot hsubsetSlot => hpiece subsetSlot hsubsetSlot)
    _ = ((T - 1 : ℕ) : ℚ) * epsilon := by simp [slots]

/-! ## First-occurrence coins are tape coordinates -/

/-- The batching answer at the defining query's first-occurrence slot. -/
def definingAlphaAnswer
    {Alpha Subset Query : Type*} [BEq Query] [LawfulBEq Query]
    {T : ℕ}
    (trace : Bcs.FirstOccurrenceTrace
      (Fin T → Answer Alpha Subset) Query T)
    (tape : Fin T → Answer Alpha Subset) : Alpha :=
  alphaAnswer (tape (trace.alphaSlot tape))

/-- The subset answer at the defining query's first-occurrence slot. -/
def definingSubsetAnswer
    {Alpha Subset Query : Type*} [BEq Query] [LawfulBEq Query]
    {T : ℕ}
    (trace : Bcs.FirstOccurrenceTrace
      (Fin T → Answer Alpha Subset) Query T)
    (tape : Fin T → Answer Alpha Subset) : Subset :=
  subsetAnswer (tape (trace.subsetSlot tape))

theorem definingAlphaAnswer_eq_of_alphaSlot_eq
    {Alpha Subset Query : Type*} [BEq Query] [LawfulBEq Query]
    {T : ℕ}
    (trace : Bcs.FirstOccurrenceTrace
      (Fin T → Answer Alpha Subset) Query T)
    (tape : Fin T → Answer Alpha Subset) (i : Fin T)
    (hslot : trace.alphaSlot tape = i) :
    definingAlphaAnswer trace tape = alphaAnswer (tape i) := by
  simp [definingAlphaAnswer, hslot]

theorem definingSubsetAnswer_eq_of_subsetSlot_eq
    {Alpha Subset Query : Type*} [BEq Query] [LawfulBEq Query]
    {T : ℕ}
    (trace : Bcs.FirstOccurrenceTrace
      (Fin T → Answer Alpha Subset) Query T)
    (tape : Fin T → Answer Alpha Subset) (i : Fin T)
    (hslot : trace.subsetSlot tape = i) :
    definingSubsetAnswer trace tape = subsetAnswer (tape i) := by
  simp [definingSubsetAnswer, hslot]

/-- In Case B the charged slot really supplies the defining subset answer,
and a distinct slot really supplies the later defining alpha answer. -/
theorem caseB_defining_answers
    {Alpha Subset Query : Type*} [BEq Query] [LawfulBEq Query]
    {T : ℕ}
    (trace : Bcs.FirstOccurrenceTrace
      (Fin T → Answer Alpha Subset) Query T)
    (win bindBreak : (Fin T → Answer Alpha Subset) → Prop)
    (i : Fin T) (tape : Fin T → Answer Alpha Subset)
    (hcase : trace.caseB win bindBreak i tape) :
    definingSubsetAnswer trace tape = subsetAnswer (tape i) ∧
      ∃ alphaSlot : Fin T, alphaSlot ≠ i ∧
        definingAlphaAnswer trace tape = alphaAnswer (tape alphaSlot) := by
  have hsubset := trace.subsetSlot_eq_of_caseB win bindBreak i tape hcase
  refine ⟨definingSubsetAnswer_eq_of_subsetSlot_eq trace tape i hsubset,
    trace.alphaSlot tape, ?_, rfl⟩
  intro heq
  exact trace.alphaSlot_ne_subsetSlot tape (heq.trans hsubset.symm)

/-- In listed Case A the charged slot really supplies the defining alpha
answer, while the defining subset answer sits at a distinct slot. -/
theorem caseA_listed_defining_answers
    {Alpha Subset Query : Type*} [BEq Query] [LawfulBEq Query]
    {T : ℕ}
    (trace : Bcs.FirstOccurrenceTrace
      (Fin T → Answer Alpha Subset) Query T)
    (listed win bindBreak : (Fin T → Answer Alpha Subset) → Prop)
    (i : Fin T) (tape : Fin T → Answer Alpha Subset)
    (hcase : trace.caseA listed win bindBreak i tape)
    (hlisted : listed tape) :
    definingAlphaAnswer trace tape = alphaAnswer (tape i) ∧
      ∃ subsetSlot : Fin T, subsetSlot ≠ i ∧
        definingSubsetAnswer trace tape = subsetAnswer (tape subsetSlot) := by
  have halpha := trace.alphaSlot_eq_of_caseA_listed
    listed win bindBreak i tape hcase hlisted
  refine ⟨definingAlphaAnswer_eq_of_alphaSlot_eq trace tape i halpha,
    trace.subsetSlot tape, ?_, rfl⟩
  intro heq
  exact trace.alphaSlot_ne_subsetSlot tape (halpha.trans heq.symm)

/-- In floor Case A the charged slot really supplies the defining subset
answer. -/
theorem caseA_floor_definingSubsetAnswer
    {Alpha Subset Query : Type*} [BEq Query] [LawfulBEq Query]
    {T : ℕ}
    (trace : Bcs.FirstOccurrenceTrace
      (Fin T → Answer Alpha Subset) Query T)
    (listed win bindBreak : (Fin T → Answer Alpha Subset) → Prop)
    (i : Fin T) (tape : Fin T → Answer Alpha Subset)
    (hcase : trace.caseA listed win bindBreak i tape)
    (hunlisted : ¬listed tape) :
    definingSubsetAnswer trace tape = subsetAnswer (tape i) :=
  definingSubsetAnswer_eq_of_subsetSlot_eq trace tape i
    (trace.subsetSlot_eq_of_caseA_floor listed win bindBreak i tape hcase hunlisted)

/-- Case A's floor charge is local at the defining `H₂` slot.  Once the
prefix has fixed the response-key and its floor-sized accepting family, the
unused alpha projection cancels exactly. -/
theorem subset_local_tape_card_le
    {Alpha Subset : Type*} [Fintype Alpha] [Fintype Subset]
    [DecidableEq Alpha] [DecidableEq Subset]
    {T : ℕ} (i : Fin T) (bad : Sumcheck.Prefix (Answer Alpha Subset) i.val →
      Subset → Bool)
    (subsetBudget : ℕ)
    (hlocal : ∀ pref,
      (Finset.univ.filter fun subset => bad pref subset = true).card ≤ subsetBudget) :
    (Finset.univ.filter fun tape : Fin T → Answer Alpha Subset =>
      bad (Sumcheck.extract_prefix tape i) (subsetAnswer (tape i)) = true).card ≤
        (Fintype.card Alpha * subsetBudget) *
          Fintype.card (Answer Alpha Subset) ^ (T - 1) := by
  have h := Sumcheck.slot_bad_card_le i (Fintype.card Alpha * subsetBudget)
    (fun pref answer => bad pref (subsetAnswer answer) = true) (by
      intro pref
      have hprojection := subset_projection_card
        (Alpha := Alpha) (Subset := Subset)
        (fun subset => bad pref subset = true)
      trans Fintype.card Alpha *
          (Finset.univ.filter fun subset : Subset =>
            bad pref subset = true).card
      · exact le_of_eq (by
          convert hprojection using 1
          all_goals first | rfl | (congr 1; ext; simp))
      · exact Nat.mul_le_mul_left _ (hlocal pref))
  convert h using 1
  all_goals first | rfl | (congr 1; ext; simp)

/-- Conservative, fully unconditional Case-B tape count.  The defining
`H₂` slot is fixed, while the later defining `H₁` answer may occupy any other
slot.  Each fixed pair uses `two_projection_tape_card_le`; the explicit
`T - 1` is the cost of not yet proving a stopping-time reindexing theorem.

This theorem is intentionally stronger in hypotheses and weaker numerically
than the desired optimized compiler formula.  It is safe for the complete
grid, and makes the remaining optimization issue visible rather than
silently assuming the alpha-last formula. -/
theorem later_alpha_slot_tape_card_le
    {Alpha Subset : Type*} [Fintype Alpha] [Fintype Subset]
    [DecidableEq Alpha] [DecidableEq Subset]
    {T : ℕ} (subsetSlot : Fin T)
    (success : Subset → Alpha → Prop) [DecidableRel success]
    (event : (Fin T → Answer Alpha Subset) → Prop) [DecidablePred event]
    (pairBudget : ℕ)
    (hpairs : (Finset.univ.filter fun pair : Subset × Alpha =>
      success pair.1 pair.2).card ≤ pairBudget)
    (hcover : ∀ tape, event tape → ∃ alphaSlot : Fin T,
      alphaSlot ≠ subsetSlot ∧
        success (subsetAnswer (tape subsetSlot))
          (alphaAnswer (tape alphaSlot))) :
    (Finset.univ.filter event).card ≤
      (T - 1) * pairBudget *
        Fintype.card (Answer Alpha Subset) ^ (T - 1) := by
  classical
  let slots : Finset (Fin T) := Finset.univ.erase subsetSlot
  let piece (alphaSlot : Fin T) : Finset (Fin T → Answer Alpha Subset) :=
    Finset.univ.filter fun tape =>
      success (subsetAnswer (tape subsetSlot)) (alphaAnswer (tape alphaSlot))
  have hsubset : Finset.univ.filter event ⊆ slots.biUnion piece := by
    intro tape htape
    obtain ⟨alphaSlot, hne, hsuccess⟩ :=
      hcover tape (Finset.mem_filter.mp htape).2
    exact Finset.mem_biUnion.mpr ⟨alphaSlot,
      Finset.mem_erase.mpr ⟨hne, Finset.mem_univ _⟩,
      Finset.mem_filter.mpr ⟨Finset.mem_univ _, hsuccess⟩⟩
  calc
    (Finset.univ.filter event).card ≤ (slots.biUnion piece).card :=
      Finset.card_le_card hsubset
    _ ≤ ∑ alphaSlot ∈ slots, (piece alphaSlot).card :=
      Finset.card_biUnion_le
    _ ≤ ∑ _alphaSlot ∈ slots,
        pairBudget * Fintype.card (Answer Alpha Subset) ^ (T - 1) := by
      apply Finset.sum_le_sum
      intro alphaSlot halphaSlot
      exact two_projection_tape_card_le subsetSlot alphaSlot
        (Finset.mem_erase.mp halphaSlot).1.symm success pairBudget hpairs
    _ = (T - 1) *
        (pairBudget * Fintype.card (Answer Alpha Subset) ^ (T - 1)) := by
      simp [slots]
    _ = (T - 1) * pairBudget *
        Fintype.card (Answer Alpha Subset) ^ (T - 1) := by ring

/-! ## Ligero incidence specializations -/

/-- Complete Case-A floor count for a fixed defining `H₂` slot.  The allowed
coordinate set is a function of the prior tape prefix, so it may encode the
commitment, batching challenge, and response fixed by the actual execution.
Only its proved cardinality bound is used. -/
theorem ligero_caseA_floor_tape_card_le
    {Alpha : Type*} [Fintype Alpha] [DecidableEq Alpha]
    {n r floor T : ℕ} (subsetSlot : Fin T)
    (allowed : Sumcheck.Prefix
      (Answer Alpha (LigeroFamily.QuerySet n r)) subsetSlot.val → Finset (Fin n))
    (event : (Fin T → Answer Alpha (LigeroFamily.QuerySet n r)) → Prop)
    [DecidablePred event]
    (hallowed : ∀ pref, (allowed pref).card ≤ floor)
    (hcover : ∀ tape, event tape →
      (subsetAnswer (tape subsetSlot)).coordinates ⊆
        allowed (Sumcheck.extract_prefix tape subsetSlot)) :
    (Finset.univ.filter event).card ≤
      (Fintype.card Alpha * floor.choose r) *
        Fintype.card (Answer Alpha (LigeroFamily.QuerySet n r)) ^ (T - 1) := by
  classical
  let localEvent : (Fin T → Answer Alpha (LigeroFamily.QuerySet n r)) → Prop := fun tape =>
    (subsetAnswer (tape subsetSlot)).coordinates ⊆
      allowed (Sumcheck.extract_prefix tape subsetSlot)
  have hsubset : Finset.univ.filter event ⊆ Finset.univ.filter localEvent := by
    intro tape htape
    exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
      hcover tape (Finset.mem_filter.mp htape).2⟩
  have hlocal := subset_local_tape_card_le subsetSlot
    (fun pref query => decide (query.coordinates ⊆ allowed pref))
    (floor.choose r) (by
      intro pref
      have hwithin := LigeroFamily.card_queriesWithin_le (r := r)
        (allowed pref) (hallowed pref)
      simpa [LigeroFamily.queriesWithin] using hwithin)
  calc
    (Finset.univ.filter event).card ≤ (Finset.univ.filter localEvent).card :=
      Finset.card_le_card hsubset
    _ ≤ (Fintype.card Alpha * floor.choose r) *
        Fintype.card (Answer Alpha (LigeroFamily.QuerySet n r)) ^ (T - 1) := by
      convert hlocal using 1
      all_goals first | rfl | (congr 1; ext; simp [localEvent])

/-- Exact probability form of `ligero_caseA_floor_tape_card_le`.  The unused
alpha projection and all uncharged tape coordinates cancel, leaving precisely
the without-replacement probability that the charged size-`r` query lies in a
set of size at most `floor`. -/
theorem ligero_caseA_floor_tape_ratio_le
    {Alpha : Type*} [Fintype Alpha] [DecidableEq Alpha] [Nonempty Alpha]
    {n r floor T : ℕ} (subsetSlot : Fin T)
    (allowed : Sumcheck.Prefix
      (Answer Alpha (LigeroFamily.QuerySet n r)) subsetSlot.val → Finset (Fin n))
    (event : (Fin T → Answer Alpha (LigeroFamily.QuerySet n r)) → Prop)
    [DecidablePred event]
    (hallowed : ∀ pref, (allowed pref).card ≤ floor)
    (hcover : ∀ tape, event tape →
      (subsetAnswer (tape subsetSlot)).coordinates ⊆
        allowed (Sumcheck.extract_prefix tape subsetSlot))
    (hquery : r ≤ n) :
    ((Finset.univ.filter event).card : ℚ) /
        Fintype.card
          (Fin T → Answer Alpha (LigeroFamily.QuerySet n r)) ≤
      LigeroFamily.hypergeometricRatio floor n r := by
  classical
  letI : Nonempty (LigeroFamily.QuerySet n r) :=
    LigeroFamily.QuerySet.nonempty hquery
  letI : Nonempty (Answer Alpha (LigeroFamily.QuerySet n r)) := inferInstance
  letI : Nonempty
      (Fin T → Answer Alpha (LigeroFamily.QuerySet n r)) :=
    ⟨fun _ ↦ Classical.choice
      (inferInstance : Nonempty
        (Answer Alpha (LigeroFamily.QuerySet n r)))⟩
  have hcount := ligero_caseA_floor_tape_card_le subsetSlot allowed event
    hallowed hcover
  have hT : T - 1 + 1 = T := by
    have := subsetSlot.isLt
    omega
  have hchoose : 0 < n.choose r := Nat.choose_pos hquery
  have hanswer :
      Fintype.card (Answer Alpha (LigeroFamily.QuerySet n r)) =
        Fintype.card Alpha * n.choose r := by
    simp only [Answer, Fintype.card_prod,
      LigeroFamily.QuerySet.fintype_card]
  have htape :
      Fintype.card
          (Fin T → Answer Alpha (LigeroFamily.QuerySet n r)) =
        Fintype.card (Answer Alpha (LigeroFamily.QuerySet n r)) ^ T := by
    simp
  have hden : (0 : ℚ) <
      Fintype.card
        (Fin T → Answer Alpha (LigeroFamily.QuerySet n r)) := by
    exact_mod_cast Fintype.card_pos
  rw [div_le_iff₀ hden]
  calc
    ((Finset.univ.filter event).card : ℚ) ≤
        ((Fintype.card Alpha * floor.choose r) *
          Fintype.card (Answer Alpha (LigeroFamily.QuerySet n r)) ^
            (T - 1) : ℕ) := by
      exact_mod_cast hcount
    _ = LigeroFamily.hypergeometricRatio floor n r *
        Fintype.card
          (Fin T → Answer Alpha (LigeroFamily.QuerySet n r)) := by
      rw [htape, hanswer, ← hT, pow_succ]
      unfold LigeroFamily.hypergeometricRatio
      push_cast
      have hchooseQ : (n.choose r : ℚ) ≠ 0 := by
        exact_mod_cast Nat.ne_of_gt hchoose
      field_simp [hchooseQ]

/-- Complete conservative Case-B incidence count for a fixed defining `H₂`
slot.  A later `H₁` answer supplies `alpha`; the successful independent
`(querySet, alpha)` pairs are counted by `Bcs.alpha_last_pair_card_le`, and
`later_alpha_slot_tape_card_le` lifts that theorem to actual paired tapes.
-/
theorem ligero_caseB_tape_card_le
    {Alpha : Type*} [Fintype Alpha] [DecidableEq Alpha]
    {n r goodCap absoluteCap badCount T : ℕ}
    (subsetSlot : Fin T)
    (bad : Finset Alpha) (allowed : Alpha → Finset (Fin n))
    (event : (Fin T → Answer Alpha (LigeroFamily.QuerySet n r)) → Prop)
    [DecidablePred event]
    (hbad : bad.card ≤ badCount)
    (hgood : ∀ alpha ∉ bad, (allowed alpha).card ≤ goodCap)
    (habsolute : ∀ alpha, (allowed alpha).card ≤ absoluteCap)
    (hcover : ∀ tape, event tape → ∃ alphaSlot : Fin T,
      alphaSlot ≠ subsetSlot ∧
        (subsetAnswer (tape subsetSlot)).coordinates ⊆
          allowed (alphaAnswer (tape alphaSlot))) :
    (Finset.univ.filter event).card ≤
      (T - 1) *
        (Fintype.card Alpha * goodCap.choose r +
          badCount * absoluteCap.choose r) *
        Fintype.card (Answer Alpha (LigeroFamily.QuerySet n r)) ^ (T - 1) := by
  classical
  let success : LigeroFamily.QuerySet n r → Alpha → Prop := fun query alpha =>
    query.coordinates ⊆ allowed alpha
  have hpairs := Bcs.alpha_last_pair_card_le (r := r)
    bad allowed hbad hgood habsolute
  exact later_alpha_slot_tape_card_le subsetSlot success event
    (Fintype.card Alpha * goodCap.choose r + badCount * absoluteCap.choose r)
    (by simpa [success] using hpairs) hcover

variable {AlphaKey SubsetKey : Type*}
variable {α : Type*}

/-- Append a query exactly when it has not appeared before. -/
def appendIfMissing [DecidableEq α] (trace : List α) (query : α) : List α :=
  if query ∈ trace then trace else trace ++ [query]

theorem mem_appendIfMissing [DecidableEq α] (trace : List α) (query : α) :
    query ∈ appendIfMissing trace query := by
  by_cases h : query ∈ trace <;> simp [appendIfMissing, h]

theorem mem_appendIfMissing_of_mem [DecidableEq α]
    {trace : List α} {query item : α} (hitem : item ∈ trace) :
    item ∈ appendIfMissing trace query := by
  by_cases hquery : query ∈ trace <;>
    simp [appendIfMissing, hquery, hitem]

theorem length_appendIfMissing_le [DecidableEq α]
    (trace : List α) (query : α) :
    (appendIfMissing trace query).length ≤ trace.length + 1 := by
  by_cases h : query ∈ trace <;> simp [appendIfMissing, h]

/-- Appending a possibly missing query preserves the first-occurrence index
of every item already present in the trace. -/
theorem idxOf_appendIfMissing_of_mem [DecidableEq α]
    (trace : List α) (query item : α) (hitem : item ∈ trace) :
    (appendIfMissing trace query).idxOf item = trace.idxOf item := by
  unfold appendIfMissing
  split
  · rfl
  · exact List.idxOf_append_of_mem hitem

/-- Appending a missing fixed query cannot change an already fixed prefix.
If the list ends inside that prefix, equality of prefixes forces the two
lists themselves to be equal. -/
theorem take_appendIfMissing_congr [DecidableEq α]
    (left right : List α) (query : α) (k : ℕ)
    (h : left.take k = right.take k) :
    (appendIfMissing left query).take k =
      (appendIfMissing right query).take k := by
  by_cases hleft : k ≤ left.length
  · have hright : k ≤ right.length := by
      have hlen := congrArg List.length h
      simpa [List.length_take, Nat.min_eq_left hleft] using hlen.symm
    unfold appendIfMissing
    split <;> split
    all_goals simpa [List.take_append_of_le_length hleft,
      List.take_append_of_le_length hright] using h
  · have hleftLen : left.length < k := Nat.lt_of_not_ge hleft
    have hlen := congrArg List.length h
    have hrightLen : right.length < k := by
      by_contra hnot
      have hk : k ≤ right.length := Nat.le_of_not_gt hnot
      simp [List.length_take, Nat.min_eq_right (Nat.le_of_lt hleftLen),
        Nat.min_eq_left hk] at hlen
      omega
    have heq : left = right := by
      simpa [(List.take_eq_self_iff left).2 (Nat.le_of_lt hleftLen),
        (List.take_eq_self_iff right).2 (Nat.le_of_lt hrightLen)] using h
    subst right
    rfl

/-- Equality through the first occurrence of a query fixes its exact index.
This small list lemma turns lazy-run prefix measurability into a stopping-time
statement. -/
theorem idxOf_eq_of_take_congr
    {Q : Type*} [BEq Q] [LawfulBEq Q]
    (left right : List Q) (query : Q) (j : ℕ)
    (hmem : query ∈ left) (hidx : left.idxOf query = j)
    (htake : left.take (j + 1) = right.take (j + 1)) :
    right.idxOf query = j := by
  have hmemTake : query ∈ left.take (j + 1) :=
    (List.mem_take_iff_idxOf_lt hmem).2 (by omega)
  have hmemTake' : query ∈ right.take (j + 1) := htake ▸ hmemTake
  have hmem' : query ∈ right := List.mem_of_mem_take hmemTake'
  have hupper : right.idxOf query < j + 1 :=
    (List.mem_take_iff_idxOf_lt hmem').1 hmemTake'
  have htakej : left.take j = right.take j := by
    have hprefix := congrArg (List.take j) htake
    simpa [List.take_take] using hprefix
  have hnot : query ∉ left.take j := by
    intro hquery
    have hlt := (List.mem_take_iff_idxOf_lt hmem).1 hquery
    omega
  have hnot' : query ∉ right.take j := by simpa [htakej.symm] using hnot
  have hlower : ¬ right.idxOf query < j := by
    intro hlt
    exact hnot' ((List.mem_take_iff_idxOf_lt hmem').2 hlt)
  omega

/-- The adversary's distinct-query trace with the two verifier queries
installed.  Existing queries keep their first-occurrence positions. -/
def augmentedTrace [DecidableEq AlphaKey] [DecidableEq SubsetKey]
    (trace : List (Query AlphaKey SubsetKey))
    (alphaKey : AlphaKey) (subsetKey : SubsetKey) :
    List (Query AlphaKey SubsetKey) :=
  appendIfMissing
    (appendIfMissing trace (.alpha alphaKey)) (.subset subsetKey)

/-- Installing the same two verifier queries preserves equality of every
already fixed trace prefix. -/
theorem augmentedTrace_take_congr
    [DecidableEq AlphaKey] [DecidableEq SubsetKey]
    (left right : List (Query AlphaKey SubsetKey))
    (alphaKey : AlphaKey) (subsetKey : SubsetKey) (k : ℕ)
    (h : left.take k = right.take k) :
    (augmentedTrace left alphaKey subsetKey).take k =
      (augmentedTrace right alphaKey subsetKey).take k := by
  exact take_appendIfMissing_congr _ _ (.subset subsetKey) k
    (take_appendIfMissing_congr _ _ (.alpha alphaKey) k h)

theorem alpha_mem_augmentedTrace [DecidableEq AlphaKey] [DecidableEq SubsetKey]
    (trace : List (Query AlphaKey SubsetKey))
    (alphaKey : AlphaKey) (subsetKey : SubsetKey) :
    Query.alpha alphaKey ∈ augmentedTrace trace alphaKey subsetKey := by
  unfold augmentedTrace
  have hmem := mem_appendIfMissing trace (Query.alpha alphaKey)
  exact mem_appendIfMissing_of_mem hmem

theorem subset_mem_augmentedTrace [DecidableEq AlphaKey] [DecidableEq SubsetKey]
    (trace : List (Query AlphaKey SubsetKey))
    (alphaKey : AlphaKey) (subsetKey : SubsetKey) :
    Query.subset subsetKey ∈ augmentedTrace trace alphaKey subsetKey := by
  exact mem_appendIfMissing _ _

theorem augmentedTrace_length_le [DecidableEq AlphaKey] [DecidableEq SubsetKey]
    (trace : List (Query AlphaKey SubsetKey))
    (alphaKey : AlphaKey) (subsetKey : SubsetKey) :
    (augmentedTrace trace alphaKey subsetKey).length ≤ trace.length + 2 := by
  unfold augmentedTrace
  exact (length_appendIfMissing_le _ _).trans (by
    have h := length_appendIfMissing_le trace (Query.alpha alphaKey)
    omega)

/-- Build the exact first-occurrence object consumed by the rigid compiler
from an arbitrary bounded adversary trace.  Domain separation is supplied by
the two constructors, and the verifier's two appended queries account for the
`+ 2` in the slot bound. -/
def firstOccurrenceTrace
    {Ω AlphaKey SubsetKey : Type*} [Fintype Ω]
    [DecidableEq AlphaKey] [DecidableEq SubsetKey]
    (queryBudget : ℕ)
    (trace : Ω → List (Query AlphaKey SubsetKey))
    (alphaKey : Ω → AlphaKey) (subsetKey : Ω → SubsetKey)
    (trace_length : ∀ ω, (trace ω).length ≤ queryBudget) :
    Bcs.FirstOccurrenceTrace Ω (Query AlphaKey SubsetKey) (queryBudget + 2) where
  trace ω := augmentedTrace (trace ω) (alphaKey ω) (subsetKey ω)
  alphaQuery ω := .alpha (alphaKey ω)
  subsetQuery ω := .subset (subsetKey ω)
  alpha_mem ω := alpha_mem_augmentedTrace _ _ _
  subset_mem ω := subset_mem_augmentedTrace _ _ _
  separated _ := by simp
  trace_length ω :=
    (augmentedTrace_length_le _ _ _).trans (by
      have h := trace_length ω
      omega)

/-- The operational first-occurrence trace of an actual adaptive lazy-oracle
execution.  The adversary has `queryBudget` units of fuel; its final output
determines the verifier's defining `H₁` and `H₂` inputs.  The two verifier
queries are then installed by `firstOccurrenceTrace`, giving the exact
`queryBudget + 2` slot space used by the rigid analysis.

This construction has no transcript hypothesis: the bounded trace is the
`seen` list returned by `Merkle.RandomOracle.lazyRun`, and its length bound is
the generic lazy-execution theorem. -/
def lazyFirstOccurrenceTrace
    {AlphaKey SubsetKey Alpha Subset Output : Type*}
    [DecidableEq AlphaKey] [DecidableEq SubsetKey]
    [Fintype Alpha] [Fintype Subset]
    (queryBudget : ℕ)
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey SubsetKey) (Answer Alpha Subset) Output queryBudget)
    (dflt : Answer Alpha Subset)
    (alphaKey : Output → AlphaKey) (subsetKey : Output → SubsetKey) :
    Bcs.FirstOccurrenceTrace
      (Fin (queryBudget + 2) → Answer Alpha Subset)
      (Query AlphaKey SubsetKey) (queryBudget + 2) :=
  firstOccurrenceTrace queryBudget
    (fun tape => (Merkle.RandomOracle.lazyRun tape dflt adversary []).2.1)
    (fun tape => alphaKey (Merkle.RandomOracle.lazyRun tape dflt adversary []).1)
    (fun tape => subsetKey (Merkle.RandomOracle.lazyRun tape dflt adversary []).1)
    (fun tape => by
      simpa using
        (Merkle.RandomOracle.lazyRun_seen_length_le tape dflt adversary []))

/-! ## Actual lazy-run stopping selectors -/

/-- Which defining random-oracle query is selected after the charged slot. -/
inductive DefiningQueryKind
  | alpha
  | subset
deriving DecidableEq

def definingQuery
    (kind : DefiningQueryKind) (alphaKey : AlphaKey) (subsetKey : SubsetKey) :
    Query AlphaKey SubsetKey :=
  match kind with
  | .alpha => .alpha alphaKey
  | .subset => .subset subsetKey

/-- Reinsert a charged tape answer into the remaining typed coordinates. -/
def reinsertFixedTape
    {D Z A : Type*} {N : ℕ} (fixedSlot : Fin (N + 2))
    (split : D ≃ Z × A) (fixed : D)
    (rest : Fin (N + 1) → Z × A) : Fin (N + 2) → D :=
  fixedSlot.insertNth fixed (fun k ↦ split.symm (rest k))

/-- Deleting one coordinate and reinserting it reconstructs the original
tape exactly. -/
theorem reinsertFixedTape_self
    {D Z A : Type*} {N : ℕ} (fixedSlot : Fin (N + 2))
    (split : D ≃ Z × A) (tape : Fin (N + 2) → D) :
    reinsertFixedTape fixedSlot split (tape fixedSlot)
      (fun k ↦ split (tape (fixedSlot.succAbove k))) = tape := by
  funext i
  by_cases hi : i = fixedSlot
  · subst i
    simp [reinsertFixedTape]
  · obtain ⟨k, hk⟩ := Fin.exists_succAbove_eq hi
    rw [← hk]
    simp [reinsertFixedTape]

/-- The adversary trace with the two fixed verifier queries installed. -/
def lazyAugmentedTrace
    {D Z A Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq SubsetKey]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey SubsetKey) D Output N)
    (dflt : D) (fixedSlot : Fin (N + 2)) (split : D ≃ Z × A)
    (alphaKey : D → AlphaKey) (subsetKey : D → SubsetKey)
    (fixed : D) (rest : Fin (N + 1) → Z × A) :
    List (Query AlphaKey SubsetKey) :=
  let tape := reinsertFixedTape fixedSlot split fixed rest
  augmentedTrace (Merkle.RandomOracle.lazyRun tape dflt adversary []).2.1
    (alphaKey fixed) (subsetKey fixed)

/-- Exact slot of either fixed defining query in the augmented lazy trace. -/
def lazyAugmentedTargetSlot
    {D Z A Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq SubsetKey]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey SubsetKey) D Output N)
    (dflt : D) (fixedSlot : Fin (N + 2)) (split : D ≃ Z × A)
    (alphaKey : D → AlphaKey) (subsetKey : D → SubsetKey)
    (kind : DefiningQueryKind)
    (fixed : D) (rest : Fin (N + 1) → Z × A) : Fin (N + 2) :=
  let trace := lazyAugmentedTrace adversary dflt fixedSlot split
    alphaKey subsetKey fixed rest
  let target := definingQuery kind (alphaKey fixed) (subsetKey fixed)
  ⟨trace.idxOf target, by
    have hmem : target ∈ trace := by
      cases kind with
      | alpha => exact alpha_mem_augmentedTrace _ _ _
      | subset => exact subset_mem_augmentedTrace _ _ _
    have hseen := Merkle.RandomOracle.lazyRun_seen_length_le
      (reinsertFixedTape fixedSlot split fixed rest) dflt adversary []
    have hlength := augmentedTrace_length_le
      (Merkle.RandomOracle.lazyRun
        (reinsertFixedTape fixedSlot split fixed rest) dflt adversary []).2.1
      (alphaKey fixed) (subsetKey fixed)
    exact (List.idxOf_lt_length_of_mem hmem).trans_le
      (hlength.trans (by simpa using Nat.add_le_add_right hseen 2))⟩

/-- Delete a known-distinct coordinate from a finite slot index. -/
noncomputable def eraseFixedSlotIndex {N : ℕ}
    (fixed target : Fin (N + 2)) : Fin (N + 1) :=
  if h : target = fixed then 0
  else Classical.choose (Fin.exists_succAbove_eq h)

theorem succAbove_eraseFixedSlotIndex {N : ℕ}
    (fixed target : Fin (N + 2)) (hne : target ≠ fixed) :
    fixed.succAbove (eraseFixedSlotIndex fixed target) = target := by
  simp only [eraseFixedSlotIndex, dif_neg hne]
  exact Classical.choose_spec (Fin.exists_succAbove_eq hne)

/-- Remaining-slot selector for an actual lazy execution. -/
noncomputable def lazyAugmentedSelector
    {D Z A Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq SubsetKey]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey SubsetKey) D Output N)
    (dflt : D) (fixedSlot : Fin (N + 2)) (split : D ≃ Z × A)
    (alphaKey : D → AlphaKey) (subsetKey : D → SubsetKey)
    (kind : DefiningQueryKind) :
    D → (Fin (N + 1) → Z × A) → Fin (N + 1) :=
  fun fixed rest ↦ eraseFixedSlotIndex fixedSlot
    (lazyAugmentedTargetSlot adversary dflt fixedSlot split
      alphaKey subsetKey kind fixed rest)

/-- The order branch on which the defining target is genuinely after the
charged fixed slot. -/
def lazyAugmentedLater
    {D Z A Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq SubsetKey]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey SubsetKey) D Output N)
    (dflt : D) (fixedSlot : Fin (N + 2)) (split : D ≃ Z × A)
    (alphaKey : D → AlphaKey) (subsetKey : D → SubsetKey)
    (kind : DefiningQueryKind) :
    D × (Fin (N + 1) → Z × A) → Prop :=
  fun input ↦ fixedSlot < lazyAugmentedTargetSlot adversary dflt fixedSlot
    split alphaKey subsetKey kind input.1 input.2

/-- First occurrence in the actual augmented lazy trace is a predictable
stopping coordinate on the branch where it follows the charged slot.  The
proof uses `lazyRun_seen_take_congr`; no predictability hypothesis is exposed
to protocol callers. -/
theorem lazyAugmentedSelector_predictableOn
    {D Z A Output : Type*} {N : ℕ}
    [DecidableEq D] [DecidableEq Z] [DecidableEq A]
    [DecidableEq AlphaKey] [DecidableEq SubsetKey]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey SubsetKey) D Output N)
    (dflt : D) (fixedSlot : Fin (N + 2)) (split : D ≃ Z × A)
    (alphaKey : D → AlphaKey) (subsetKey : D → SubsetKey)
    (kind : DefiningQueryKind) :
    Bcs.IsPredictableSelectorOn
      (lazyAugmentedLater adversary dflt fixedSlot split
        alphaKey subsetKey kind)
      (lazyAugmentedSelector adversary dflt fixedSlot split
        alphaKey subsetKey kind) := by
  classical
  intro fixed left right hleft _hright hagree
  let leftTape := reinsertFixedTape fixedSlot split fixed left
  let rightTape := reinsertFixedTape fixedSlot split fixed right
  let leftTarget := lazyAugmentedTargetSlot adversary dflt fixedSlot split
    alphaKey subsetKey kind fixed left
  let rightTarget := lazyAugmentedTargetSlot adversary dflt fixedSlot split
    alphaKey subsetKey kind fixed right
  let leftSelected := lazyAugmentedSelector adversary dflt fixedSlot split
    alphaKey subsetKey kind fixed left
  have hfixedBefore : fixedSlot < leftTarget := hleft
  have htargetNe : leftTarget ≠ fixedSlot := ne_of_gt hfixedBefore
  have hselectedSlot : fixedSlot.succAbove leftSelected = leftTarget := by
    exact succAbove_eraseFixedSlotIndex fixedSlot leftTarget htargetNe
  have htapes : ∀ i : Fin (N + 2), i.val < leftTarget.val →
      leftTape i = rightTape i := by
    intro i hi
    by_cases hifixed : i = fixedSlot
    · subst i
      simp [leftTape, rightTape, reinsertFixedTape]
    · obtain ⟨k, hk⟩ := Fin.exists_succAbove_eq hifixed
      have hklt : k < leftSelected := by
        apply (Fin.strictMono_succAbove fixedSlot).lt_iff_lt.mp
        rw [hk, hselectedSlot]
        exact hi
      have hrest := hagree k hklt
      rw [← hk]
      simp only [leftTape, rightTape, reinsertFixedTape,
        Fin.insertNth_apply_succAbove]
      exact congrArg split.symm hrest
  have hseen := Merkle.RandomOracle.lazyRun_seen_take_congr
    leftTape rightTape dflt leftTarget.val htapes adversary []
  have haugmented := augmentedTrace_take_congr
    (Merkle.RandomOracle.lazyRun leftTape dflt adversary []).2.1
    (Merkle.RandomOracle.lazyRun rightTape dflt adversary []).2.1
    (alphaKey fixed) (subsetKey fixed) (leftTarget.val + 1) hseen
  have hindex :
      (lazyAugmentedTrace adversary dflt fixedSlot split alphaKey subsetKey
        fixed right).idxOf
          (definingQuery kind (alphaKey fixed) (subsetKey fixed)) =
        leftTarget.val := by
    apply idxOf_eq_of_take_congr
      (lazyAugmentedTrace adversary dflt fixedSlot split alphaKey subsetKey
        fixed left)
      (lazyAugmentedTrace adversary dflt fixedSlot split alphaKey subsetKey
        fixed right)
      (definingQuery kind (alphaKey fixed) (subsetKey fixed)) leftTarget.val
    · cases kind with
      | alpha => exact alpha_mem_augmentedTrace _ _ _
      | subset => exact subset_mem_augmentedTrace _ _ _
    · rfl
    · simpa [lazyAugmentedTrace, leftTape, rightTape] using haugmented
  have htarget : rightTarget = leftTarget := by
    apply Fin.ext
    exact hindex
  simp only [lazyAugmentedSelector, rightTarget] at htarget ⊢
  rw [htarget]

/-! ## Prefix-derived defining-query selector

The verifier's other defining query is determined by the charged query and its
answer, both available at the charged slot.  It must not be reconstructed from
the adversary's final output, which may depend on later oracle answers. -/

def lazyPrefixTargetTrace
    {Q D Z A Output : Type*} {N : ℕ} [DecidableEq Q]
    (adversary : Merkle.RandomOracle.Tree Q D Output N)
    (dflt : D) (fixedSlot : Fin (N + 2))
    (split : D ≃ Z × A)
    (targetFrom : List Q → D → Q)
    (fixed : D) (rest : Fin (N + 1) → Z × A) : List Q :=
  let tape := reinsertFixedTape fixedSlot split fixed rest
  let seen := (Merkle.RandomOracle.lazyRun tape dflt adversary []).2.1
  appendIfMissing seen (targetFrom (seen.take (fixedSlot.val + 1)) fixed)

def lazyPrefixTargetSlot
    {Q D Z A Output : Type*} {N : ℕ} [DecidableEq Q]
    (adversary : Merkle.RandomOracle.Tree Q D Output N)
    (dflt : D) (fixedSlot : Fin (N + 2))
    (split : D ≃ Z × A)
    (targetFrom : List Q → D → Q)
    (fixed : D) (rest : Fin (N + 1) → Z × A) : Fin (N + 2) :=
  let trace := lazyPrefixTargetTrace adversary dflt fixedSlot split targetFrom fixed rest
  let target := targetFrom
    ((Merkle.RandomOracle.lazyRun (reinsertFixedTape fixedSlot split fixed rest)
      dflt adversary []).2.1.take (fixedSlot.val + 1)) fixed
  ⟨trace.idxOf target, by
    have hmem : target ∈ trace := mem_appendIfMissing _ _
    have hseen := Merkle.RandomOracle.lazyRun_seen_length_le
      (reinsertFixedTape fixedSlot split fixed rest) dflt adversary []
    have hlength := length_appendIfMissing_le
      (Merkle.RandomOracle.lazyRun (reinsertFixedTape fixedSlot split fixed rest)
        dflt adversary []).2.1 target
    simp only [List.length_nil, zero_add] at hseen
    have hbound := hlength.trans (Nat.add_le_add_right hseen 1)
    exact (List.idxOf_lt_length_of_mem hmem).trans_le
      (hbound.trans (by omega))⟩

noncomputable def lazyPrefixSelector
    {Q D Z A Output : Type*} {N : ℕ} [DecidableEq Q]
    (adversary : Merkle.RandomOracle.Tree Q D Output N)
    (dflt : D) (fixedSlot : Fin (N + 2))
    (split : D ≃ Z × A)
    (targetFrom : List Q → D → Q) :
    D → (Fin (N + 1) → Z × A) → Fin (N + 1) :=
  fun fixed rest ↦ eraseFixedSlotIndex fixedSlot
    (lazyPrefixTargetSlot adversary dflt fixedSlot split targetFrom fixed rest)

def lazyPrefixLater
    {Q D Z A Output : Type*} {N : ℕ} [DecidableEq Q]
    (adversary : Merkle.RandomOracle.Tree Q D Output N)
    (dflt : D) (fixedSlot : Fin (N + 2))
    (split : D ≃ Z × A)
    (targetFrom : List Q → D → Q) :
    D × (Fin (N + 1) → Z × A) → Prop :=
  fun input ↦ fixedSlot <
    lazyPrefixTargetSlot adversary dflt fixedSlot split targetFrom input.1 input.2

/-- The other defining query, when computed from the charged-query prefix and
the charged answer, is an actual predictable stopping coordinate. -/
theorem lazyPrefixSelector_predictableOn
    {Q D Z A Output : Type*} {N : ℕ}
    [DecidableEq Q] [DecidableEq D] [DecidableEq Z] [DecidableEq A]
    (adversary : Merkle.RandomOracle.Tree Q D Output N)
    (dflt : D) (fixedSlot : Fin (N + 2))
    (split : D ≃ Z × A)
    (targetFrom : List Q → D → Q) :
    Bcs.IsPredictableSelectorOn
      (lazyPrefixLater adversary dflt fixedSlot split targetFrom)
      (lazyPrefixSelector adversary dflt fixedSlot split targetFrom) := by
  classical
  intro fixed left right hleft _hright hagree
  let leftTape := reinsertFixedTape fixedSlot split fixed left
  let rightTape := reinsertFixedTape fixedSlot split fixed right
  let leftTarget := lazyPrefixTargetSlot adversary dflt fixedSlot split targetFrom fixed left
  let rightTarget := lazyPrefixTargetSlot adversary dflt fixedSlot split targetFrom fixed right
  let leftSelected := lazyPrefixSelector adversary dflt fixedSlot split targetFrom fixed left
  have hfixedBefore : fixedSlot < leftTarget := hleft
  have htargetNe : leftTarget ≠ fixedSlot := ne_of_gt hfixedBefore
  have hselectedSlot : fixedSlot.succAbove leftSelected = leftTarget :=
    succAbove_eraseFixedSlotIndex fixedSlot leftTarget htargetNe
  have htapes : ∀ i : Fin (N + 2), i.val < leftTarget.val →
      leftTape i = rightTape i := by
    intro i hi
    by_cases hifixed : i = fixedSlot
    · subst i
      simp [leftTape, rightTape, reinsertFixedTape]
    · obtain ⟨k, hk⟩ := Fin.exists_succAbove_eq hifixed
      have hklt : k < leftSelected := by
        apply (Fin.strictMono_succAbove fixedSlot).lt_iff_lt.mp
        rw [hk, hselectedSlot]
        exact hi
      have hrest := hagree k hklt
      rw [← hk]
      simpa [leftTape, rightTape, reinsertFixedTape] using congrArg split.symm hrest
  have hseen := Merkle.RandomOracle.lazyRun_seen_take_congr
    leftTape rightTape dflt leftTarget.val htapes adversary []
  have hprefix :
      (Merkle.RandomOracle.lazyRun leftTape dflt adversary []).2.1.take
          (fixedSlot.val + 1) =
        (Merkle.RandomOracle.lazyRun rightTape dflt adversary []).2.1.take
          (fixedSlot.val + 1) := by
    have htake := congrArg (List.take (fixedSlot.val + 1)) hseen
    simpa [List.take_take, Nat.min_eq_left (by omega :
      fixedSlot.val + 1 ≤ leftTarget.val + 1)] using htake
  have haugmented := take_appendIfMissing_congr
    (Merkle.RandomOracle.lazyRun leftTape dflt adversary []).2.1
    (Merkle.RandomOracle.lazyRun rightTape dflt adversary []).2.1
    (targetFrom
      ((Merkle.RandomOracle.lazyRun leftTape dflt adversary []).2.1.take
        (fixedSlot.val + 1)) fixed)
    (leftTarget.val + 1) hseen
  have htargetQuery :
      targetFrom
          ((Merkle.RandomOracle.lazyRun leftTape dflt adversary []).2.1.take
            (fixedSlot.val + 1)) fixed =
        targetFrom
          ((Merkle.RandomOracle.lazyRun rightTape dflt adversary []).2.1.take
            (fixedSlot.val + 1)) fixed :=
    congrArg (fun p ↦ targetFrom p fixed) hprefix
  have haugmented' :
      (appendIfMissing
        (Merkle.RandomOracle.lazyRun leftTape dflt adversary []).2.1
        (targetFrom
          ((Merkle.RandomOracle.lazyRun leftTape dflt adversary []).2.1.take
            (fixedSlot.val + 1)) fixed)).take (leftTarget.val + 1) =
      (appendIfMissing
        (Merkle.RandomOracle.lazyRun rightTape dflt adversary []).2.1
        (targetFrom
          ((Merkle.RandomOracle.lazyRun rightTape dflt adversary []).2.1.take
            (fixedSlot.val + 1)) fixed)).take (leftTarget.val + 1) := by
    rw [← htargetQuery]
    exact haugmented
  have hindex :
      (lazyPrefixTargetTrace adversary dflt fixedSlot split targetFrom fixed right).idxOf
          (targetFrom
            ((Merkle.RandomOracle.lazyRun rightTape dflt adversary []).2.1.take
              (fixedSlot.val + 1)) fixed) = leftTarget.val := by
    rw [← hprefix]
    apply idxOf_eq_of_take_congr
      (lazyPrefixTargetTrace adversary dflt fixedSlot split targetFrom fixed left)
      (lazyPrefixTargetTrace adversary dflt fixedSlot split targetFrom fixed right)
      (targetFrom
        ((Merkle.RandomOracle.lazyRun leftTape dflt adversary []).2.1.take
          (fixedSlot.val + 1)) fixed) leftTarget.val
    · exact mem_appendIfMissing _ _
    · rfl
    · simpa [lazyPrefixTargetTrace, leftTape, rightTape] using haugmented'
  have htarget : rightTarget = leftTarget := by
    apply Fin.ext
    exact hindex
  simp only [lazyPrefixSelector, rightTarget] at htarget ⊢
  rw [htarget]

/-- Raw-answer form of the predictable stopping count.  It is useful when the
charged prefix decides between the H₁ and H₂ cases: both branches are relations
on two complete oracle answers, and a common pair budget is paid once. -/
theorem predictable_raw_other_slot_tape_on_card_le
    {D : Type*} [Fintype D] [DecidableEq D] {N : ℕ}
    (fixedSlot : Fin (N + 2))
    (select : D → (Fin (N + 1) → PUnit × D) → Fin (N + 1))
    (admissible : D × (Fin (N + 1) → PUnit × D) → Prop)
    [DecidablePred admissible]
    (hselect : Bcs.IsPredictableSelectorOn admissible select)
    (success : ((Fin (N + 1) → PUnit) × (Fin N → D)) → D → D → Prop)
    [∀ data, DecidableRel (success data)]
    (event : (Fin (N + 2) → D) → Prop) [DecidablePred event]
    (budget : ℕ)
    (hpairs : ∀ data, (Finset.univ.filter fun pair : D × D ↦
      success data pair.1 pair.2).card ≤ Fintype.card D * budget)
    (hcover : ∀ tape, event tape →
      let fixed := tape fixedSlot
      let rest := fun k ↦
        (Equiv.punitProd D).symm (tape (fixedSlot.succAbove k))
      let selected := select fixed rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (selected.succAbove k)).2)
      admissible (fixed, rest) ∧ success data fixed (rest selected).2) :
    (Finset.univ.filter event).card ≤
      budget * Fintype.card D ^ (N + 1) := by
  classical
  have hraw := predictable_other_slot_tape_on_card_le fixedSlot
    (Equiv.punitProd D).symm select admissible hselect success event
    (Fintype.card D * budget) hpairs hcover
  calc
    (Finset.univ.filter event).card ≤
        (Fintype.card D * budget) * Fintype.card PUnit ^ (N + 1) *
          Fintype.card D ^ N := hraw
    _ = budget * Fintype.card D ^ (N + 1) := by
      simp only [Fintype.card_punit, one_pow, mul_one, pow_succ]
      ring

/-- Raw paired-answer specialization retaining an exact rational pair density. -/
theorem predictable_raw_other_slot_tape_on_ratio_le
    {D : Type*} [Fintype D] [DecidableEq D] [Nonempty D] {N : ℕ}
    (fixedSlot : Fin (N + 2))
    (select : D → (Fin (N + 1) → PUnit × D) → Fin (N + 1))
    (admissible : D × (Fin (N + 1) → PUnit × D) → Prop)
    [DecidablePred admissible]
    (hselect : Bcs.IsPredictableSelectorOn admissible select)
    (success : ((Fin (N + 1) → PUnit) × (Fin N → D)) → D → D → Prop)
    [∀ data, DecidableRel (success data)]
    (event : (Fin (N + 2) → D) → Prop) [DecidablePred event]
    (epsilon : ℚ)
    (hpairs : ∀ data, ((Finset.univ.filter fun pair : D × D ↦
      success data pair.1 pair.2).card : ℚ) /
        (Fintype.card D * Fintype.card D) ≤ epsilon)
    (hcover : ∀ tape, event tape →
      let fixed := tape fixedSlot
      let rest := fun k ↦
        (Equiv.punitProd D).symm (tape (fixedSlot.succAbove k))
      let selected := select fixed rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (selected.succAbove k)).2)
      admissible (fixed, rest) ∧ success data fixed (rest selected).2) :
    ((Finset.univ.filter event).card : ℚ) /
        Fintype.card (Fin (N + 2) → D) ≤ epsilon := by
  exact predictable_other_slot_tape_on_ratio_le fixedSlot
    (Equiv.punitProd D).symm select admissible hselect success event epsilon hpairs hcover

/-- Complete two-domain lazy-oracle count.  The charged query prefix chooses
the A or B relation before its answer is read; therefore the two pair budgets
combine by `max`, not by addition. -/
theorem lazy_prefix_two_branch_tape_card_le
    {Q D Output : Type*} [DecidableEq Q] [Fintype D] [DecidableEq D]
    {N budgetA budgetB : ℕ}
    (adversary : Merkle.RandomOracle.Tree Q D Output N) (dflt : D)
    (fixedSlot : Fin (N + 2)) (targetFrom : List Q → D → Q)
    (branchA : ((Fin (N + 1) → PUnit) × (Fin N → D)) → Bool)
    (successA successB :
      ((Fin (N + 1) → PUnit) × (Fin N → D)) → D → D → Prop)
    [∀ data, DecidableRel (successA data)]
    [∀ data, DecidableRel (successB data)]
    (hpairsA : ∀ data, (Finset.univ.filter fun pair : D × D ↦
      successA data pair.1 pair.2).card ≤ Fintype.card D * budgetA)
    (hpairsB : ∀ data, (Finset.univ.filter fun pair : D × D ↦
      successB data pair.1 pair.2).card ≤ Fintype.card D * budgetB)
    (event : (Fin (N + 2) → D) → Prop) [DecidablePred event]
    (hcover : ∀ tape, event tape →
      let fixed := tape fixedSlot
      let rest := fun k ↦
        (Equiv.punitProd D).symm (tape (fixedSlot.succAbove k))
      let selected := lazyPrefixSelector adversary dflt fixedSlot
        (Equiv.punitProd D).symm targetFrom fixed rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (selected.succAbove k)).2)
      lazyPrefixLater adversary dflt fixedSlot
          (Equiv.punitProd D).symm targetFrom (fixed, rest) ∧
        if branchA data then successA data fixed (rest selected).2
        else successB data fixed (rest selected).2) :
    (Finset.univ.filter event).card ≤
      max budgetA budgetB * Fintype.card D ^ (N + 1) := by
  classical
  let success : ((Fin (N + 1) → PUnit) × (Fin N → D)) → D → D → Prop :=
    fun data fixed later ↦
      if branchA data then successA data fixed later
      else successB data fixed later
  have hpairs : ∀ data, (Finset.univ.filter fun pair : D × D ↦
      success data pair.1 pair.2).card ≤
        Fintype.card D * max budgetA budgetB := by
    intro data
    by_cases hbranch : branchA data = true
    · simp only [success, hbranch, ↓reduceIte]
      exact (hpairsA data).trans
        (Nat.mul_le_mul_left _ (Nat.le_max_left _ _))
    · have hfalse : branchA data = false := Bool.eq_false_of_not_eq_true hbranch
      simp only [success, hfalse, Bool.false_eq_true, ↓reduceIte]
      exact (hpairsB data).trans
        (Nat.mul_le_mul_left _ (Nat.le_max_right _ _))
  apply predictable_raw_other_slot_tape_on_card_le fixedSlot
    (lazyPrefixSelector adversary dflt fixedSlot
      (Equiv.punitProd D).symm targetFrom)
    (lazyPrefixLater adversary dflt fixedSlot
      (Equiv.punitProd D).symm targetFrom)
    (lazyPrefixSelector_predictableOn adversary dflt fixedSlot
      (Equiv.punitProd D).symm targetFrom)
    success event (max budgetA budgetB) hpairs
  intro tape htape
  simpa [success] using hcover tape htape

/-- Exact-density two-branch lazy-oracle theorem.  Prefix-measurable A/B
branches combine by `max`, with no integer rounding and no branch union. -/
theorem lazy_prefix_two_branch_tape_ratio_le
    {Q D Output : Type*} [DecidableEq Q] [Fintype D] [DecidableEq D]
    [Nonempty D] {N : ℕ}
    (adversary : Merkle.RandomOracle.Tree Q D Output N) (dflt : D)
    (fixedSlot : Fin (N + 2)) (targetFrom : List Q → D → Q)
    (branchA : ((Fin (N + 1) → PUnit) × (Fin N → D)) → Bool)
    (successA successB :
      ((Fin (N + 1) → PUnit) × (Fin N → D)) → D → D → Prop)
    [∀ data, DecidableRel (successA data)]
    [∀ data, DecidableRel (successB data)]
    (epsilonA epsilonB : ℚ)
    (hpairsA : ∀ data, ((Finset.univ.filter fun pair : D × D ↦
      successA data pair.1 pair.2).card : ℚ) /
        (Fintype.card D * Fintype.card D) ≤ epsilonA)
    (hpairsB : ∀ data, ((Finset.univ.filter fun pair : D × D ↦
      successB data pair.1 pair.2).card : ℚ) /
        (Fintype.card D * Fintype.card D) ≤ epsilonB)
    (event : (Fin (N + 2) → D) → Prop) [DecidablePred event]
    (hcover : ∀ tape, event tape →
      let fixed := tape fixedSlot
      let rest := fun k ↦
        (Equiv.punitProd D).symm (tape (fixedSlot.succAbove k))
      let selected := lazyPrefixSelector adversary dflt fixedSlot
        (Equiv.punitProd D).symm targetFrom fixed rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (selected.succAbove k)).2)
      lazyPrefixLater adversary dflt fixedSlot
          (Equiv.punitProd D).symm targetFrom (fixed, rest) ∧
        if branchA data then successA data fixed (rest selected).2
        else successB data fixed (rest selected).2) :
    ((Finset.univ.filter event).card : ℚ) /
        Fintype.card (Fin (N + 2) → D) ≤ max epsilonA epsilonB := by
  classical
  let success : ((Fin (N + 1) → PUnit) × (Fin N → D)) → D → D → Prop :=
    fun data fixed later ↦
      if branchA data then successA data fixed later
      else successB data fixed later
  have hpairs : ∀ data, ((Finset.univ.filter fun pair : D × D ↦
      success data pair.1 pair.2).card : ℚ) /
        (Fintype.card D * Fintype.card D) ≤ max epsilonA epsilonB := by
    intro data
    by_cases hbranch : branchA data = true
    · simp only [success, hbranch, ↓reduceIte]
      exact (hpairsA data).trans (le_max_left _ _)
    · have hfalse : branchA data = false := Bool.eq_false_of_not_eq_true hbranch
      simp only [success, hfalse, Bool.false_eq_true, ↓reduceIte]
      exact (hpairsB data).trans (le_max_right _ _)
  apply predictable_raw_other_slot_tape_on_ratio_le fixedSlot
    (lazyPrefixSelector adversary dflt fixedSlot
      (Equiv.punitProd D).symm targetFrom)
    (lazyPrefixLater adversary dflt fixedSlot
      (Equiv.punitProd D).symm targetFrom)
    (lazyPrefixSelector_predictableOn adversary dflt fixedSlot
      (Equiv.punitProd D).symm targetFrom)
    success event (max epsilonA epsilonB) hpairs
  intro tape htape
  simpa [success] using hcover tape htape

/-! ## Response-indexed output target (Case A) -/

/-- The actual query trace for response-rigid Case A.  Both verifier queries
are installed in protocol order.  Keeping the precursor is essential when
the adversary never asked the defining `H₁`: omitting it would shift the
subsequent `H₂` slot and would not describe the canonical augmented trace. -/
def lazyResponseTargetTrace
    {Q D R Output : Type*} {N : ℕ} [DecidableEq Q]
    (adversary : Merkle.RandomOracle.Tree Q D Output N)
    (dflt : D) (fixedSlot : Fin (N + 2))
    (precursorOf targetOf : R → Q)
    (fixedResponse : D × R)
    (rest : Fin (N + 1) → PUnit × D) : List Q :=
  let tape := reinsertFixedTape (N := N) fixedSlot (Equiv.punitProd D).symm
    fixedResponse.1 rest
  let seen := (Merkle.RandomOracle.lazyRun tape dflt adversary []).2.1
  appendIfMissing (appendIfMissing seen (precursorOf fixedResponse.2))
    (targetOf fixedResponse.2)

/-- Exact first-occurrence slot of the response-dependent `H₂` target in the
canonical two-query augmentation. -/
def lazyResponseTargetSlot
    {Q D R Output : Type*} {N : ℕ} [DecidableEq Q]
    (adversary : Merkle.RandomOracle.Tree Q D Output N)
    (dflt : D) (fixedSlot : Fin (N + 2))
    (precursorOf targetOf : R → Q)
    (fixedResponse : D × R)
    (rest : Fin (N + 1) → PUnit × D) : Fin (N + 2) :=
  let trace := lazyResponseTargetTrace (N := N) adversary dflt fixedSlot
    precursorOf targetOf fixedResponse rest
  ⟨trace.idxOf (targetOf fixedResponse.2), by
    show trace.idxOf (targetOf fixedResponse.2) < N + 2
    have hmem : targetOf fixedResponse.2 ∈ trace := mem_appendIfMissing _ _
    have hseen := Merkle.RandomOracle.lazyRun_seen_length_le
      (reinsertFixedTape (N := N) fixedSlot (Equiv.punitProd D).symm
        fixedResponse.1 rest) dflt adversary []
    have hfirst := length_appendIfMissing_le
      (Merkle.RandomOracle.lazyRun
        (reinsertFixedTape (N := N) fixedSlot (Equiv.punitProd D).symm
          fixedResponse.1 rest) dflt adversary []).2.1
      (precursorOf fixedResponse.2)
    have hsecond := length_appendIfMissing_le
      (appendIfMissing
        (Merkle.RandomOracle.lazyRun
          (reinsertFixedTape (N := N) fixedSlot (Equiv.punitProd D).symm
            fixedResponse.1 rest) dflt adversary []).2.1
        (precursorOf fixedResponse.2)) (targetOf fixedResponse.2)
    have hfirst' := Nat.add_le_add_right hfirst 1
    have hseen' :
        (Merkle.RandomOracle.lazyRun
          (reinsertFixedTape (N := N) fixedSlot (Equiv.punitProd D).symm
            fixedResponse.1 rest) dflt adversary []).2.1.length + 1 + 1 ≤
          N + 2 := by
      have hs := hseen
      simp only [List.length_nil, zero_add] at hs
      omega
    exact (List.idxOf_lt_length_of_mem hmem).trans_le
      (hsecond.trans (hfirst'.trans hseen'))⟩

/-- First occurrence of a target fixed by an explicitly retained response.
The response may itself be the final output of the adversary; retaining it in
the counting pair is the response-rigidity step. -/
noncomputable def lazyResponseSelector
    {Q D R Output : Type*} {N : ℕ} [DecidableEq Q]
    (adversary : Merkle.RandomOracle.Tree Q D Output N)
    (dflt : D) (fixedSlot : Fin (N + 2))
    (precursorOf targetOf : R → Q) :
    D × R → (Fin (N + 1) → PUnit × D) → Fin (N + 1) :=
  fun fixedResponse rest ↦ eraseFixedSlotIndex fixedSlot
    (lazyResponseTargetSlot adversary dflt fixedSlot precursorOf targetOf
      fixedResponse rest)

/-- Branch on which the retained response's target occurs after the charged
alpha slot. -/
def lazyResponseLater
    {Q D R Output : Type*} {N : ℕ} [DecidableEq Q]
    (adversary : Merkle.RandomOracle.Tree Q D Output N)
    (dflt : D) (fixedSlot : Fin (N + 2))
    (precursorOf targetOf : R → Q) :
    (D × R) × (Fin (N + 1) → PUnit × D) → Prop :=
  fun input ↦ fixedSlot <
    lazyResponseTargetSlot adversary dflt fixedSlot precursorOf targetOf
      input.1 input.2

/-- Once the final response is retained as part of the counted pair, its H₂
target is a genuine predictable stopping coordinate. -/
theorem lazyResponseSelector_predictableOn
    {Q D R Output : Type*} {N : ℕ}
    [DecidableEq Q] [DecidableEq D]
    (adversary : Merkle.RandomOracle.Tree Q D Output N)
    (dflt : D) (fixedSlot : Fin (N + 2))
    (precursorOf targetOf : R → Q) :
    Bcs.IsPredictableSelectorOn
      (lazyResponseLater adversary dflt fixedSlot precursorOf targetOf)
      (lazyResponseSelector adversary dflt fixedSlot precursorOf targetOf) := by
  classical
  intro fixedResponse left right hleft _hright hagree
  let leftTape := reinsertFixedTape fixedSlot (Equiv.punitProd D).symm
    fixedResponse.1 left
  let rightTape := reinsertFixedTape fixedSlot (Equiv.punitProd D).symm
    fixedResponse.1 right
  let leftTarget := lazyResponseTargetSlot adversary dflt fixedSlot
    precursorOf targetOf fixedResponse left
  let rightTarget := lazyResponseTargetSlot adversary dflt fixedSlot
    precursorOf targetOf fixedResponse right
  let leftSelected := lazyResponseSelector adversary dflt fixedSlot
    precursorOf targetOf fixedResponse left
  have htargetNe : leftTarget ≠ fixedSlot := ne_of_gt hleft
  have hselectedSlot : fixedSlot.succAbove leftSelected = leftTarget :=
    succAbove_eraseFixedSlotIndex fixedSlot leftTarget htargetNe
  have htapes : ∀ i : Fin (N + 2), i.val < leftTarget.val →
      leftTape i = rightTape i := by
    intro i hi
    by_cases hifixed : i = fixedSlot
    · subst i
      simp [leftTape, rightTape, reinsertFixedTape]
    · obtain ⟨k, hk⟩ := Fin.exists_succAbove_eq hifixed
      have hklt : k < leftSelected := by
        apply (Fin.strictMono_succAbove fixedSlot).lt_iff_lt.mp
        rw [hk, hselectedSlot]
        exact hi
      have hrest := hagree k hklt
      rw [← hk]
      simpa [leftTape, rightTape, reinsertFixedTape] using
        congrArg (Equiv.punitProd D) hrest
  have hseen := Merkle.RandomOracle.lazyRun_seen_take_congr
    leftTape rightTape dflt leftTarget.val htapes adversary []
  have hfirst := take_appendIfMissing_congr
    (Merkle.RandomOracle.lazyRun leftTape dflt adversary []).2.1
    (Merkle.RandomOracle.lazyRun rightTape dflt adversary []).2.1
    (precursorOf fixedResponse.2) (leftTarget.val + 1) hseen
  have hsecond := take_appendIfMissing_congr
    (appendIfMissing
      (Merkle.RandomOracle.lazyRun leftTape dflt adversary []).2.1
      (precursorOf fixedResponse.2))
    (appendIfMissing
      (Merkle.RandomOracle.lazyRun rightTape dflt adversary []).2.1
      (precursorOf fixedResponse.2))
    (targetOf fixedResponse.2) (leftTarget.val + 1) hfirst
  have hindex :
      (lazyResponseTargetTrace adversary dflt fixedSlot precursorOf targetOf
        fixedResponse right).idxOf (targetOf fixedResponse.2) =
          leftTarget.val := by
    apply idxOf_eq_of_take_congr
      (lazyResponseTargetTrace adversary dflt fixedSlot precursorOf targetOf
        fixedResponse left)
      (lazyResponseTargetTrace adversary dflt fixedSlot precursorOf targetOf
        fixedResponse right)
      (targetOf fixedResponse.2) leftTarget.val
    · exact mem_appendIfMissing _ _
    · rfl
    · simpa [lazyResponseTargetTrace, leftTape, rightTape] using hsecond
  have htarget : rightTarget = leftTarget := by
    apply Fin.ext
    exact hindex
  simp only [lazyResponseSelector, rightTarget] at htarget ⊢
  rw [htarget]

/-- Canonical response-rigid keys make the two-target selector exactly the
`H₂` first-occurrence slot of `lazyFirstOccurrenceTrace`.  No key-discipline
hypothesis is exposed: the `H₁` key and response are retained together, and
the `H₂` key is definitionally their pair. -/
theorem lazyResponseTargetSlot_eq_canonicalSubsetSlot
    {AlphaKey Alpha Subset Response Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq Response]
    [Fintype Alpha] [Fintype Subset]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey (AlphaKey × Response)) (Answer Alpha Subset) Output N)
    (dflt : Answer Alpha Subset)
    (keyOf : Output → AlphaKey) (responseOf : Output → Response)
    (tape : Fin (N + 2) → Answer Alpha Subset)
    (fixedSlot : Fin (N + 2)) :
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    let retained := (keyOf output, responseOf output)
    let rest := fun k ↦ (Equiv.punitProd (Answer Alpha Subset)).symm
      (tape (fixedSlot.succAbove k))
    lazyResponseTargetSlot adversary dflt fixedSlot
        (fun value ↦ Query.alpha value.1) Query.subset
        (tape fixedSlot, retained) rest =
      (lazyFirstOccurrenceTrace N adversary dflt keyOf
        (fun output ↦ (keyOf output, responseOf output))).subsetSlot tape := by
  dsimp only
  apply Fin.ext
  have htape := reinsertFixedTape_self fixedSlot
    (Equiv.punitProd (Answer Alpha Subset)).symm tape
  simp only [lazyResponseTargetSlot, lazyResponseTargetTrace,
    Bcs.FirstOccurrenceTrace.subsetSlot, lazyFirstOccurrenceTrace,
    firstOccurrenceTrace]
  rw [htape]
  rfl

/-- On canonical listed Case A, the corrected response selector is
unconditionally the later defining `H₂` slot, and the two charged answers are
exactly the defining alpha and subset answers of the first-occurrence trace. -/
theorem canonicalCaseA_listed_selector
    {AlphaKey Alpha Subset Response Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq Response]
    [Fintype Alpha] [Fintype Subset]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey (AlphaKey × Response)) (Answer Alpha Subset) Output N)
    (dflt : Answer Alpha Subset)
    (keyOf : Output → AlphaKey) (responseOf : Output → Response)
    (listed win bindBreak :
      (Fin (N + 2) → Answer Alpha Subset) → Prop)
    (i : Fin (N + 2)) (tape : Fin (N + 2) → Answer Alpha Subset)
    (hcase : (lazyFirstOccurrenceTrace N adversary dflt keyOf
      (fun output ↦ (keyOf output, responseOf output))).caseA
        listed win bindBreak i tape)
    (hlisted : listed tape) :
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    let retained := (keyOf output, responseOf output)
    let rest := fun k ↦ (Equiv.punitProd (Answer Alpha Subset)).symm
      (tape (i.succAbove k))
    let chosen := lazyResponseSelector adversary dflt i
      (fun value ↦ Query.alpha value.1) Query.subset
      (tape i, retained) rest
    lazyResponseLater adversary dflt i
        (fun value ↦ Query.alpha value.1) Query.subset
        ((tape i, retained), rest) ∧
      alphaAnswer (tape i) = definingAlphaAnswer
        (lazyFirstOccurrenceTrace N adversary dflt keyOf
          (fun output ↦ (keyOf output, responseOf output))) tape ∧
      subsetAnswer (rest chosen).2 = definingSubsetAnswer
        (lazyFirstOccurrenceTrace N adversary dflt keyOf
          (fun output ↦ (keyOf output, responseOf output))) tape := by
  dsimp only
  let trace := lazyFirstOccurrenceTrace N adversary dflt keyOf
    (fun output ↦ (keyOf output, responseOf output))
  let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
  let retained := (keyOf output, responseOf output)
  let rest := fun k ↦ (Equiv.punitProd (Answer Alpha Subset)).symm
    (tape (i.succAbove k))
  let target := lazyResponseTargetSlot adversary dflt i
    (fun value ↦ Query.alpha value.1) Query.subset
    (tape i, retained) rest
  let chosen := lazyResponseSelector adversary dflt i
    (fun value ↦ Query.alpha value.1) Query.subset
    (tape i, retained) rest
  have htarget : target = trace.subsetSlot tape := by
    exact lazyResponseTargetSlot_eq_canonicalSubsetSlot adversary dflt
      keyOf responseOf tape i
  have halpha : trace.alphaSlot tape = i :=
    trace.alphaSlot_eq_of_caseA_listed listed win bindBreak i tape hcase hlisted
  have hlater : i < target := by
    rw [htarget, ← halpha]
    exact hcase.2.2.1
  have hchosen : i.succAbove chosen = trace.subsetSlot tape := by
    rw [← htarget]
    exact succAbove_eraseFixedSlotIndex i target (ne_of_gt hlater)
  refine ⟨?_, ?_, ?_⟩
  · exact hlater
  · symm
    exact definingAlphaAnswer_eq_of_alphaSlot_eq trace tape i halpha
  · change subsetAnswer (rest chosen).2 = definingSubsetAnswer trace tape
    rw [definingSubsetAnswer_eq_of_subsetSlot_eq trace tape
      (trace.subsetSlot tape) rfl]
    have hrest : (rest chosen).2 = tape (trace.subsetSlot tape) := by
      simp only [rest]
      rw [← hchosen]
      simp
    rw [hrest]

/-- Recover the canonical `H₁` query from the charged `H₂` query at the end
of a query prefix.  The fallback is unreachable on Case B and therefore does
not become a protocol hypothesis. -/
def canonicalAlphaTargetFromPrefix
    {AlphaKey Response D : Type*}
    (fallback : AlphaKey)
    (pref : List (Query AlphaKey (AlphaKey × Response))) (_fixed : D) :
    Query AlphaKey (AlphaKey × Response) :=
  match pref.getLast? with
  | some (.subset value) => .alpha value.1
  | _ => .alpha fallback

/-- Recover the complete `(H₁ key, response)` payload encoded by the charged
`H₂` query.  On Case B the fallback is unreachable: the charged query itself
is the defining subset query. -/
def canonicalSubsetKeyFromPrefix
    {AlphaKey Response : Type*}
    (fallback : AlphaKey × Response)
    (pref : List (Query AlphaKey (AlphaKey × Response))) :
    AlphaKey × Response :=
  match pref.getLast? with
  | some (.subset value) => value
  | _ => fallback

/-- The defining Case-A `H₂` payload as a function of the answer prefix
strictly before its charged slot.  If the adversary itself made the slot's
subset query, its payload is read from `slotQuery`.  Otherwise the verifier
appended the defining query after the adversary stopped; in that branch every
slot used by the adversary is already in the prefix, so the padded execution
has the same final output. -/
noncomputable def canonicalCaseAFloorSubsetKey
    {AlphaKey Alpha Subset Response Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq Response]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey (AlphaKey × Response)) (Answer Alpha Subset) Output N)
    (dflt : Answer Alpha Subset) (alphaKey : AlphaKey)
    (responseOf : Output → Response) (i : Fin (N + 2))
    (pref : Sumcheck.Prefix (Answer Alpha Subset) i.val) :
    AlphaKey × Response :=
  let padded := Merkle.RandomOracle.pad (T := N + 2) dflt pref
  match Merkle.RandomOracle.slotQuery (T := N + 2) dflt adversary pref with
  | some (.subset value) => value
  | _ =>
      (alphaKey,
        responseOf (Merkle.RandomOracle.lazyRun padded dflt adversary []).1)

/-- On the unlisted Case-A branch, the prefix-derived payload is exactly the
actual final `(H₁ key, response)` used in the defining `H₂` query.  This is
proved from lazy execution and first occurrence; no response-stability
hypothesis is exposed. -/
theorem canonicalCaseAFloorSubsetKey_eq
    {AlphaKey Alpha Subset Response Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq Response]
    [Fintype Alpha] [Fintype Subset]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey (AlphaKey × Response)) (Answer Alpha Subset) Output N)
    (dflt : Answer Alpha Subset) (alphaKey : AlphaKey)
    (responseOf : Output → Response)
    (listed win bindBreak :
      (Fin (N + 2) → Answer Alpha Subset) → Prop)
    (i : Fin (N + 2)) (tape : Fin (N + 2) → Answer Alpha Subset)
    (hcase : (lazyFirstOccurrenceTrace N adversary dflt
      (fun _output ↦ alphaKey)
      (fun output ↦ (alphaKey, responseOf output))).caseA
        listed win bindBreak i tape)
    (hunlisted : ¬listed tape) :
    canonicalCaseAFloorSubsetKey adversary dflt alphaKey responseOf i
        (Sumcheck.extract_prefix tape i) =
      (alphaKey,
        responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1) := by
  classical
  let run := Merkle.RandomOracle.lazyRun tape dflt adversary []
  let seen := run.2.1
  let target : Query AlphaKey (AlphaKey × Response) :=
    .subset (alphaKey, responseOf run.1)
  let first := appendIfMissing seen (.alpha alphaKey)
  let augmented := appendIfMissing first target
  have hslot :=
    (lazyFirstOccurrenceTrace N adversary dflt
      (fun _output ↦ alphaKey)
      (fun output ↦ (alphaKey, responseOf output))).subsetSlot_eq_of_caseA_floor
        listed win bindBreak i tape hcase hunlisted
  have hidx : augmented.idxOf target = i.val := by
    exact Fin.ext_iff.mp hslot
  by_cases hi : i.val < seen.length
  · have htargetSeen : target ∈ seen := by
      by_contra hnot
      have hnotFirst : target ∉ first := by
        unfold first appendIfMissing
        split
        · exact hnot
        · simp [hnot, target]
      have htargetIndex : augmented.idxOf target = first.length := by
        rw [show augmented = first ++ [target] by
          simp [augmented, appendIfMissing, hnotFirst]]
        rw [List.idxOf_append_of_notMem hnotFirst]
        simp
      have hseenFirst : seen.length ≤ first.length := by
        unfold first appendIfMissing
        split <;> simp
      rw [hidx] at htargetIndex
      omega
    have htargetFirst : target ∈ first :=
      mem_appendIfMissing_of_mem htargetSeen
    have hidxSeen : seen.idxOf target = i.val := by
      rw [idxOf_appendIfMissing_of_mem first target target htargetFirst,
        idxOf_appendIfMissing_of_mem seen (.alpha alphaKey) target
          htargetSeen] at hidx
      exact hidx
    have hget : seen[i.val]? = some target := by
      rw [List.getElem?_eq_getElem hi]
      congr 1
      have htargetIndexLt : seen.idxOf target < seen.length :=
        List.idxOf_lt_length_of_mem htargetSeen
      simpa only [hidxSeen] using List.getElem_idxOf htargetIndexLt
    have hslotQuery := Merkle.RandomOracle.slotQuery_eq
      (T := N + 2) dflt adversary (j := i.val) (by omega) tape
    have hslotQuery' :
        Merkle.RandomOracle.slotQuery (T := N + 2) dflt adversary
            (Sumcheck.extract_prefix tape i) = some target := by
      convert hslotQuery.trans hget using 1
      congr 1
    simp only [canonicalCaseAFloorSubsetKey, hslotQuery', target, run]
  · have hseenLe : seen.length ≤ i.val := Nat.le_of_not_gt hi
    let padded := Merkle.RandomOracle.pad (T := N + 2) dflt
      (Sumcheck.extract_prefix tape i)
    have hagree : ∀ j : Fin (N + 2), j.val < seen.length →
        tape j = padded j := by
      intro j hj
      symm
      exact Merkle.RandomOracle.pad_agree dflt
        (Sumcheck.extract_prefix tape i) j (hj.trans_le hseenLe)
    have hrun : Merkle.RandomOracle.lazyRun tape dflt adversary [] =
        Merkle.RandomOracle.lazyRun padded dflt adversary [] := by
      apply Merkle.RandomOracle.lazyRun_eq_of_agree_below_seen_length
      simpa only [run, seen] using hagree
    have hnone : seen[i.val]? = none :=
      List.getElem?_eq_none hseenLe
    have hslotQuery := Merkle.RandomOracle.slotQuery_eq
      (T := N + 2) dflt adversary (j := i.val) (by omega) tape
    have hslotQuery' :
        Merkle.RandomOracle.slotQuery (T := N + 2) dflt adversary
            (Sumcheck.extract_prefix tape i) = none := by
      convert hslotQuery.trans hnone using 1
      congr 1
    simp only [canonicalCaseAFloorSubsetKey, hslotQuery']
    rw [← hrun]

/-- The defining `H₁` answer reconstructed from the same pre-`H₂` prefix.
The commitment key is fixed before either Fiat--Shamir query; the first
occurrence of that key is therefore determined before the charged Case-A
floor slot. -/
noncomputable def canonicalCaseAFloorAlpha
    {AlphaKey Alpha Subset Response Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq Response]
    [Fintype Alpha] [Fintype Subset]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey (AlphaKey × Response)) (Answer Alpha Subset) Output N)
    (dflt : Answer Alpha Subset) (alphaKey : AlphaKey)
    (responseOf : Output → Response) (i : Fin (N + 2))
    (pref : Sumcheck.Prefix (Answer Alpha Subset) i.val) : Alpha :=
  let padded := Merkle.RandomOracle.pad (T := N + 2) dflt pref
  let trace := lazyFirstOccurrenceTrace N adversary dflt
    (fun _output ↦ alphaKey) (fun output ↦ (alphaKey, responseOf output))
  definingAlphaAnswer trace padded

/-- On unlisted Case A, `canonicalCaseAFloorAlpha` is the actual defining
batching challenge.  Together with `canonicalCaseAFloorSubsetKey_eq`, this
makes the complete accepting-coordinate set a function of the tape prefix
strictly before the fresh `H₂` answer. -/
theorem canonicalCaseAFloorAlpha_eq
    {AlphaKey Alpha Subset Response Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq Response]
    [Fintype Alpha] [Fintype Subset]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey (AlphaKey × Response)) (Answer Alpha Subset) Output N)
    (dflt : Answer Alpha Subset) (alphaKey : AlphaKey)
    (responseOf : Output → Response)
    (listed win bindBreak :
      (Fin (N + 2) → Answer Alpha Subset) → Prop)
    (i : Fin (N + 2)) (tape : Fin (N + 2) → Answer Alpha Subset)
    (hcase : (lazyFirstOccurrenceTrace N adversary dflt
      (fun _output ↦ alphaKey)
      (fun output ↦ (alphaKey, responseOf output))).caseA
        listed win bindBreak i tape)
    (hunlisted : ¬listed tape) :
    canonicalCaseAFloorAlpha adversary dflt alphaKey responseOf i
        (Sumcheck.extract_prefix tape i) =
      definingAlphaAnswer
        (lazyFirstOccurrenceTrace N adversary dflt
          (fun _output ↦ alphaKey)
          (fun output ↦ (alphaKey, responseOf output))) tape := by
  classical
  let trace := lazyFirstOccurrenceTrace N adversary dflt
    (fun _output ↦ alphaKey)
    (fun output ↦ (alphaKey, responseOf output))
  let padded := Merkle.RandomOracle.pad (T := N + 2) dflt
    (Sumcheck.extract_prefix tape i)
  let actualSeen := (Merkle.RandomOracle.lazyRun tape dflt adversary []).2.1
  let paddedSeen := (Merkle.RandomOracle.lazyRun padded dflt adversary []).2.1
  let alphaQuery : Query AlphaKey (AlphaKey × Response) := .alpha alphaKey
  let actualFirst := appendIfMissing actualSeen alphaQuery
  let paddedFirst := appendIfMissing paddedSeen alphaQuery
  let actualAlphaSlot := trace.alphaSlot tape
  have hsubsetSlot := trace.subsetSlot_eq_of_caseA_floor
    listed win bindBreak i tape hcase hunlisted
  have halphaBefore : actualAlphaSlot < i := by
    rw [← hsubsetSlot]
    exact hcase.2.2.1
  have hagree : ∀ j : Fin (N + 2), j.val < actualAlphaSlot.val →
      padded j = tape j := by
    intro j hj
    exact Merkle.RandomOracle.pad_agree dflt
      (Sumcheck.extract_prefix tape i) j
      (hj.trans halphaBefore)
  have hseen : paddedSeen.take (actualAlphaSlot.val + 1) =
      actualSeen.take (actualAlphaSlot.val + 1) := by
    simpa only [paddedSeen, actualSeen] using
      Merkle.RandomOracle.lazyRun_seen_take_congr padded tape dflt
        actualAlphaSlot.val hagree adversary []
  have hfirst : paddedFirst.take (actualAlphaSlot.val + 1) =
      actualFirst.take (actualAlphaSlot.val + 1) := by
    exact take_appendIfMissing_congr paddedSeen actualSeen alphaQuery
      (actualAlphaSlot.val + 1) hseen
  have halphaActualMem : alphaQuery ∈ actualFirst :=
    mem_appendIfMissing _ _
  have halphaPaddedMem : alphaQuery ∈ paddedFirst :=
    mem_appendIfMissing _ _
  have halphaActualIdx : actualFirst.idxOf alphaQuery = actualAlphaSlot.val := by
    have hfull :
        (appendIfMissing actualFirst
          (.subset (alphaKey,
            responseOf
              (Merkle.RandomOracle.lazyRun tape dflt adversary []).1))).idxOf
            alphaQuery = actualAlphaSlot.val := by
      rfl
    rw [idxOf_appendIfMissing_of_mem _ _ _ halphaActualMem] at hfull
    exact hfull
  have halphaPaddedIdx : paddedFirst.idxOf alphaQuery = actualAlphaSlot.val := by
    apply idxOf_eq_of_take_congr actualFirst paddedFirst alphaQuery
      actualAlphaSlot.val halphaActualMem halphaActualIdx
    exact hfirst.symm
  have hpaddedSlot : trace.alphaSlot padded = actualAlphaSlot := by
    apply Fin.ext
    have hfull :
        (appendIfMissing paddedFirst
          (.subset (alphaKey,
            responseOf
              (Merkle.RandomOracle.lazyRun padded dflt adversary []).1))).idxOf
            alphaQuery = paddedFirst.idxOf alphaQuery :=
      idxOf_appendIfMissing_of_mem _ _ _ halphaPaddedMem
    simpa only [trace, paddedFirst, paddedSeen, alphaQuery, augmentedTrace,
      Bcs.FirstOccurrenceTrace.alphaSlot, lazyFirstOccurrenceTrace,
      firstOccurrenceTrace] using
        hfull.trans halphaPaddedIdx
  unfold canonicalCaseAFloorAlpha
  change alphaAnswer (padded (trace.alphaSlot padded)) =
    alphaAnswer (tape (trace.alphaSlot tape))
  rw [hpaddedSlot]
  congr 1
  exact Merkle.RandomOracle.pad_agree dflt
    (Sumcheck.extract_prefix tape i) actualAlphaSlot halphaBefore

/-- On canonical Case B, the prefix through the charged H₂ slot determines
both the exact H₁ key and the final response.  In particular the response is
fixed before the charged H₂ answer is read. -/
theorem canonicalCaseB_prefix_subsetKey
    {AlphaKey Alpha Subset Response Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq Response]
    [Fintype Alpha] [Fintype Subset]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey (AlphaKey × Response)) (Answer Alpha Subset) Output N)
    (dflt : Answer Alpha Subset)
    (keyOf : Output → AlphaKey) (responseOf : Output → Response)
    (fallback : AlphaKey × Response)
    (win bindBreak : (Fin (N + 2) → Answer Alpha Subset) → Prop)
    (i : Fin (N + 2)) (tape : Fin (N + 2) → Answer Alpha Subset)
    (hcase : (lazyFirstOccurrenceTrace N adversary dflt keyOf
      (fun output ↦ (keyOf output, responseOf output))).caseB
        win bindBreak i tape) :
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    let seen := (Merkle.RandomOracle.lazyRun tape dflt adversary []).2.1
    canonicalSubsetKeyFromPrefix fallback (seen.take (i.val + 1)) =
      (keyOf output, responseOf output) := by
  dsimp only
  let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
  let seen := (Merkle.RandomOracle.lazyRun tape dflt adversary []).2.1
  let alphaQuery : Query AlphaKey (AlphaKey × Response) :=
    .alpha (keyOf output)
  let subsetQuery : Query AlphaKey (AlphaKey × Response) :=
    .subset (keyOf output, responseOf output)
  let first := appendIfMissing seen alphaQuery
  have hsubsetSeen : subsetQuery ∈ seen := by
    by_contra hmissing
    have hmissingFirst : subsetQuery ∉ first := by
      unfold first appendIfMissing
      split
      · exact hmissing
      · simp [hmissing, subsetQuery, alphaQuery]
    have halphaFirst : alphaQuery ∈ first := mem_appendIfMissing _ _
    have halphaLt : first.idxOf alphaQuery < first.length :=
      List.idxOf_lt_length_of_mem halphaFirst
    have horder := hcase.2.2.2
    change (appendIfMissing first subsetQuery).idxOf subsetQuery <
      (appendIfMissing first subsetQuery).idxOf alphaQuery at horder
    have htrace : appendIfMissing first subsetQuery = first ++ [subsetQuery] := by
      simp [appendIfMissing, hmissingFirst]
    rw [htrace, List.idxOf_append_of_notMem hmissingFirst,
      List.idxOf_append_of_mem halphaFirst] at horder
    simp at horder
    omega
  have hidxSeen : seen.idxOf subsetQuery = i.val := by
    have hslot := hcase.2.2.1
    change (appendIfMissing first subsetQuery).idxOf subsetQuery = i.val at hslot
    have hsubsetFirst : subsetQuery ∈ first :=
      mem_appendIfMissing_of_mem hsubsetSeen
    have hfinal : appendIfMissing first subsetQuery = first := by
      simp [appendIfMissing, hsubsetFirst]
    have hfirst : first.idxOf subsetQuery = seen.idxOf subsetQuery := by
      unfold first appendIfMissing
      split
      · rfl
      · exact List.idxOf_append_of_mem hsubsetSeen
    rw [hfinal, hfirst] at hslot
    exact hslot
  have hilt : i.val < seen.length := by
    rw [← hidxSeen]
    exact List.idxOf_lt_length_of_mem hsubsetSeen
  have hget : seen[i.val] = subsetQuery := by
    have hidxlt : seen.idxOf subsetQuery < seen.length :=
      List.idxOf_lt_length_of_mem hsubsetSeen
    simpa only [hidxSeen] using List.getElem_idxOf hidxlt
  rw [List.take_succ_eq_append_getElem hilt, hget]
  simp [canonicalSubsetKeyFromPrefix, subsetQuery]
  exact ⟨rfl, rfl⟩

/-- The response payload read from the query prefix through a designated
lazy-oracle slot. -/
def canonicalResponseAtSlot
    {AlphaKey Alpha Subset Response Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq Response]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey (AlphaKey × Response)) (Answer Alpha Subset) Output N)
    (dflt : Answer Alpha Subset) (fallback : AlphaKey × Response)
    (i : Fin (N + 2)) (tape : Fin (N + 2) → Answer Alpha Subset) : Response :=
  (canonicalSubsetKeyFromPrefix fallback
    ((Merkle.RandomOracle.lazyRun tape dflt adversary []).2.1.take
      (i.val + 1))).2

/-- On Case B, `canonicalResponseAtSlot` is the adversary's exact final
response. -/
theorem canonicalResponseAtSlot_eq_of_caseB
    {AlphaKey Alpha Subset Response Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq Response]
    [Fintype Alpha] [Fintype Subset]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey (AlphaKey × Response)) (Answer Alpha Subset) Output N)
    (dflt : Answer Alpha Subset)
    (keyOf : Output → AlphaKey) (responseOf : Output → Response)
    (fallback : AlphaKey × Response)
    (win bindBreak : (Fin (N + 2) → Answer Alpha Subset) → Prop)
    (i : Fin (N + 2)) (tape : Fin (N + 2) → Answer Alpha Subset)
    (hcase : (lazyFirstOccurrenceTrace N adversary dflt keyOf
      (fun output ↦ (keyOf output, responseOf output))).caseB
        win bindBreak i tape) :
    canonicalResponseAtSlot adversary dflt fallback i tape =
      responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1 := by
  have h := canonicalCaseB_prefix_subsetKey adversary dflt keyOf responseOf
    fallback win bindBreak i tape hcase
  simpa only [canonicalResponseAtSlot] using congrArg Prod.snd h

/-- The response read at slot `i` depends only on answer slots strictly
before `i`; the charged H₂ answer and every later answer are irrelevant. -/
theorem canonicalResponseAtSlot_congr
    {AlphaKey Alpha Subset Response Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq Response]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey (AlphaKey × Response)) (Answer Alpha Subset) Output N)
    (dflt : Answer Alpha Subset) (fallback : AlphaKey × Response)
    (i : Fin (N + 2))
    (left right : Fin (N + 2) → Answer Alpha Subset)
    (hagree : ∀ j, j.val < i.val → left j = right j) :
    canonicalResponseAtSlot adversary dflt fallback i left =
      canonicalResponseAtSlot adversary dflt fallback i right := by
  have hseen := Merkle.RandomOracle.lazyRun_seen_take_congr
    left right dflt i.val hagree adversary []
  exact congrArg
    (fun pref ↦ (canonicalSubsetKeyFromPrefix fallback pref).2) hseen

/-- Canonical full tape built from the data left after deleting a charged
slot and one later selected slot.  Only the first `N` coordinates are copied;
the final two coordinates are filled with the public default. -/
def prefixTapeFromErasedData
    {D : Type*} {N : ℕ} (dflt : D)
    (data : (Fin (N + 1) → PUnit.{1}) × (Fin N → D)) : Fin (N + 2) → D :=
  fun j ↦ if h : j.val < N then data.2 ⟨j.val, h⟩ else dflt

/-- If the selected slot is later than the charged slot, the canonical tape
from erased data agrees with the original tape at every coordinate strictly
before the charged slot.  Hence every pre-answer query-prefix function may
be evaluated on `data` alone. -/
theorem prefixTapeFromErasedData_eq_before
    {D : Type*} {N : ℕ} (dflt : D)
    (fixedSlot : Fin (N + 2)) (selected : Fin (N + 1))
    (tape : Fin (N + 2) → D)
    (hlater : fixedSlot < fixedSlot.succAbove selected) :
    let rest := fun k ↦
      (Equiv.punitProd.{0} D).symm (tape (fixedSlot.succAbove k))
    let data := ((fun k ↦ (rest k).1),
      fun k ↦ (rest (selected.succAbove k)).2)
    ∀ j, j < fixedSlot → prefixTapeFromErasedData dflt data j = tape j := by
  dsimp only
  intro j hj
  have hfixedSelected : fixedSlot ≤ selected.castSucc :=
    (Fin.lt_succAbove_iff_le_castSucc fixedSlot selected).mp hlater
  have hjN : j.val < N := by
    have hselected := selected.isLt
    change j.val < fixedSlot.val at hj
    change fixedSlot.val ≤ selected.val at hfixedSelected
    omega
  let middle : Fin (N + 1) := ⟨j.val, by omega⟩
  let small : Fin N := ⟨j.val, hjN⟩
  have hjSelected : middle < selected := by
    change j.val < selected.val
    change j.val < fixedSlot.val at hj
    change fixedSlot.val ≤ selected.val at hfixedSelected
    omega
  have hselectedAbove : selected.succAbove small = middle := by
    have hsmallSelected : small.castSucc < selected := by
      change j.val < selected.val
      exact hjSelected
    rw [Fin.succAbove_of_castSucc_lt selected small hsmallSelected]
    apply Fin.ext
    rfl
  have hfixedAbove : fixedSlot.succAbove middle = j := by
    have hmiddleFixed : middle.castSucc < fixedSlot := by
      change j.val < fixedSlot.val
      exact hj
    rw [Fin.succAbove_of_castSucc_lt fixedSlot middle hmiddleFixed]
    apply Fin.ext
    rfl
  simp only [prefixTapeFromErasedData, dif_pos hjN]
  rw [hselectedAbove, hfixedAbove]
  exact (Equiv.punitProd.{0} D).apply_symm_apply (tape j)

/-- Case-B response reconstructed solely from the erased counting data. -/
def canonicalCaseBResponseFromData
    {AlphaKey Alpha Subset Response Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq Response]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey (AlphaKey × Response)) (Answer Alpha Subset) Output N)
    (dflt : Answer Alpha Subset) (fallback : AlphaKey × Response)
    (fixedSlot : Fin (N + 2))
    (data : (Fin (N + 1) → PUnit.{1}) ×
      (Fin N → Answer Alpha Subset)) : Response :=
  canonicalResponseAtSlot adversary dflt fallback fixedSlot
    (prefixTapeFromErasedData dflt data)

/-- On canonical Case B the defining `H₂` query must already occur in the
adversary trace (otherwise protocol-order augmentation would put `H₁`
first).  Consequently its prefix reveals the exact `H₁` key. -/
theorem canonicalCaseB_prefix_target
    {AlphaKey Alpha Subset Response Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq Response]
    [Fintype Alpha] [Fintype Subset]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey (AlphaKey × Response)) (Answer Alpha Subset) Output N)
    (dflt : Answer Alpha Subset)
    (keyOf : Output → AlphaKey) (responseOf : Output → Response)
    (fallback : AlphaKey)
    (win bindBreak : (Fin (N + 2) → Answer Alpha Subset) → Prop)
    (i : Fin (N + 2)) (tape : Fin (N + 2) → Answer Alpha Subset)
    (hcase : (lazyFirstOccurrenceTrace N adversary dflt keyOf
      (fun output ↦ (keyOf output, responseOf output))).caseB
        win bindBreak i tape) :
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    let seen := (Merkle.RandomOracle.lazyRun tape dflt adversary []).2.1
    canonicalAlphaTargetFromPrefix fallback (seen.take (i.val + 1)) (tape i) =
      Query.alpha (keyOf output) := by
  dsimp only
  let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
  let seen := (Merkle.RandomOracle.lazyRun tape dflt adversary []).2.1
  let alphaQuery : Query AlphaKey (AlphaKey × Response) :=
    .alpha (keyOf output)
  let subsetQuery : Query AlphaKey (AlphaKey × Response) :=
    .subset (keyOf output, responseOf output)
  let first := appendIfMissing seen alphaQuery
  have hsubsetSeen : subsetQuery ∈ seen := by
    by_contra hmissing
    have hmissingFirst : subsetQuery ∉ first := by
      unfold first appendIfMissing
      split
      · exact hmissing
      · simp [hmissing, subsetQuery, alphaQuery]
    have halphaFirst : alphaQuery ∈ first := mem_appendIfMissing _ _
    have halphaLt : first.idxOf alphaQuery < first.length :=
      List.idxOf_lt_length_of_mem halphaFirst
    have horder := hcase.2.2.2
    change (appendIfMissing first subsetQuery).idxOf subsetQuery <
      (appendIfMissing first subsetQuery).idxOf alphaQuery at horder
    have htrace : appendIfMissing first subsetQuery = first ++ [subsetQuery] := by
      simp [appendIfMissing, hmissingFirst]
    rw [htrace, List.idxOf_append_of_notMem hmissingFirst,
      List.idxOf_append_of_mem halphaFirst] at horder
    simp at horder
    omega
  have hidxSeen : seen.idxOf subsetQuery = i.val := by
    have hslot := hcase.2.2.1
    change (appendIfMissing first subsetQuery).idxOf subsetQuery = i.val at hslot
    have hsubsetFirst : subsetQuery ∈ first :=
      mem_appendIfMissing_of_mem hsubsetSeen
    have hfinal : appendIfMissing first subsetQuery = first := by
      simp [appendIfMissing, hsubsetFirst]
    have hfirst : first.idxOf subsetQuery = seen.idxOf subsetQuery := by
      unfold first appendIfMissing
      split
      · rfl
      · exact List.idxOf_append_of_mem hsubsetSeen
    rw [hfinal, hfirst] at hslot
    exact hslot
  have hilt : i.val < seen.length := by
    rw [← hidxSeen]
    exact List.idxOf_lt_length_of_mem hsubsetSeen
  have hget : seen[i.val] = subsetQuery := by
    have hidxlt : seen.idxOf subsetQuery < seen.length :=
      List.idxOf_lt_length_of_mem hsubsetSeen
    simpa only [hidxSeen] using List.getElem_idxOf hidxlt
  rw [List.take_succ_eq_append_getElem hilt, hget]
  simp [canonicalAlphaTargetFromPrefix, subsetQuery]
  change keyOf output = keyOf output
  rfl

/-- The prefix-derived selector is exactly the canonical defining `H₁` slot
on Case B. -/
theorem lazyPrefixTargetSlot_eq_canonicalAlphaSlot_of_caseB
    {AlphaKey Alpha Subset Response Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq Response]
    [Fintype Alpha] [Fintype Subset]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey (AlphaKey × Response)) (Answer Alpha Subset) Output N)
    (dflt : Answer Alpha Subset)
    (keyOf : Output → AlphaKey) (responseOf : Output → Response)
    (fallback : AlphaKey)
    (win bindBreak : (Fin (N + 2) → Answer Alpha Subset) → Prop)
    (i : Fin (N + 2)) (tape : Fin (N + 2) → Answer Alpha Subset)
    (hcase : (lazyFirstOccurrenceTrace N adversary dflt keyOf
      (fun output ↦ (keyOf output, responseOf output))).caseB
        win bindBreak i tape) :
    let rest := fun k ↦ (Equiv.punitProd (Answer Alpha Subset)).symm
      (tape (i.succAbove k))
    lazyPrefixTargetSlot adversary dflt i
        (Equiv.punitProd (Answer Alpha Subset)).symm
        (canonicalAlphaTargetFromPrefix fallback) (tape i) rest =
      (lazyFirstOccurrenceTrace N adversary dflt keyOf
        (fun output ↦ (keyOf output, responseOf output))).alphaSlot tape := by
  dsimp only
  let trace := lazyFirstOccurrenceTrace N adversary dflt keyOf
    (fun output ↦ (keyOf output, responseOf output))
  let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
  let seen := (Merkle.RandomOracle.lazyRun tape dflt adversary []).2.1
  let alphaQuery : Query AlphaKey (AlphaKey × Response) :=
    .alpha (keyOf output)
  let subsetQuery : Query AlphaKey (AlphaKey × Response) :=
    .subset (keyOf output, responseOf output)
  let first := appendIfMissing seen alphaQuery
  have htape := reinsertFixedTape_self i
    (Equiv.punitProd (Answer Alpha Subset)).symm tape
  have htarget : canonicalAlphaTargetFromPrefix fallback
      (seen.take (i.val + 1)) (tape i) = alphaQuery := by
    exact canonicalCaseB_prefix_target adversary dflt keyOf responseOf fallback
      win bindBreak i tape hcase
  apply Fin.ext
  simp only [lazyPrefixTargetSlot, lazyPrefixTargetTrace,
    Bcs.FirstOccurrenceTrace.alphaSlot, lazyFirstOccurrenceTrace,
    firstOccurrenceTrace]
  rw [htape, htarget]
  have halphaFirst : alphaQuery ∈ first := mem_appendIfMissing _ _
  change first.idxOf alphaQuery =
    (appendIfMissing first subsetQuery).idxOf alphaQuery
  by_cases hsubsetFirst : subsetQuery ∈ first
  · rw [show appendIfMissing first subsetQuery = first by
      simp [appendIfMissing, hsubsetFirst]]
  · have hfinal : appendIfMissing first subsetQuery = first ++ [subsetQuery] := by
      simp [appendIfMissing, hsubsetFirst]
    rw [hfinal, List.idxOf_append_of_mem halphaFirst]

/-- On canonical Case B, predictable deletion selects the later defining
`H₁` answer, while the charged fixed answer is exactly the defining `H₂`
answer.  This discharges the full operational key discipline without a
caller-supplied trace hypothesis. -/
theorem canonicalCaseB_selector
    {AlphaKey Alpha Subset Response Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq Response]
    [Fintype Alpha] [Fintype Subset]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey (AlphaKey × Response)) (Answer Alpha Subset) Output N)
    (dflt : Answer Alpha Subset)
    (keyOf : Output → AlphaKey) (responseOf : Output → Response)
    (fallback : AlphaKey)
    (win bindBreak : (Fin (N + 2) → Answer Alpha Subset) → Prop)
    (i : Fin (N + 2)) (tape : Fin (N + 2) → Answer Alpha Subset)
    (hcase : (lazyFirstOccurrenceTrace N adversary dflt keyOf
      (fun output ↦ (keyOf output, responseOf output))).caseB
        win bindBreak i tape) :
    let rest := fun k ↦ (Equiv.punitProd (Answer Alpha Subset)).symm
      (tape (i.succAbove k))
    let chosen := lazyPrefixSelector adversary dflt i
      (Equiv.punitProd (Answer Alpha Subset)).symm
      (canonicalAlphaTargetFromPrefix fallback) (tape i) rest
    lazyPrefixLater adversary dflt i
        (Equiv.punitProd (Answer Alpha Subset)).symm
        (canonicalAlphaTargetFromPrefix fallback) (tape i, rest) ∧
      subsetAnswer (tape i) = definingSubsetAnswer
        (lazyFirstOccurrenceTrace N adversary dflt keyOf
          (fun output ↦ (keyOf output, responseOf output))) tape ∧
      alphaAnswer (rest chosen).2 = definingAlphaAnswer
        (lazyFirstOccurrenceTrace N adversary dflt keyOf
          (fun output ↦ (keyOf output, responseOf output))) tape := by
  dsimp only
  let trace := lazyFirstOccurrenceTrace N adversary dflt keyOf
    (fun output ↦ (keyOf output, responseOf output))
  let rest := fun k ↦ (Equiv.punitProd (Answer Alpha Subset)).symm
    (tape (i.succAbove k))
  let target := lazyPrefixTargetSlot adversary dflt i
    (Equiv.punitProd (Answer Alpha Subset)).symm
    (canonicalAlphaTargetFromPrefix fallback) (tape i) rest
  let chosen := lazyPrefixSelector adversary dflt i
    (Equiv.punitProd (Answer Alpha Subset)).symm
    (canonicalAlphaTargetFromPrefix fallback) (tape i) rest
  have htarget : target = trace.alphaSlot tape := by
    exact lazyPrefixTargetSlot_eq_canonicalAlphaSlot_of_caseB adversary dflt
      keyOf responseOf fallback win bindBreak i tape hcase
  have hsubset : trace.subsetSlot tape = i :=
    trace.subsetSlot_eq_of_caseB win bindBreak i tape hcase
  have hlater : i < target := by
    rw [htarget, ← hsubset]
    exact hcase.2.2.2
  have hchosen : i.succAbove chosen = trace.alphaSlot tape := by
    rw [← htarget]
    exact succAbove_eraseFixedSlotIndex i target (ne_of_gt hlater)
  refine ⟨hlater, ?_, ?_⟩
  · symm
    exact definingSubsetAnswer_eq_of_subsetSlot_eq trace tape i hsubset
  · change alphaAnswer (rest chosen).2 = definingAlphaAnswer trace tape
    rw [definingAlphaAnswer_eq_of_alphaSlot_eq trace tape
      (trace.alphaSlot tape) rfl]
    have hrest : (rest chosen).2 = tape (trace.alphaSlot tape) := by
      simp only [rest]
      rw [← hchosen]
      simp
    rw [hrest]

/-- The Case-B response strategy used after predictable deletion is exactly
the adversary's response on the original tape.  Unlike a caller hypothesis,
this follows from the response payload in the charged H₂ query and the fact
that both deleted answers occur at or after that query. -/
theorem canonicalCaseBResponseFromData_eq
    {AlphaKey Alpha Subset Response Output : Type*} {N : ℕ}
    [DecidableEq AlphaKey] [DecidableEq Response]
    [Fintype Alpha] [Fintype Subset]
    (adversary : Merkle.RandomOracle.Tree
      (Query AlphaKey (AlphaKey × Response)) (Answer Alpha Subset) Output N)
    (dflt : Answer Alpha Subset)
    (keyOf : Output → AlphaKey) (responseOf : Output → Response)
    (fallback : AlphaKey × Response)
    (win bindBreak : (Fin (N + 2) → Answer Alpha Subset) → Prop)
    (i : Fin (N + 2)) (tape : Fin (N + 2) → Answer Alpha Subset)
    (hcase : (lazyFirstOccurrenceTrace N adversary dflt keyOf
      (fun output ↦ (keyOf output, responseOf output))).caseB
        win bindBreak i tape) :
    let rest := fun k ↦ (Equiv.punitProd.{0} (Answer Alpha Subset)).symm
      (tape (i.succAbove k))
    let chosen := lazyPrefixSelector adversary dflt i
      (Equiv.punitProd.{0} (Answer Alpha Subset)).symm
      (canonicalAlphaTargetFromPrefix fallback.1) (tape i) rest
    let data := ((fun k ↦ (rest k).1),
      fun k ↦ (rest (chosen.succAbove k)).2)
    canonicalCaseBResponseFromData adversary dflt fallback i data =
      responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1 := by
  dsimp only
  let rest := fun k ↦ (Equiv.punitProd.{0} (Answer Alpha Subset)).symm
    (tape (i.succAbove k))
  let target := lazyPrefixTargetSlot adversary dflt i
    (Equiv.punitProd.{0} (Answer Alpha Subset)).symm
    (canonicalAlphaTargetFromPrefix fallback.1) (tape i) rest
  let chosen := lazyPrefixSelector adversary dflt i
    (Equiv.punitProd.{0} (Answer Alpha Subset)).symm
    (canonicalAlphaTargetFromPrefix fallback.1) (tape i) rest
  let data := ((fun k ↦ (rest k).1),
    fun k ↦ (rest (chosen.succAbove k)).2)
  have hselector := canonicalCaseB_selector adversary dflt keyOf responseOf
    fallback.1 win bindBreak i tape hcase
  have hlater : i < target := hselector.1
  have htargetNe : target ≠ i := ne_of_gt hlater
  have hchosen : i.succAbove chosen = target := by
    exact succAbove_eraseFixedSlotIndex i target htargetNe
  have hlaterChosen : i < i.succAbove chosen := by
    rw [hchosen]
    exact hlater
  have hagree : ∀ j, j.val < i.val →
      prefixTapeFromErasedData dflt data j = tape j := by
    intro j hj
    exact prefixTapeFromErasedData_eq_before dflt i chosen tape hlaterChosen
      j (by exact_mod_cast hj)
  calc
    canonicalCaseBResponseFromData adversary dflt fallback i data =
        canonicalResponseAtSlot adversary dflt fallback i tape := by
      exact canonicalResponseAtSlot_congr adversary dflt fallback i
        (prefixTapeFromErasedData dflt data) tape hagree
    _ = responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1 :=
      canonicalResponseAtSlot_eq_of_caseB adversary dflt keyOf responseOf
        fallback win bindBreak i tape hcase

/-- Exact response-rigid Case-A count.

The final response is allowed to depend on the entire lazy execution.  It is
included in the independent triple `(fixed answer, response, later answer)`;
after that response is fixed, its defining H₂ query is predictable.  A
strategy-uniform triple density therefore lifts to the full tape with no
union over possible later slots. -/
theorem lazy_response_target_tape_ratio_le
    {Q D R Output : Type*} [DecidableEq Q]
    [Fintype D] [DecidableEq D] [Nonempty D]
    [Fintype R] [DecidableEq R] [Nonempty R]
    {N : ℕ}
    (adversary : Merkle.RandomOracle.Tree Q D Output N) (dflt : D)
    (fixedSlot : Fin (N + 2)) (responseOf : Output → R)
    (precursorOf targetOf : R → Q)
    (success : ((Fin (N + 1) → PUnit.{1}) × (Fin N → D)) →
      (D × R) → D → Prop)
    [∀ data, DecidableRel (success data)]
    (epsilon : ℚ)
    (htriples : ∀ data, ((Finset.univ.filter fun value : (D × R) × D ↦
      success data value.1 value.2).card : ℚ) /
        (Fintype.card D * Fintype.card D) ≤ epsilon)
    (event : (Fin (N + 2) → D) → Prop) [DecidablePred event]
    (hcover : ∀ tape, event tape →
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let fixedResponse := (tape fixedSlot, responseOf output)
      let rest := fun k ↦
        (Equiv.punitProd.{0} D).symm (tape (fixedSlot.succAbove k))
      let selected := lazyResponseSelector adversary dflt fixedSlot
        precursorOf targetOf fixedResponse rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (selected.succAbove k)).2)
      lazyResponseLater adversary dflt fixedSlot precursorOf targetOf
          (fixedResponse, rest) ∧
        success data fixedResponse (rest selected).2) :
    ((Finset.univ.filter event).card : ℚ) /
        Fintype.card (Fin (N + 2) → D) ≤ epsilon := by
  classical
  let Seq := Fin (N + 1) → PUnit.{1} × D
  let tapeOf : (D × R) × Seq → Fin (N + 2) → D := fun input ↦
    reinsertFixedTape fixedSlot (Equiv.punitProd.{0} D).symm input.1.1 input.2
  let admissible : (D × R) × Seq → Prop := fun input ↦
    lazyResponseLater adversary dflt fixedSlot precursorOf targetOf input ∧
      input.1.2 = responseOf
        (Merkle.RandomOracle.lazyRun (tapeOf input) dflt adversary []).1
  let encode : (Fin (N + 2) → D) → (D × R) × Seq := fun tape ↦
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    ((tape fixedSlot, responseOf output), fun k ↦
      (Equiv.punitProd.{0} D).symm (tape (fixedSlot.succAbove k)))
  have hencode : Function.Injective encode := by
    intro first second heq
    funext k
    by_cases hk : k = fixedSlot
    · subst k
      exact congrArg (fun value ↦ value.1.1) heq
    · obtain ⟨l, hl⟩ := Fin.exists_succAbove_eq hk
      have hrest := congrFun (congrArg Prod.snd heq) l
      exact (Equiv.punitProd.{0} D).symm.injective (by
        simpa [encode, hl] using hrest)
  let good : Finset ((D × R) × Seq) := Finset.univ.filter fun input ↦
    admissible input ∧
    let selected := lazyResponseSelector adversary dflt fixedSlot
      precursorOf targetOf input.1 input.2
    let data := ((fun k ↦ (input.2 k).1),
      fun k ↦ (input.2 (selected.succAbove k)).2)
    success data input.1 (input.2 selected).2
  have hevent : (Finset.univ.filter event).card ≤ good.card := by
    apply Finset.card_le_card_of_injOn encode
    · intro tape htape
      apply Finset.mem_filter.mpr
      refine ⟨Finset.mem_univ _, ?_⟩
      have hc := hcover tape (Finset.mem_filter.mp htape).2
      have htapeOf : tapeOf (encode tape) = tape := by
        funext k
        by_cases hk : k = fixedSlot
        · subst k
          simp [tapeOf, encode, reinsertFixedTape]
        · obtain ⟨l, hl⟩ := Fin.exists_succAbove_eq hk
          rw [← hl]
          simp [tapeOf, encode, reinsertFixedTape]
      have hadmissible : admissible (encode tape) := by
        constructor
        · simpa [encode] using hc.1
        · change responseOf
              (Merkle.RandomOracle.lazyRun tape dflt adversary []).1 =
            responseOf
              (Merkle.RandomOracle.lazyRun (tapeOf (encode tape)) dflt
                adversary []).1
          rw [htapeOf]
      have hsuccess :
          let selected := lazyResponseSelector adversary dflt fixedSlot
            precursorOf targetOf (encode tape).1 (encode tape).2
          let data := ((fun k ↦ ((encode tape).2 k).1),
            fun k ↦ ((encode tape).2 (selected.succAbove k)).2)
          success data (encode tape).1 ((encode tape).2 selected).2 := by
        simpa [encode] using hc.2
      exact And.intro hadmissible hsuccess
    · intro first _ second _ heq
      exact hencode heq
  have hD : (0 : ℚ) < Fintype.card D := by
    exact_mod_cast Fintype.card_pos
  have hR : (0 : ℚ) < Fintype.card R := by
    exact_mod_cast Fintype.card_pos
  have hpair : ∀ data, ((Finset.univ.filter fun value : (D × R) × D ↦
      success data value.1 value.2).card : ℚ) /
        (Fintype.card (D × R) * Fintype.card D) ≤
          epsilon / Fintype.card R := by
    intro data
    rw [div_le_div_iff₀ (mul_pos (by
      simpa only [Fintype.card_prod, Nat.cast_mul] using mul_pos hD hR) hD) hR]
    have h := (div_le_iff₀ (mul_pos hD hD)).mp (htriples data)
    simp only [Fintype.card_prod, Nat.cast_mul]
    calc
      ((Finset.univ.filter fun value : (D × R) × D ↦
          success data value.1 value.2).card : ℚ) * Fintype.card R
        ≤ (epsilon * (Fintype.card D * Fintype.card D)) *
            Fintype.card R := mul_le_mul_of_nonneg_right h hR.le
      _ = epsilon *
          (Fintype.card D * Fintype.card R * Fintype.card D) := by ring
  have hgood : (good.card : ℚ) /
      Fintype.card ((D × R) × Seq) ≤ epsilon / Fintype.card R := by
    simpa [good, Seq, admissible] using
      Bcs.predictable_stopping_dependent_on_ratio_le
        (lazyResponseSelector adversary dflt fixedSlot precursorOf targetOf)
        admissible
        (by
          intro fixedResponse left right hleft hright hagree
          exact lazyResponseSelector_predictableOn adversary dflt fixedSlot
            precursorOf targetOf fixedResponse left right hleft.1 hright.1 hagree)
        success (epsilon / Fintype.card R) hpair
  have hcard : (Fintype.card ((D × R) × Seq) : ℚ) =
      Fintype.card R * Fintype.card (Fin (N + 2) → D) := by
    simp only [Seq, Fintype.card_prod, Fintype.card_fun, Fintype.card_fin,
      Fintype.card_punit, one_mul, Nat.cast_mul, Nat.cast_pow]
    rw [pow_succ']
    ring
  have hTape : (0 : ℚ) < Fintype.card (Fin (N + 2) → D) := by
    exact_mod_cast Fintype.card_pos
  rw [div_le_iff₀ hTape]
  have hgood' : (good.card : ℚ) ≤
      epsilon * Fintype.card (Fin (N + 2) → D) := by
    rw [hcard, div_le_div_iff₀ (mul_pos hR hTape) hR] at hgood
    have hscaled : (Fintype.card R : ℚ) * good.card ≤
        Fintype.card R *
          (epsilon * Fintype.card (Fin (N + 2) → D)) := by
      calc
        (Fintype.card R : ℚ) * good.card =
            (good.card : ℚ) * Fintype.card R := by ring
        _ ≤ epsilon *
            (Fintype.card R * Fintype.card (Fin (N + 2) → D)) := hgood
        _ = (Fintype.card R : ℚ) *
            (epsilon * Fintype.card (Fin (N + 2) → D)) := by ring
    have hRne : (Fintype.card R : ℚ) ≠ 0 := ne_of_gt hR
    calc
      (good.card : ℚ) =
          ((Fintype.card R : ℚ) * good.card) / Fintype.card R := by
            field_simp [hRne]
      _ ≤ (Fintype.card R *
          (epsilon * Fintype.card (Fin (N + 2) → D))) /
            Fintype.card R :=
        div_le_div_of_nonneg_right hscaled hR.le
      _ = epsilon * Fintype.card (Fin (N + 2) → D) := by
        field_simp [hRne]
  have heventQ : ((Finset.univ.filter event).card : ℚ) ≤ good.card := by
    exact_mod_cast hevent
  exact heventQ.trans hgood'

end Bcs.TypedFiatShamir
