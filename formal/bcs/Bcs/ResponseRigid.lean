import Bcs.Counting
import LigeroFamily.Protocol.Finite
import Sumcheck.Counting
import Mathlib.Data.Rat.Cast.Order

/-!
# Response-rigid Fiat--Shamir attribution

This is the finite-ROM counting core for the response-rigid compiler.  It
separates the two possible orders of the defining queries:

* `caseA`: the response/query-set hash is fresh after the batching challenge;
* `caseB`: the query-set hash is fresh first and the batching challenge is
  queried later.

The second case must not be bounded by conditioning on the later query's
occurrence: an adversary may decide to make that query after seeing the query
set.  `predictable_selection_card_le` is the repaired argument.  The decision
to continue may depend arbitrarily on the early value and on intervening
randomness `Z`, but not on the later fresh `alpha`; dropping that decision
indicator leaves an ordinary count over independent `(Y, alpha)` pairs.

`RigidAttribution` packages the operational reduction from an adversary run to
the binding, case-A, and case-B events.  Case A itself has two natural charges.
A canonical floor-sized part of the query-success event is charged to the
fresh `H₂` slot.  The remaining high-agreement excess, after that baseline has
been removed, is charged to the earlier fresh `H₁` slot and controlled by
listed responses.  This split is needed both to avoid double counting the
floor and to account for commitment grinding.  Case B is
charged to the earlier `H₂` slot and its budget is a global predictable-slot
count, not a pointwise conditional count at the later `H₁` slot.  These two
choices prevent, respectively, commitment-selection and continuation-selection
biases.

`ChainedTrace` is the same accounting for a compiler that **chains**: when the
query-set hash reads the batching challenge, `H₂(x, root, alpha, response)`, the
second query cannot precede the first, case B is empty, and the bound loses its
`caseBAlphaLastBudget` term.  Chaining also subsumes domain separation for this
argument -- `ChainedTrace.separated` is a theorem rather than a field.
-/

set_option autoImplicit false
set_option relaxedAutoImplicit false

namespace Bcs

open Finset
open scoped Classical

/-! ## The predictable alpha-last lemma -/

/-- A continuation may inspect the early query-set answer `Y` and arbitrary
intervening randomness `Z` before deciding whether to request a fresh
challenge `A`.  Its successful triples are no more numerous than all
successful `(Y,A)` pairs times `|Z|`.

There is deliberately no hypothesis on `occurs` beyond its type: it may be an
arbitrary adaptive selection rule in `Y` and `Z`.  Its inability to read `A`
is enforced by the argument order.
-/
theorem predictable_selection_card_le
    {Y Z A : Type*} [Fintype Y] [Fintype Z] [Fintype A]
    [DecidableEq Y] [DecidableEq Z] [DecidableEq A]
    (occurs : Y → Z → Prop) (success : Y → A → Prop) (pairBudget : ℕ)
    (hpairs : (Finset.filter (fun p : Y × A ↦ success p.1 p.2) Finset.univ).card ≤
      pairBudget) :
    (Finset.filter (fun p : (Y × Z) × A ↦
      occurs p.1.1 p.1.2 ∧ success p.1.1 p.2) Finset.univ).card ≤
        Fintype.card Z * pairBudget := by
  classical
  rw [card_filter_prod_fst]
  calc
    ∑ yz : Y × Z,
        (Finset.filter (fun a : A ↦ occurs yz.1 yz.2 ∧ success yz.1 a)
          Finset.univ).card
        ≤ ∑ yz : Y × Z,
            (Finset.filter (fun a : A ↦ success yz.1 a) Finset.univ).card := by
          apply Finset.sum_le_sum
          intro yz _
          apply Finset.card_le_card
          intro a ha
          simp only [Finset.mem_filter, Finset.mem_univ, true_and] at ha ⊢
          exact ha.2
    _ = Fintype.card Z * ∑ y : Y,
          (Finset.filter (fun a : A ↦ success y a) Finset.univ).card := by
        simp only [Fintype.sum_prod_type]
        rw [Finset.mul_sum]
        apply Finset.sum_congr rfl
        intro y _
        simp [Finset.sum_const]
    _ = Fintype.card Z *
          (Finset.filter (fun p : Y × A ↦ success p.1 p.2) Finset.univ).card := by
        rw [Sumcheck.card_prod_filter]
    _ ≤ Fintype.card Z * pairBudget := Nat.mul_le_mul_left _ hpairs

/-- Rational form of `predictable_selection_card_le`.  The denominator is
the full product space `Y × Z × A`; the adaptive `occurs` factor cancels,
leaving the density of successful independent `(Y,A)` pairs. -/
theorem predictable_selection_ratio_le
    {Y Z A : Type*} [Fintype Y] [Fintype Z] [Fintype A]
    [DecidableEq Y] [DecidableEq Z] [DecidableEq A]
    [Nonempty Y] [Nonempty Z] [Nonempty A]
    (occurs : Y → Z → Prop) (success : Y → A → Prop) (pairBudget : ℕ)
    (hpairs : (Finset.filter (fun p : Y × A ↦ success p.1 p.2) Finset.univ).card ≤
      pairBudget) :
    ((Finset.filter (fun p : (Y × Z) × A ↦
        occurs p.1.1 p.1.2 ∧ success p.1.1 p.2) Finset.univ).card : ℚ) /
          Fintype.card ((Y × Z) × A) ≤
      (pairBudget : ℚ) / (Fintype.card Y * Fintype.card A) := by
  have hcard := predictable_selection_card_le occurs success pairBudget hpairs
  have hY : (0 : ℚ) < Fintype.card Y := by exact_mod_cast Fintype.card_pos
  have hZ : (0 : ℚ) < Fintype.card Z := by exact_mod_cast Fintype.card_pos
  have hA : (0 : ℚ) < Fintype.card A := by exact_mod_cast Fintype.card_pos
  rw [Fintype.card_prod, Fintype.card_prod]
  simp only [Nat.cast_mul]
  rw [div_le_div_iff₀ (mul_pos (mul_pos hY hZ) hA) (mul_pos hY hA)]
  have hcast :
      ((Finset.filter (fun p : (Y × Z) × A ↦
          occurs p.1.1 p.1.2 ∧ success p.1.1 p.2) Finset.univ).card : ℚ) ≤
        Fintype.card Z * pairBudget := by exact_mod_cast hcard
  calc
    ((Finset.filter (fun p : (Y × Z) × A ↦
        occurs p.1.1 p.1.2 ∧ success p.1.1 p.2) Finset.univ).card : ℚ) *
          (Fintype.card Y * Fintype.card A)
      ≤ (Fintype.card Z * pairBudget : ℚ) *
          (Fintype.card Y * Fintype.card A) :=
        mul_le_mul_of_nonneg_right hcast (le_of_lt (mul_pos hY hA))
    _ = (pairBudget : ℚ) *
          (Fintype.card Y * Fintype.card Z * Fintype.card A) := by ring

/-! ## A predictable stopping coordinate -/

/-- A selected sequence coordinate is predictable when its index is fixed by
the values strictly before it.  In particular its own answer and all later
answers cannot influence which coordinate is selected. -/
def IsPredictableSelector
    {Y Z A : Type*} {N : ℕ}
    (select : Y → (Fin (N + 1) → Z × A) → Fin (N + 1)) : Prop :=
  ∀ y xs ys,
    (∀ k, k < select y xs → xs k = ys k) → select y ys = select y xs

/-- Optional-stopping count for a single predictable fresh answer.  Even
though `select` may inspect `Y`, all noise coordinates, and earlier `A`
answers, the selected `A` is still fresh.  Hence a global `pairBudget` on
successful `(Y,A)` pairs is paid once, with no factor `N+1`.

The proof deletes the adaptively selected `A` coordinate.  Predictability
makes the deletion injective: if two deletions selected different indices,
their prefixes up to the earlier index would agree, forcing the same index. -/
theorem predictable_stopping_card_le
    {Y Z A : Type*} [Fintype Y] [Fintype Z] [Fintype A]
    [DecidableEq Y] [DecidableEq Z] [DecidableEq A]
    {N : ℕ}
    (select : Y → (Fin (N + 1) → Z × A) → Fin (N + 1))
    (hselect : IsPredictableSelector select)
    (success : Y → A → Prop) [DecidableRel success]
    (pairBudget : ℕ)
    (hpairs : (Finset.univ.filter fun pair : Y × A =>
      success pair.1 pair.2).card ≤ pairBudget) :
    (Finset.univ.filter fun input : Y × (Fin (N + 1) → Z × A) =>
      success input.1 (input.2 (select input.1 input.2)).2).card ≤
      pairBudget * Fintype.card Z ^ (N + 1) * Fintype.card A ^ N := by
  classical
  let Seq := Fin (N + 1) → Z × A
  let Data := (Fin (N + 1) → Z) × (Fin N → A)
  let pairOf : Y × Seq → Y × A := fun input =>
    (input.1, (input.2 (select input.1 input.2)).2)
  let dataOf : Y × Seq → Data := fun input =>
    ((fun k => (input.2 k).1),
      fun k => (input.2 ((select input.1 input.2).succAbove k)).2)
  have hencode : Function.Injective (fun input : Y × Seq =>
      (pairOf input, dataOf input)) := by
    rintro ⟨y₁, xs⟩ ⟨y₂, ys⟩ heq
    have hy : y₁ = y₂ := congrArg (fun value => value.1.1) heq
    subst y₂
    let jx := select y₁ xs
    let jy := select y₁ ys
    have hz : ∀ k, (xs k).1 = (ys k).1 := by
      intro k
      exact congrFun (congrArg (fun value => value.2.1) heq) k
    have herased : ∀ k, (xs (jx.succAbove k)).2 =
        (ys (jy.succAbove k)).2 := by
      intro k
      exact congrFun (congrArg (fun value => value.2.2) heq) k
    have hselected : (xs jx).2 = (ys jy).2 :=
      congrArg (fun value => value.1.2) heq
    have hprefix_xy (hxy : jx < jy) :
        ∀ k, k < jx → xs k = ys k := by
      intro k hk
      apply Prod.ext (hz k)
      have hklast : k ≠ Fin.last N := by
        exact ne_of_lt (hk.trans_le (Fin.le_last jx))
      let l : Fin N := k.castPred hklast
      have hx : jx.succAbove l = k := by
        exact Fin.succAbove_castPred_of_lt jx k hk
      have hy' : jy.succAbove l = k := by
        exact Fin.succAbove_castPred_of_lt jy k (hk.trans hxy)
      simpa [hx, hy'] using herased l
    have hj : jx = jy := by
      rcases lt_trichotomy jx jy with hxy | hEq | hyx
      · have hs := hselect y₁ xs ys (hprefix_xy hxy)
        exact hs.symm
      · exact hEq
      · have hprefix_yx : ∀ k, k < jy → ys k = xs k := by
          intro k hk
          apply Prod.ext (hz k).symm
          have hklast : k ≠ Fin.last N :=
            ne_of_lt (hk.trans_le (Fin.le_last jy))
          let l : Fin N := k.castPred hklast
          have hy' : jy.succAbove l = k := by
            exact Fin.succAbove_castPred_of_lt jy k hk
          have hx : jx.succAbove l = k := by
            exact Fin.succAbove_castPred_of_lt jx k (hk.trans hyx)
          simpa [hx, hy'] using (herased l).symm
        have hs := hselect y₁ ys xs hprefix_yx
        exact hs
    apply Prod.ext
    · rfl
    funext k
    apply Prod.ext (hz k)
    by_cases hk : k = jx
    · subst k
      simpa [hj] using hselected
    · obtain ⟨l, hl⟩ := Fin.exists_succAbove_eq hk
      have := herased l
      have hl' : jy.succAbove l = k := by rw [← hj]; exact hl
      rw [hl, hl'] at this
      exact this
  let goodPairs : Finset (Y × A) := Finset.univ.filter fun pair =>
    success pair.1 pair.2
  calc
    (Finset.univ.filter fun input : Y × Seq =>
        success input.1 (input.2 (select input.1 input.2)).2).card
      ≤ (goodPairs ×ˢ (Finset.univ : Finset Data)).card := by
        apply Finset.card_le_card_of_injOn
          (fun input => (pairOf input, dataOf input))
        · intro input hinput
          exact Finset.mem_product.mpr
            ⟨Finset.mem_filter.mpr ⟨Finset.mem_univ _,
              (Finset.mem_filter.mp hinput).2⟩, Finset.mem_univ _⟩
        · intro first _ second _ heq
          exact hencode heq
    _ = goodPairs.card * Fintype.card Data := by simp
    _ ≤ pairBudget * Fintype.card Data :=
      Nat.mul_le_mul_right _ (by simpa [goodPairs] using hpairs)
    _ = pairBudget * Fintype.card Z ^ (N + 1) * Fintype.card A ^ N := by
      simp [Data, mul_assoc]

/-- Strategy-dependent optional stopping.  After the predictable coordinate
is deleted, the success relation may depend on *all* retained data: every
`Z` coordinate and every unselected `A` coordinate.  A uniform pair bound in
each such fibre still costs `pairBudget` only once.

This is the form needed by Fiat--Shamir.  Fixing the rest of the oracle tape
fixes an arbitrary response strategy; the fresh selected answer is the only
coordinate that the strategy cannot inspect. -/
theorem predictable_stopping_dependent_card_le
    {Y Z A : Type*} [Fintype Y] [Fintype Z] [Fintype A]
    [DecidableEq Y] [DecidableEq Z] [DecidableEq A]
    {N : ℕ}
    (select : Y → (Fin (N + 1) → Z × A) → Fin (N + 1))
    (hselect : IsPredictableSelector select)
    (success : ((Fin (N + 1) → Z) × (Fin N → A)) → Y → A → Prop)
    [∀ data, DecidableRel (success data)]
    (pairBudget : ℕ)
    (hpairs : ∀ data, (Finset.univ.filter fun pair : Y × A ↦
      success data pair.1 pair.2).card ≤ pairBudget) :
    (Finset.univ.filter fun input : Y × (Fin (N + 1) → Z × A) ↦
      let selected := select input.1 input.2
      let data := ((fun k ↦ (input.2 k).1),
        fun k ↦ (input.2 (selected.succAbove k)).2)
      success data input.1 (input.2 selected).2).card ≤
      pairBudget * Fintype.card Z ^ (N + 1) * Fintype.card A ^ N := by
  classical
  let Seq := Fin (N + 1) → Z × A
  let Data := (Fin (N + 1) → Z) × (Fin N → A)
  let pairOf : Y × Seq → Y × A := fun input ↦
    (input.1, (input.2 (select input.1 input.2)).2)
  let dataOf : Y × Seq → Data := fun input ↦
    ((fun k ↦ (input.2 k).1),
      fun k ↦ (input.2 ((select input.1 input.2).succAbove k)).2)
  have hencode : Function.Injective (fun input : Y × Seq ↦
      (dataOf input, pairOf input)) := by
    rintro ⟨y₁, xs⟩ ⟨y₂, ys⟩ heq
    have hy : y₁ = y₂ := congrArg (fun value ↦ value.2.1) heq
    subst y₂
    let jx := select y₁ xs
    let jy := select y₁ ys
    have hz : ∀ k, (xs k).1 = (ys k).1 := by
      intro k
      exact congrFun (congrArg (fun value ↦ value.1.1) heq) k
    have herased : ∀ k, (xs (jx.succAbove k)).2 =
        (ys (jy.succAbove k)).2 := by
      intro k
      exact congrFun (congrArg (fun value ↦ value.1.2) heq) k
    have hselected : (xs jx).2 = (ys jy).2 :=
      congrArg (fun value ↦ value.2.2) heq
    have hprefix_xy (hxy : jx < jy) :
        ∀ k, k < jx → xs k = ys k := by
      intro k hk
      apply Prod.ext (hz k)
      have hklast : k ≠ Fin.last N := by
        exact ne_of_lt (hk.trans_le (Fin.le_last jx))
      let l : Fin N := k.castPred hklast
      have hx : jx.succAbove l = k := by
        exact Fin.succAbove_castPred_of_lt jx k hk
      have hy' : jy.succAbove l = k := by
        exact Fin.succAbove_castPred_of_lt jy k (hk.trans hxy)
      simpa [hx, hy'] using herased l
    have hj : jx = jy := by
      rcases lt_trichotomy jx jy with hxy | hEq | hyx
      · exact (hselect y₁ xs ys (hprefix_xy hxy)).symm
      · exact hEq
      · have hprefix_yx : ∀ k, k < jy → ys k = xs k := by
          intro k hk
          apply Prod.ext (hz k).symm
          have hklast : k ≠ Fin.last N := by
            exact ne_of_lt (hk.trans_le (Fin.le_last jy))
          let l : Fin N := k.castPred hklast
          have hy' : jy.succAbove l = k := by
            exact Fin.succAbove_castPred_of_lt jy k hk
          have hx : jx.succAbove l = k := by
            exact Fin.succAbove_castPred_of_lt jx k (hk.trans hyx)
          simpa [hx, hy'] using (herased l).symm
        exact hselect y₁ ys xs hprefix_yx
    apply Prod.ext
    · rfl
    funext k
    apply Prod.ext (hz k)
    by_cases hk : k = jx
    · subst k
      simpa [hj] using hselected
    · obtain ⟨l, hl⟩ := Fin.exists_succAbove_eq hk
      have he := herased l
      have hl' : jy.succAbove l = k := by rw [← hj]; exact hl
      rw [hl, hl'] at he
      exact he
  let good : Finset (Data × (Y × A)) := Finset.univ.filter fun value ↦
    success value.1 value.2.1 value.2.2
  have hgood : good.card ≤ Fintype.card Data * pairBudget := by
    rw [show good.card = ∑ data : Data,
        (Finset.univ.filter fun pair : Y × A ↦
          success data pair.1 pair.2).card by
      dsimp [good]
      rw [card_filter_prod_fst]]
    calc
      ∑ data : Data, (Finset.univ.filter fun pair : Y × A ↦
          success data pair.1 pair.2).card
        ≤ ∑ _data : Data, pairBudget :=
          Finset.sum_le_sum fun data _ ↦ hpairs data
      _ = Fintype.card Data * pairBudget := by simp
  calc
    (Finset.univ.filter fun input : Y × Seq ↦
        success (dataOf input) input.1
          (input.2 (select input.1 input.2)).2).card
      ≤ good.card := by
        apply Finset.card_le_card_of_injOn fun input ↦
          (dataOf input, pairOf input)
        · intro input hinput
          exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
            (Finset.mem_filter.mp hinput).2⟩
        · intro first _ second _ heq
          exact hencode heq
    _ ≤ Fintype.card Data * pairBudget := hgood
    _ = pairBudget * Fintype.card Z ^ (N + 1) * Fintype.card A ^ N := by
      simp [Data]
      ring

/-- Predictability restricted to an admissible order branch.  This is the
correct operational notion for first-occurrence arguments: the H₁-after-H₂
selector need only be a stopping coordinate on Case B, while the reverse
selector is used only on Case A. -/
def IsPredictableSelectorOn
    {Y Z A : Type*} {N : ℕ}
    (admissible : Y × (Fin (N + 1) → Z × A) → Prop)
    (select : Y → (Fin (N + 1) → Z × A) → Fin (N + 1)) : Prop :=
  ∀ y xs ys, admissible (y, xs) → admissible (y, ys) →
    (∀ k, k < select y xs → xs k = ys k) → select y ys = select y xs

/-- Fibre-uniform optional stopping on an admissible order branch.  The proof
is the same deletion injection as the global theorem, but injectivity is
needed only between admissible successful inputs. -/
theorem predictable_stopping_dependent_on_card_le
    {Y Z A : Type*} [Fintype Y] [Fintype Z] [Fintype A]
    [DecidableEq Y] [DecidableEq Z] [DecidableEq A]
    {N : ℕ}
    (select : Y → (Fin (N + 1) → Z × A) → Fin (N + 1))
    (admissible : Y × (Fin (N + 1) → Z × A) → Prop)
    [DecidablePred admissible]
    (hselect : IsPredictableSelectorOn admissible select)
    (success : ((Fin (N + 1) → Z) × (Fin N → A)) → Y → A → Prop)
    [∀ data, DecidableRel (success data)]
    (pairBudget : ℕ)
    (hpairs : ∀ data, (Finset.univ.filter fun pair : Y × A ↦
      success data pair.1 pair.2).card ≤ pairBudget) :
    (Finset.univ.filter fun input : Y × (Fin (N + 1) → Z × A) ↦
      admissible input ∧
      let selected := select input.1 input.2
      let data := ((fun k ↦ (input.2 k).1),
        fun k ↦ (input.2 (selected.succAbove k)).2)
      success data input.1 (input.2 selected).2).card ≤
      pairBudget * Fintype.card Z ^ (N + 1) * Fintype.card A ^ N := by
  classical
  let Seq := Fin (N + 1) → Z × A
  let Data := (Fin (N + 1) → Z) × (Fin N → A)
  let pairOf : Y × Seq → Y × A := fun input ↦
    (input.1, (input.2 (select input.1 input.2)).2)
  let dataOf : Y × Seq → Data := fun input ↦
    ((fun k ↦ (input.2 k).1),
      fun k ↦ (input.2 ((select input.1 input.2).succAbove k)).2)
  let domain : Finset (Y × Seq) := Finset.univ.filter fun input ↦
    admissible input ∧ success (dataOf input) input.1
      (input.2 (select input.1 input.2)).2
  have hencode : Set.InjOn (fun input : Y × Seq ↦
      (dataOf input, pairOf input)) domain := by
    intro first hfirst second hsecond heq
    rcases first with ⟨y₁, xs⟩
    rcases second with ⟨y₂, ys⟩
    have hadm₁ : admissible (y₁, xs) :=
      (Finset.mem_filter.mp hfirst).2.1
    have hadm₂ : admissible (y₂, ys) :=
      (Finset.mem_filter.mp hsecond).2.1
    have hy : y₁ = y₂ := congrArg (fun value ↦ value.2.1) heq
    subst y₂
    let jx := select y₁ xs
    let jy := select y₁ ys
    have hz : ∀ k, (xs k).1 = (ys k).1 := by
      intro k
      exact congrFun (congrArg (fun value ↦ value.1.1) heq) k
    have herased : ∀ k, (xs (jx.succAbove k)).2 =
        (ys (jy.succAbove k)).2 := by
      intro k
      exact congrFun (congrArg (fun value ↦ value.1.2) heq) k
    have hselected : (xs jx).2 = (ys jy).2 :=
      congrArg (fun value ↦ value.2.2) heq
    have hprefix_xy (hxy : jx < jy) :
        ∀ k, k < jx → xs k = ys k := by
      intro k hk
      apply Prod.ext (hz k)
      have hklast : k ≠ Fin.last N := by
        exact ne_of_lt (hk.trans_le (Fin.le_last jx))
      let l : Fin N := k.castPred hklast
      have hx : jx.succAbove l = k := by
        exact Fin.succAbove_castPred_of_lt jx k hk
      have hy' : jy.succAbove l = k := by
        exact Fin.succAbove_castPred_of_lt jy k (hk.trans hxy)
      simpa [hx, hy'] using herased l
    have hj : jx = jy := by
      rcases lt_trichotomy jx jy with hxy | hEq | hyx
      · exact (hselect y₁ xs ys hadm₁ hadm₂ (hprefix_xy hxy)).symm
      · exact hEq
      · have hprefix_yx : ∀ k, k < jy → ys k = xs k := by
          intro k hk
          apply Prod.ext (hz k).symm
          have hklast : k ≠ Fin.last N := by
            exact ne_of_lt (hk.trans_le (Fin.le_last jy))
          let l : Fin N := k.castPred hklast
          have hy' : jy.succAbove l = k := by
            exact Fin.succAbove_castPred_of_lt jy k hk
          have hx : jx.succAbove l = k := by
            exact Fin.succAbove_castPred_of_lt jx k (hk.trans hyx)
          simpa [hx, hy'] using (herased l).symm
        exact hselect y₁ ys xs hadm₂ hadm₁ hprefix_yx
    apply Prod.ext
    · rfl
    funext k
    apply Prod.ext (hz k)
    by_cases hk : k = jx
    · subst k
      simpa [hj] using hselected
    · obtain ⟨l, hl⟩ := Fin.exists_succAbove_eq hk
      have he := herased l
      have hl' : jy.succAbove l = k := by rw [← hj]; exact hl
      rw [hl, hl'] at he
      exact he
  let good : Finset (Data × (Y × A)) := Finset.univ.filter fun value ↦
    success value.1 value.2.1 value.2.2
  have hgood : good.card ≤ Fintype.card Data * pairBudget := by
    rw [show good.card = ∑ data : Data,
        (Finset.univ.filter fun pair : Y × A ↦
          success data pair.1 pair.2).card by
      dsimp [good]
      rw [card_filter_prod_fst]]
    calc
      ∑ data : Data, (Finset.univ.filter fun pair : Y × A ↦
          success data pair.1 pair.2).card
        ≤ ∑ _data : Data, pairBudget :=
          Finset.sum_le_sum fun data _ ↦ hpairs data
      _ = Fintype.card Data * pairBudget := by simp
  calc
    domain.card ≤ good.card := by
      apply Finset.card_le_card_of_injOn
        (fun input ↦ (dataOf input, pairOf input))
      · intro input hinput
        exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
          (Finset.mem_filter.mp hinput).2.2⟩
      · exact hencode
    _ ≤ Fintype.card Data * pairBudget := hgood
    _ = pairBudget * Fintype.card Z ^ (N + 1) * Fintype.card A ^ N := by
      simp [Data]
      ring

/-- Rational optional-stopping theorem with a strategy-uniform pair density.

This is the exact-density form of `predictable_stopping_dependent_on_card_le`:
it does not round a rational pair bound to an integer cardinality budget. -/
theorem predictable_stopping_dependent_on_ratio_le
    {Y Z A : Type*} [Fintype Y] [Fintype Z] [Fintype A]
    [DecidableEq Y] [DecidableEq Z] [DecidableEq A]
    [Nonempty Y] [Nonempty Z] [Nonempty A]
    {N : ℕ}
    (select : Y → (Fin (N + 1) → Z × A) → Fin (N + 1))
    (admissible : Y × (Fin (N + 1) → Z × A) → Prop)
    [DecidablePred admissible]
    (hselect : IsPredictableSelectorOn admissible select)
    (success : ((Fin (N + 1) → Z) × (Fin N → A)) → Y → A → Prop)
    [∀ data, DecidableRel (success data)]
    (epsilon : ℚ)
    (hpairs : ∀ data, ((Finset.univ.filter fun pair : Y × A ↦
      success data pair.1 pair.2).card : ℚ) /
        (Fintype.card Y * Fintype.card A) ≤ epsilon) :
    ((Finset.univ.filter fun input : Y × (Fin (N + 1) → Z × A) ↦
      admissible input ∧
      let selected := select input.1 input.2
      let data := ((fun k ↦ (input.2 k).1),
        fun k ↦ (input.2 (selected.succAbove k)).2)
      success data input.1 (input.2 selected).2).card : ℚ) /
        Fintype.card (Y × (Fin (N + 1) → Z × A)) ≤ epsilon := by
  classical
  let Seq := Fin (N + 1) → Z × A
  let Data := (Fin (N + 1) → Z) × (Fin N → A)
  let pairOf : Y × Seq → Y × A := fun input ↦
    (input.1, (input.2 (select input.1 input.2)).2)
  let dataOf : Y × Seq → Data := fun input ↦
    ((fun k ↦ (input.2 k).1),
      fun k ↦ (input.2 ((select input.1 input.2).succAbove k)).2)
  let domain : Finset (Y × Seq) := Finset.univ.filter fun input ↦
    admissible input ∧ success (dataOf input) input.1
      (input.2 (select input.1 input.2)).2
  have hencode : Set.InjOn (fun input : Y × Seq ↦
      (dataOf input, pairOf input)) domain := by
    intro first hfirst second hsecond heq
    rcases first with ⟨y₁, xs⟩
    rcases second with ⟨y₂, ys⟩
    have hadm₁ : admissible (y₁, xs) :=
      (Finset.mem_filter.mp hfirst).2.1
    have hadm₂ : admissible (y₂, ys) :=
      (Finset.mem_filter.mp hsecond).2.1
    have hy : y₁ = y₂ := congrArg (fun value ↦ value.2.1) heq
    subst y₂
    let jx := select y₁ xs
    let jy := select y₁ ys
    have hz : ∀ k, (xs k).1 = (ys k).1 := by
      intro k
      exact congrFun (congrArg (fun value ↦ value.1.1) heq) k
    have herased : ∀ k, (xs (jx.succAbove k)).2 =
        (ys (jy.succAbove k)).2 := by
      intro k
      exact congrFun (congrArg (fun value ↦ value.1.2) heq) k
    have hselected : (xs jx).2 = (ys jy).2 :=
      congrArg (fun value ↦ value.2.2) heq
    have hprefix_xy (hxy : jx < jy) :
        ∀ k, k < jx → xs k = ys k := by
      intro k hk
      apply Prod.ext (hz k)
      have hklast : k ≠ Fin.last N := by
        exact ne_of_lt (hk.trans_le (Fin.le_last jx))
      let l : Fin N := k.castPred hklast
      have hx : jx.succAbove l = k := by
        exact Fin.succAbove_castPred_of_lt jx k hk
      have hy' : jy.succAbove l = k := by
        exact Fin.succAbove_castPred_of_lt jy k (hk.trans hxy)
      simpa [hx, hy'] using herased l
    have hj : jx = jy := by
      rcases lt_trichotomy jx jy with hxy | hEq | hyx
      · exact (hselect y₁ xs ys hadm₁ hadm₂ (hprefix_xy hxy)).symm
      · exact hEq
      · have hprefix_yx : ∀ k, k < jy → ys k = xs k := by
          intro k hk
          apply Prod.ext (hz k).symm
          have hklast : k ≠ Fin.last N := by
            exact ne_of_lt (hk.trans_le (Fin.le_last jy))
          let l : Fin N := k.castPred hklast
          have hy' : jy.succAbove l = k := by
            exact Fin.succAbove_castPred_of_lt jy k hk
          have hx : jx.succAbove l = k := by
            exact Fin.succAbove_castPred_of_lt jx k (hk.trans hyx)
          simpa [hx, hy'] using (herased l).symm
        exact hselect y₁ ys xs hadm₂ hadm₁ hprefix_yx
    apply Prod.ext
    · rfl
    funext k
    apply Prod.ext (hz k)
    by_cases hk : k = jx
    · subst k
      simpa [hj] using hselected
    · obtain ⟨l, hl⟩ := Fin.exists_succAbove_eq hk
      have he := herased l
      have hl' : jy.succAbove l = k := by rw [← hj]; exact hl
      rw [hl, hl'] at he
      exact he
  let good : Finset (Data × (Y × A)) := Finset.univ.filter fun value ↦
    success value.1 value.2.1 value.2.2
  have hdomain : domain.card ≤ good.card := by
    apply Finset.card_le_card_of_injOn
      (fun input ↦ (dataOf input, pairOf input))
    · intro input hinput
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
        (Finset.mem_filter.mp hinput).2.2⟩
    · exact hencode
  have hpairDen : (0 : ℚ) < Fintype.card Y * Fintype.card A := by
    have hY : 0 < Fintype.card Y := Fintype.card_pos
    have hA : 0 < Fintype.card A := Fintype.card_pos
    exact_mod_cast Nat.mul_pos hY hA
  have hpair (data : Data) :
      ((Finset.univ.filter fun pair : Y × A ↦
        success data pair.1 pair.2).card : ℚ) ≤
          epsilon * (Fintype.card Y * Fintype.card A) :=
    (div_le_iff₀ hpairDen).mp (hpairs data)
  have hgoodEq : good.card = ∑ data : Data,
      (Finset.univ.filter fun pair : Y × A ↦
        success data pair.1 pair.2).card := by
    dsimp [good]
    rw [card_filter_prod_fst]
  have hgood : (good.card : ℚ) ≤
      Fintype.card Data *
        (epsilon * (Fintype.card Y * Fintype.card A)) := by
    rw [hgoodEq]
    push_cast
    calc
      ∑ data : Data, ((Finset.univ.filter fun pair : Y × A ↦
          success data pair.1 pair.2).card : ℚ)
        ≤ ∑ _data : Data,
            epsilon * (Fintype.card Y * Fintype.card A) :=
          Finset.sum_le_sum (fun data _ ↦ hpair data)
      _ = Fintype.card Data *
          (epsilon * (Fintype.card Y * Fintype.card A)) := by simp
  have htotal : (0 : ℚ) <
      Fintype.card (Y × (Fin (N + 1) → Z × A)) := by
    exact_mod_cast Fintype.card_pos
  rw [div_le_iff₀ htotal]
  calc
    ((Finset.univ.filter fun input : Y × (Fin (N + 1) → Z × A) ↦
        admissible input ∧
        let selected := select input.1 input.2
        let data := ((fun k ↦ (input.2 k).1),
          fun k ↦ (input.2 (selected.succAbove k)).2)
        success data input.1 (input.2 selected).2).card : ℚ)
      ≤ (good.card : ℚ) := by
        exact_mod_cast hdomain
    _ ≤ Fintype.card Data *
        (epsilon * (Fintype.card Y * Fintype.card A)) := hgood
    _ = epsilon *
        Fintype.card (Y × (Fin (N + 1) → Z × A)) := by
      simp only [Data, Fintype.card_prod, Fintype.card_fun,
        Fintype.card_fin, Nat.cast_mul, Nat.cast_pow]
      rw [mul_pow]
      ring

/-! ## Ligero's alpha-last incidence count -/

/-- Count the independent `(querySet, alpha)` pairs for which the query set
lies in the alpha-dependent agreement set.  Good alphas use `goodCap`; the
at-most-`badCount` exceptional alphas use the universal `absoluteCap`.

The intentionally slightly loose right side is the one used by the repaired
compiler:

`|A| * choose(goodCap,r) + badCount * choose(absoluteCap,r)`.

After division by `|A| * choose(n,r)` this is
`hyp(goodCap) + badCount/|A| * hyp(absoluteCap)`.
-/
theorem alpha_last_pair_card_le
    {A : Type*} [Fintype A] [DecidableEq A]
    {n r goodCap absoluteCap badCount : ℕ}
    (bad : Finset A) (allowed : A → Finset (Fin n))
    (hbad : bad.card ≤ badCount)
    (hgood : ∀ alpha ∉ bad, (allowed alpha).card ≤ goodCap)
    (habsolute : ∀ alpha, (allowed alpha).card ≤ absoluteCap) :
    (Finset.filter (fun p : LigeroFamily.QuerySet n r × A ↦
        p.1.coordinates ⊆ allowed p.2) Finset.univ).card ≤
      Fintype.card A * goodCap.choose r + badCount * absoluteCap.choose r := by
  classical
  rw [card_filter_prod_snd]
  calc
    ∑ alpha : A, (Finset.filter (fun query : LigeroFamily.QuerySet n r ↦
          query.coordinates ⊆ allowed alpha) Finset.univ).card
      ≤ ∑ alpha : A, (goodCap.choose r +
          if alpha ∈ bad then absoluteCap.choose r else 0) := by
        apply Finset.sum_le_sum
        intro alpha _
        by_cases ha : alpha ∈ bad
        · calc
            (Finset.filter (fun query : LigeroFamily.QuerySet n r ↦
                query.coordinates ⊆ allowed alpha) Finset.univ).card
                = (LigeroFamily.queriesWithin (r := r) (allowed alpha)).card := rfl
            _ ≤ absoluteCap.choose r :=
                LigeroFamily.card_queriesWithin_le (allowed alpha) (habsolute alpha)
            _ ≤ goodCap.choose r +
                (if alpha ∈ bad then absoluteCap.choose r else 0) := by simp [ha]
        · calc
            (Finset.filter (fun query : LigeroFamily.QuerySet n r ↦
                query.coordinates ⊆ allowed alpha) Finset.univ).card
                = (LigeroFamily.queriesWithin (r := r) (allowed alpha)).card := rfl
            _ ≤ goodCap.choose r :=
                LigeroFamily.card_queriesWithin_le (allowed alpha) (hgood alpha ha)
            _ ≤ goodCap.choose r +
                (if alpha ∈ bad then absoluteCap.choose r else 0) := by simp [ha]
    _ = Fintype.card A * goodCap.choose r + bad.card * absoluteCap.choose r := by
        rw [Finset.sum_add_distrib]
        simp [Finset.sum_const]
    _ ≤ Fintype.card A * goodCap.choose r +
          badCount * absoluteCap.choose r := by gcongr

/-- Tight alpha-last incidence count.  Exceptional alphas pay only the
*increment* from the good cap to the absolute cap; the common good baseline
is not charged a second time. -/
theorem alpha_last_pair_card_le_tight
    {A : Type*} [Fintype A] [DecidableEq A]
    {n r goodCap absoluteCap badCount : ℕ}
    (bad : Finset A) (allowed : A → Finset (Fin n))
    (hbad : bad.card ≤ badCount)
    (hgood : ∀ alpha ∉ bad, (allowed alpha).card ≤ goodCap)
    (habsolute : ∀ alpha, (allowed alpha).card ≤ absoluteCap)
    (hcaps : goodCap ≤ absoluteCap) :
    (Finset.filter (fun p : LigeroFamily.QuerySet n r × A ↦
        p.1.coordinates ⊆ allowed p.2) Finset.univ).card ≤
      Fintype.card A * goodCap.choose r +
        badCount * (absoluteCap.choose r - goodCap.choose r) := by
  classical
  have hchoose : goodCap.choose r ≤ absoluteCap.choose r :=
    Nat.choose_le_choose r hcaps
  rw [card_filter_prod_snd]
  calc
    ∑ alpha : A, (Finset.filter (fun query : LigeroFamily.QuerySet n r ↦
          query.coordinates ⊆ allowed alpha) Finset.univ).card
      ≤ ∑ alpha : A, (goodCap.choose r +
          if alpha ∈ bad then absoluteCap.choose r - goodCap.choose r else 0) := by
        apply Finset.sum_le_sum
        intro alpha _
        by_cases ha : alpha ∈ bad
        · calc
            (Finset.filter (fun query : LigeroFamily.QuerySet n r ↦
                query.coordinates ⊆ allowed alpha) Finset.univ).card
                = (LigeroFamily.queriesWithin (r := r) (allowed alpha)).card := rfl
            _ ≤ absoluteCap.choose r :=
                LigeroFamily.card_queriesWithin_le (allowed alpha) (habsolute alpha)
            _ = goodCap.choose r +
                (absoluteCap.choose r - goodCap.choose r) := by omega
            _ = goodCap.choose r +
                (if alpha ∈ bad then
                  absoluteCap.choose r - goodCap.choose r else 0) := by simp [ha]
        · calc
            (Finset.filter (fun query : LigeroFamily.QuerySet n r ↦
                query.coordinates ⊆ allowed alpha) Finset.univ).card
                = (LigeroFamily.queriesWithin (r := r) (allowed alpha)).card := rfl
            _ ≤ goodCap.choose r :=
                LigeroFamily.card_queriesWithin_le (allowed alpha) (hgood alpha ha)
            _ ≤ goodCap.choose r +
                (if alpha ∈ bad then
                  absoluteCap.choose r - goodCap.choose r else 0) := by simp [ha]
    _ = Fintype.card A * goodCap.choose r +
          bad.card * (absoluteCap.choose r - goodCap.choose r) := by
        rw [Finset.sum_add_distrib]
        simp [Finset.sum_const]
    _ ≤ Fintype.card A * goodCap.choose r +
          badCount * (absoluteCap.choose r - goodCap.choose r) := by gcongr

/-- Alpha-last with the adaptive continuation included.  This is the exact
composition of `alpha_last_pair_card_le` and
`predictable_selection_card_le`; in particular `occurs` may select on the
early query set. -/
theorem alpha_last_predictable_card_le
    {A Z : Type*} [Fintype A] [Fintype Z] [DecidableEq A] [DecidableEq Z]
    {n r goodCap absoluteCap badCount : ℕ}
    (bad : Finset A) (allowed : A → Finset (Fin n))
    (occurs : LigeroFamily.QuerySet n r → Z → Prop)
    (hbad : bad.card ≤ badCount)
    (hgood : ∀ alpha ∉ bad, (allowed alpha).card ≤ goodCap)
    (habsolute : ∀ alpha, (allowed alpha).card ≤ absoluteCap) :
    (Finset.filter (fun p : (LigeroFamily.QuerySet n r × Z) × A ↦
        occurs p.1.1 p.1.2 ∧ p.1.1.coordinates ⊆ allowed p.2)
      Finset.univ).card ≤
      Fintype.card Z *
        (Fintype.card A * goodCap.choose r + badCount * absoluteCap.choose r) := by
  classical
  have hpairs := alpha_last_pair_card_le (r := r) bad allowed hbad hgood habsolute
  rw [card_filter_prod_fst] at hpairs ⊢
  calc
    ∑ qz : LigeroFamily.QuerySet n r × Z,
        (Finset.filter (fun alpha : A ↦
          occurs qz.1 qz.2 ∧ qz.1.coordinates ⊆ allowed alpha) Finset.univ).card
      ≤ ∑ qz : LigeroFamily.QuerySet n r × Z,
          (Finset.filter (fun alpha : A ↦
            qz.1.coordinates ⊆ allowed alpha) Finset.univ).card := by
        apply Finset.sum_le_sum
        intro qz _
        apply Finset.card_le_card
        intro alpha ha
        simp only [Finset.mem_filter, Finset.mem_univ, true_and] at ha ⊢
        exact ha.2
    _ = Fintype.card Z * ∑ query : LigeroFamily.QuerySet n r,
          (Finset.filter (fun alpha : A ↦
            query.coordinates ⊆ allowed alpha) Finset.univ).card := by
        simp only [Fintype.sum_prod_type]
        rw [Finset.mul_sum]
        apply Finset.sum_congr rfl
        intro query _
        simp [Finset.sum_const]
    _ ≤ Fintype.card Z *
        (Fintype.card A * goodCap.choose r + badCount * absoluteCap.choose r) :=
      Nat.mul_le_mul_left _ hpairs

/-- Predictable alpha-last count with the tight exceptional increment. -/
theorem alpha_last_predictable_card_le_tight
    {A Z : Type*} [Fintype A] [Fintype Z] [DecidableEq A] [DecidableEq Z]
    {n r goodCap absoluteCap badCount : ℕ}
    (bad : Finset A) (allowed : A → Finset (Fin n))
    (occurs : LigeroFamily.QuerySet n r → Z → Prop)
    (hbad : bad.card ≤ badCount)
    (hgood : ∀ alpha ∉ bad, (allowed alpha).card ≤ goodCap)
    (habsolute : ∀ alpha, (allowed alpha).card ≤ absoluteCap)
    (hcaps : goodCap ≤ absoluteCap) :
    (Finset.filter (fun p : (LigeroFamily.QuerySet n r × Z) × A ↦
        occurs p.1.1 p.1.2 ∧ p.1.1.coordinates ⊆ allowed p.2)
      Finset.univ).card ≤
      Fintype.card Z *
        (Fintype.card A * goodCap.choose r +
          badCount * (absoluteCap.choose r - goodCap.choose r)) := by
  classical
  have hpairs := alpha_last_pair_card_le_tight (r := r) bad allowed
    hbad hgood habsolute hcaps
  rw [card_filter_prod_fst] at hpairs ⊢
  calc
    ∑ qz : LigeroFamily.QuerySet n r × Z,
        (Finset.filter (fun alpha : A ↦
          occurs qz.1 qz.2 ∧ qz.1.coordinates ⊆ allowed alpha) Finset.univ).card
      ≤ ∑ qz : LigeroFamily.QuerySet n r × Z,
          (Finset.filter (fun alpha : A ↦
            qz.1.coordinates ⊆ allowed alpha) Finset.univ).card := by
        apply Finset.sum_le_sum
        intro qz _
        apply Finset.card_le_card
        intro alpha ha
        simp only [Finset.mem_filter, Finset.mem_univ, true_and] at ha ⊢
        exact ha.2
    _ = Fintype.card Z * ∑ query : LigeroFamily.QuerySet n r,
          (Finset.filter (fun alpha : A ↦
            query.coordinates ⊆ allowed alpha) Finset.univ).card := by
        simp only [Fintype.sum_prod_type]
        rw [Finset.mul_sum]
        apply Finset.sum_congr rfl
        intro query _
        simp [Finset.sum_const]
    _ ≤ Fintype.card Z *
        (Fintype.card A * goodCap.choose r +
          badCount * (absoluteCap.choose r - goodCap.choose r)) :=
      Nat.mul_le_mul_left _ hpairs

/-! ## Query-slot attribution and the compiler union bound -/

/-- The operational output of the repaired ROM reduction.

`caseA_card` and `caseB_card` are separate on purpose.  A case-A event combines
two disjoint events: its baseline part is charged to its fresh `H₂` slot and
its listed excess to its earlier fresh `H₁` slot.  A case-B event is proved globally
with `alpha_last_predictable_card_le`, never by a pointwise conditional bound
at the later `H₁` slot.
-/
structure RigidAttribution (Ω : Type*) [Fintype Ω] (querySlots : ℕ) where
  win : Ω → Prop
  bindBreak : Ω → Prop
  caseA : Fin querySlots → Ω → Prop
  caseB : Fin querySlots → Ω → Prop
  bindBudget : ℕ
  caseAFloorBudget : ℕ
  caseAListedBudget : ℕ
  caseBAlphaLastBudget : ℕ
  cover : ∀ ω, win ω → bindBreak ω ∨
    (∃ i, caseA i ω) ∨ (∃ i, caseB i ω)
  bind_card : (Finset.filter bindBreak Finset.univ).card ≤ bindBudget
  caseA_card : ∀ i, (Finset.filter (caseA i) Finset.univ).card ≤
    caseAFloorBudget + caseAListedBudget
  caseB_card : ∀ i, (Finset.filter (caseB i) Finset.univ).card ≤
    caseBAlphaLastBudget

/-! ## First-occurrence partition -/

/-- The trace facts established after the verifier appends its two defining
queries.  `alphaQuery` is `H₁(x,root)` and `subsetQuery` is
`H₂(x,root,response)`.  Appending missing verifier queries is precisely what
proves `alpha_mem` and `subset_mem`; `trace_length` carries the resulting
`Q+2` bound.

The two inputs are required to be distinct (normally by domain-separation
tags), so their first occurrences have a strict order. -/
structure FirstOccurrenceTrace (Ω Query : Type*) (querySlots : ℕ)
    [BEq Query] [LawfulBEq Query] where
  trace : Ω → List Query
  alphaQuery : Ω → Query
  subsetQuery : Ω → Query
  alpha_mem : ∀ ω, alphaQuery ω ∈ trace ω
  subset_mem : ∀ ω, subsetQuery ω ∈ trace ω
  separated : ∀ ω, alphaQuery ω ≠ subsetQuery ω
  trace_length : ∀ ω, (trace ω).length ≤ querySlots

namespace FirstOccurrenceTrace

variable {Ω Query : Type*} [Fintype Ω] [BEq Query] [LawfulBEq Query]
variable {querySlots : ℕ}

/-- Pull a first-occurrence trace back along a deterministic map of sample
spaces.  This is used to add independent Merkle randomness without changing
the two Fiat--Shamir defining queries or their order. -/
def comap {Ω' : Type*}
    (F : FirstOccurrenceTrace Ω Query querySlots) (f : Ω' → Ω) :
    FirstOccurrenceTrace Ω' Query querySlots where
  trace ω := F.trace (f ω)
  alphaQuery ω := F.alphaQuery (f ω)
  subsetQuery ω := F.subsetQuery (f ω)
  alpha_mem ω := F.alpha_mem (f ω)
  subset_mem ω := F.subset_mem (f ω)
  separated ω := F.separated (f ω)
  trace_length ω := F.trace_length (f ω)

/-- Case A: `H₁` occurred first.  The caller partitions query success into a
canonical floor-sized baseline and a high-agreement excess.  Baseline
executions are charged to the first `H₂` slot, where the subset answer is
fresh.  Listed-excess executions are charged to the first `H₁` slot, where
the batching challenge is fresh.  The latter choice is what accounts for
grinding over candidate roots.

`listed` is the caller-supplied excess-event predicate, not merely the claim
that agreement exceeds the floor.  In the Ligero instantiation, one first
chooses a canonical floor-sized subset of every larger agreement set; the
baseline event is containment in that subset, and `listed` is successful
containment in the larger set but not in the baseline subset.
-/
def caseA (F : FirstOccurrenceTrace Ω Query querySlots)
    (listed win bindBreak : Ω → Prop) (i : Fin querySlots) (ω : Ω) : Prop :=
  win ω ∧ ¬bindBreak ω ∧
    (F.trace ω).idxOf (F.alphaQuery ω) <
      (F.trace ω).idxOf (F.subsetQuery ω) ∧
    ((¬listed ω ∧ (F.trace ω).idxOf (F.subsetQuery ω) = i.val) ∨
      (listed ω ∧ (F.trace ω).idxOf (F.alphaQuery ω) = i.val))

/-- Case B, also charged to the first H2 slot: H2 occurred before H1.  This
is the slot whose fresh subset answer the predictable-selection lemma uses.
-/
def caseB (F : FirstOccurrenceTrace Ω Query querySlots)
    (win bindBreak : Ω → Prop) (i : Fin querySlots) (ω : Ω) : Prop :=
  win ω ∧ ¬bindBreak ω ∧
    (F.trace ω).idxOf (F.subsetQuery ω) = i.val ∧
    (F.trace ω).idxOf (F.subsetQuery ω) <
      (F.trace ω).idxOf (F.alphaQuery ω)

omit [Fintype Ω] in
/-- The defining queries' first occurrences are different. -/
theorem idxOf_ne (F : FirstOccurrenceTrace Ω Query querySlots) (ω : Ω) :
    (F.trace ω).idxOf (F.alphaQuery ω) ≠
      (F.trace ω).idxOf (F.subsetQuery ω) := by
  intro heq
  exact F.separated ω ((List.idxOf_inj (F.alpha_mem ω)).mp heq)

omit [Fintype Ω] in
/-- The first H2 occurrence is a real slot of the augmented trace. -/
theorem subset_idx_lt (F : FirstOccurrenceTrace Ω Query querySlots) (ω : Ω) :
    (F.trace ω).idxOf (F.subsetQuery ω) < querySlots :=
  lt_of_lt_of_le (List.idxOf_lt_length_of_mem (F.subset_mem ω)) (F.trace_length ω)

omit [Fintype Ω] in
/-- The first `H₁` occurrence is a real slot of the augmented trace. -/
theorem alpha_idx_lt (F : FirstOccurrenceTrace Ω Query querySlots) (ω : Ω) :
    (F.trace ω).idxOf (F.alphaQuery ω) < querySlots :=
  lt_of_lt_of_le (List.idxOf_lt_length_of_mem (F.alpha_mem ω)) (F.trace_length ω)

/-- The actual first-occurrence slot of the defining batching query. -/
def alphaSlot (F : FirstOccurrenceTrace Ω Query querySlots) (ω : Ω) :
    Fin querySlots :=
  ⟨(F.trace ω).idxOf (F.alphaQuery ω), F.alpha_idx_lt ω⟩

/-- The actual first-occurrence slot of the defining subset query. -/
def subsetSlot (F : FirstOccurrenceTrace Ω Query querySlots) (ω : Ω) :
    Fin querySlots :=
  ⟨(F.trace ω).idxOf (F.subsetQuery ω), F.subset_idx_lt ω⟩

omit [Fintype Ω] in
theorem alphaSlot_ne_subsetSlot
    (F : FirstOccurrenceTrace Ω Query querySlots) (ω : Ω) :
    F.alphaSlot ω ≠ F.subsetSlot ω := by
  intro heq
  exact F.idxOf_ne ω (Fin.ext_iff.mp heq)

omit [Fintype Ω] in
theorem subsetSlot_eq_of_caseB
    (F : FirstOccurrenceTrace Ω Query querySlots)
    (win bindBreak : Ω → Prop) (i : Fin querySlots) (ω : Ω)
    (hcase : F.caseB win bindBreak i ω) :
    F.subsetSlot ω = i := by
  exact Fin.ext hcase.2.2.1

omit [Fintype Ω] in
theorem alphaSlot_eq_of_caseA_listed
    (F : FirstOccurrenceTrace Ω Query querySlots)
    (listed win bindBreak : Ω → Prop) (i : Fin querySlots) (ω : Ω)
    (hcase : F.caseA listed win bindBreak i ω) (hlisted : listed ω) :
    F.alphaSlot ω = i := by
  rcases hcase.2.2.2 with hfloor | hexcess
  · exact absurd hlisted hfloor.1
  · exact Fin.ext hexcess.2

omit [Fintype Ω] in
theorem subsetSlot_eq_of_caseA_floor
    (F : FirstOccurrenceTrace Ω Query querySlots)
    (listed win bindBreak : Ω → Prop) (i : Fin querySlots) (ω : Ω)
    (hcase : F.caseA listed win bindBreak i ω) (hunlisted : ¬listed ω) :
    F.subsetSlot ω = i := by
  rcases hcase.2.2.2 with hfloor | hexcess
  · exact Fin.ext hfloor.2
  · exact absurd hexcess.1 hunlisted

/-- Build the compiler attribution from the canonical first-occurrence
partition.  The only remaining inputs are the three event counts: the
operational partition and the `Q+2` slot accounting are discharged here. -/
def toRigidAttribution (F : FirstOccurrenceTrace Ω Query querySlots)
    (listed win bindBreak : Ω → Prop)
    (bindBudget caseAFloorBudget caseAListedBudget caseBAlphaLastBudget : ℕ)
    (hbind : (Finset.filter bindBreak Finset.univ).card ≤ bindBudget)
    (hcaseA : ∀ i, (Finset.filter (F.caseA listed win bindBreak i) Finset.univ).card ≤
      caseAFloorBudget + caseAListedBudget)
    (hcaseB : ∀ i, (Finset.filter (F.caseB win bindBreak i) Finset.univ).card ≤
      caseBAlphaLastBudget) :
    RigidAttribution Ω querySlots where
  win := win
  bindBreak := bindBreak
  caseA := F.caseA listed win bindBreak
  caseB := F.caseB win bindBreak
  bindBudget := bindBudget
  caseAFloorBudget := caseAFloorBudget
  caseAListedBudget := caseAListedBudget
  caseBAlphaLastBudget := caseBAlphaLastBudget
  cover ω hwin := by
    by_cases hbindω : bindBreak ω
    · exact Or.inl hbindω
    · right
      rcases lt_or_gt_of_ne (F.idxOf_ne ω) with hbefore | hafter
      · by_cases hlisted : listed ω
        · let i : Fin querySlots :=
            ⟨(F.trace ω).idxOf (F.alphaQuery ω), F.alpha_idx_lt ω⟩
          exact Or.inl ⟨i, hwin, hbindω, hbefore, Or.inr ⟨hlisted, rfl⟩⟩
        · let i : Fin querySlots :=
            ⟨(F.trace ω).idxOf (F.subsetQuery ω), F.subset_idx_lt ω⟩
          exact Or.inl ⟨i, hwin, hbindω, hbefore, Or.inl ⟨hlisted, rfl⟩⟩
      · let i : Fin querySlots :=
          ⟨(F.trace ω).idxOf (F.subsetQuery ω), F.subset_idx_lt ω⟩
        exact Or.inr ⟨i, hwin, hbindω, rfl, hafter⟩
  bind_card := hbind
  caseA_card := hcaseA
  caseB_card := hcaseB

end FirstOccurrenceTrace

/-! ## Chained transcripts: removing case B -/

/-- **A chained first-occurrence trace.**

`FirstOccurrenceTrace` above admits both query orders because the query-set hash
`H₂(x, root, response)` does not read the batching challenge: nothing stops an
adversary from fixing the response, reading its query set, and only then asking
`H₁` for the challenge.  That is case B, and it is the branch that cannot be
bounded by conditioning on the later query.

Chaining removes it.  If the compiler hashes `H₂(x, root, alpha, response)`
instead, then the second query's *input* contains the first query's *answer*, so
in a lazy random-oracle execution the second query cannot occupy an earlier slot
than the first.  `chained` records exactly that, and it is a fact about the
serialization, discharged once by a concrete execution.

Two consequences, both realized below: `separated` is no longer a hypothesis --
strict order gives distinctness, so domain-separation tags are not needed for
this argument -- and the compiler bound loses its `caseBAlphaLastBudget` term
together with the predictable-selection reasoning that supplied it.
-/
structure ChainedTrace (Ω Query : Type*) (querySlots : ℕ)
    [BEq Query] [LawfulBEq Query] where
  /-- The augmented query trace. -/
  trace : Ω → List Query
  /-- The batching-challenge query `H₁(x, root)`. -/
  alphaQuery : Ω → Query
  /-- The query-set query `H₂(x, root, alpha, response)`. -/
  subsetQuery : Ω → Query
  /-- The verifier's recomputation puts `H₁` in the trace. -/
  alpha_mem : ∀ ω, alphaQuery ω ∈ trace ω
  /-- The verifier's recomputation puts `H₂` in the trace. -/
  subset_mem : ∀ ω, subsetQuery ω ∈ trace ω
  /-- **Chaining.**  `H₂`'s input contains `H₁`'s answer, so `H₁` is queried
  strictly first. -/
  chained : ∀ ω, (trace ω).idxOf (alphaQuery ω) < (trace ω).idxOf (subsetQuery ω)
  /-- The augmented trace fits the `Q + 2` slot budget. -/
  trace_length : ∀ ω, (trace ω).length ≤ querySlots

namespace ChainedTrace

variable {Ω Query : Type*} [Fintype Ω] [BEq Query] [LawfulBEq Query]
variable {querySlots : ℕ}

omit [Fintype Ω] in
/-- Distinctness is a consequence of chaining, not a separate assumption. -/
theorem separated (F : ChainedTrace Ω Query querySlots) (ω : Ω) :
    F.alphaQuery ω ≠ F.subsetQuery ω := by
  intro heq
  exact absurd (congrArg (fun q => (F.trace ω).idxOf q) heq)
    (Nat.ne_of_lt (F.chained ω))

/-- The underlying unordered trace. -/
def toFirstOccurrenceTrace (F : ChainedTrace Ω Query querySlots) :
    FirstOccurrenceTrace Ω Query querySlots where
  trace := F.trace
  alphaQuery := F.alphaQuery
  subsetQuery := F.subsetQuery
  alpha_mem := F.alpha_mem
  subset_mem := F.subset_mem
  separated := F.separated
  trace_length := F.trace_length

omit [Fintype Ω] in
/-- **Case B is empty.**  The whole point of chaining. -/
theorem not_caseB (F : ChainedTrace Ω Query querySlots)
    (win bindBreak : Ω → Prop) (i : Fin querySlots) (ω : Ω) :
    ¬ F.toFirstOccurrenceTrace.caseB win bindBreak i ω := by
  intro h
  have hlt := F.chained ω
  have hgt : (F.trace ω).idxOf (F.subsetQuery ω) <
      (F.trace ω).idxOf (F.alphaQuery ω) := h.2.2.2
  omega

/-- Case A for a chained trace.  The order conjunct of
`FirstOccurrenceTrace.caseA` is now automatic, so the caller's obligation is
just the win, the binding, and the slot. -/
def caseA (F : ChainedTrace Ω Query querySlots)
    (listed win bindBreak : Ω → Prop) (i : Fin querySlots) (ω : Ω) : Prop :=
  win ω ∧ ¬bindBreak ω ∧
    ((¬listed ω ∧ (F.trace ω).idxOf (F.subsetQuery ω) = i.val) ∨
      (listed ω ∧ (F.trace ω).idxOf (F.alphaQuery ω) = i.val))

omit [Fintype Ω] in
/-- The simplified case A is the original one. -/
theorem caseA_iff (F : ChainedTrace Ω Query querySlots)
    (listed win bindBreak : Ω → Prop) (i : Fin querySlots) (ω : Ω) :
    F.caseA listed win bindBreak i ω ↔
      F.toFirstOccurrenceTrace.caseA listed win bindBreak i ω := by
  constructor
  · exact fun h => ⟨h.1, h.2.1, F.chained ω, h.2.2⟩
  · exact fun h => ⟨h.1, h.2.1, h.2.2.2⟩

/-- The chained attribution: a zero case-B budget, discharged by `not_caseB`. -/
def toRigidAttribution (F : ChainedTrace Ω Query querySlots)
    (listed win bindBreak : Ω → Prop)
    (bindBudget caseAFloorBudget caseAListedBudget : ℕ)
    (hbind : (Finset.filter bindBreak Finset.univ).card ≤ bindBudget)
    (hcaseA : ∀ i, (Finset.filter (F.caseA listed win bindBreak i) Finset.univ).card ≤
      caseAFloorBudget + caseAListedBudget) :
    RigidAttribution Ω querySlots :=
  F.toFirstOccurrenceTrace.toRigidAttribution listed win bindBreak
    bindBudget caseAFloorBudget caseAListedBudget 0 hbind
    (by
      intro i
      refine le_trans (Finset.card_le_card ?_) (hcaseA i)
      intro ω hω
      simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
      exact (F.caseA_iff listed win bindBreak i ω).mpr hω)
    (by
      intro i
      have hempty : Finset.filter
          (F.toFirstOccurrenceTrace.caseB win bindBreak i) Finset.univ = ∅ :=
        Finset.filter_false_of_mem (fun ω _ => F.not_caseB win bindBreak i ω)
      simp [hempty])

end ChainedTrace

namespace RigidAttribution

variable {Ω : Type*} [Fintype Ω] {querySlots : ℕ}

/-- **Repaired response-rigid ROM compiler, cardinality form.**

The accepted bad executions are covered once by prefix-binding failure and
once per possible first-occurrence query slot in each order.  The case-B
budget is the predictable-slot budget, so this theorem does not make the
invalid conditioning step at the later H1 query.
-/
theorem rom_compiler_card_le (R : RigidAttribution Ω querySlots) :
    (Finset.filter R.win Finset.univ).card ≤
      R.bindBudget + querySlots *
        (R.caseAFloorBudget + R.caseAListedBudget + R.caseBAlphaLastBudget) := by
  classical
  let casesA : Finset Ω := Finset.biUnion Finset.univ
    (fun i ↦ Finset.filter (R.caseA i) Finset.univ)
  let casesB : Finset Ω := Finset.biUnion Finset.univ
    (fun i ↦ Finset.filter (R.caseB i) Finset.univ)
  calc
    (Finset.filter R.win Finset.univ).card ≤
        ((Finset.filter R.bindBreak Finset.univ ∪ casesA) ∪ casesB).card := by
      apply Finset.card_le_card
      intro ω hω
      have hwin : R.win ω := (Finset.mem_filter.mp hω).2
      rcases R.cover ω hwin with hbind | hA | hB
      · apply Finset.mem_union_left
        exact Finset.mem_union_left _ (Finset.mem_filter.mpr ⟨Finset.mem_univ _, hbind⟩)
      · apply Finset.mem_union_left
        apply Finset.mem_union_right
        obtain ⟨i, hi⟩ := hA
        exact Finset.mem_biUnion.mpr ⟨i, Finset.mem_univ _,
          Finset.mem_filter.mpr ⟨Finset.mem_univ _, hi⟩⟩
      · apply Finset.mem_union_right
        obtain ⟨i, hi⟩ := hB
        exact Finset.mem_biUnion.mpr ⟨i, Finset.mem_univ _,
          Finset.mem_filter.mpr ⟨Finset.mem_univ _, hi⟩⟩
    _ ≤ (Finset.filter R.bindBreak Finset.univ).card + casesA.card + casesB.card := by
      exact (Finset.card_union_le _ _).trans
        (Nat.add_le_add_right (Finset.card_union_le _ _) _)
    _ ≤ R.bindBudget +
          querySlots * (R.caseAFloorBudget + R.caseAListedBudget) +
          querySlots * R.caseBAlphaLastBudget := by
      apply Nat.add_le_add
      · exact Nat.add_le_add R.bind_card (by
          dsimp [casesA]
          calc
            (Finset.biUnion Finset.univ
                (fun i ↦ Finset.filter (R.caseA i) Finset.univ)).card
              ≤ ∑ i : Fin querySlots,
                  (Finset.filter (R.caseA i) Finset.univ).card :=
                Finset.card_biUnion_le
            _ ≤ ∑ _i : Fin querySlots,
                  (R.caseAFloorBudget + R.caseAListedBudget) :=
                Finset.sum_le_sum (fun i _ ↦ R.caseA_card i)
            _ = querySlots *
                  (R.caseAFloorBudget + R.caseAListedBudget) := by
                simp [Finset.sum_const])
      · dsimp [casesB]
        calc
          (Finset.biUnion Finset.univ
              (fun i ↦ Finset.filter (R.caseB i) Finset.univ)).card
            ≤ ∑ i : Fin querySlots,
                (Finset.filter (R.caseB i) Finset.univ).card :=
              Finset.card_biUnion_le
          _ ≤ ∑ _i : Fin querySlots, R.caseBAlphaLastBudget :=
              Finset.sum_le_sum (fun i _ ↦ R.caseB_card i)
          _ = querySlots * R.caseBAlphaLastBudget := by simp [Finset.sum_const]
    _ = R.bindBudget + querySlots *
          (R.caseAFloorBudget + R.caseAListedBudget + R.caseBAlphaLastBudget) := by ring

/-- Probability form of `rom_compiler_card_le` over the uniform finite-ROM
sample space. -/
theorem rom_compiler_ratio_le [Nonempty Ω] (R : RigidAttribution Ω querySlots) :
    ((Finset.filter R.win Finset.univ).card : ℚ) / Fintype.card Ω ≤
      (R.bindBudget + querySlots *
        (R.caseAFloorBudget + R.caseAListedBudget + R.caseBAlphaLastBudget) : ℕ) /
          (Fintype.card Ω : ℚ) := by
  have hΩ : (0 : ℚ) < Fintype.card Ω := by exact_mod_cast Fintype.card_pos
  exact div_le_div_of_nonneg_right
    (by exact_mod_cast R.rom_compiler_card_le) (le_of_lt hΩ)

end RigidAttribution

/-! ## Tight first-occurrence ledger

The original compatibility ledger stores Case-A floor and Case B separately,
which necessarily adds their two query-cover baselines.  Operationally both
are charged to the same fresh `H₂` slot and are disjoint prefix cases, so a
tight theorem stores their union as one subset-slot event. -/

structure TightRigidAttribution (Ω : Type*) (querySlots : ℕ) [Fintype Ω] where
  win : Ω → Prop
  bindBreak : Ω → Prop
  subsetCase : Fin querySlots → Ω → Prop
  listedCase : Fin querySlots → Ω → Prop
  bindBudget : ℕ
  subsetBudget : ℕ
  listedBudget : ℕ
  cover : ∀ ω, win ω → bindBreak ω ∨
    (∃ i, subsetCase i ω) ∨ (∃ i, listedCase i ω)
  bind_card : (Finset.filter bindBreak Finset.univ).card ≤ bindBudget
  subset_card : ∀ i,
    (Finset.filter (subsetCase i) Finset.univ).card ≤ subsetBudget
  listed_card : ∀ i,
    (Finset.filter (listedCase i) Finset.univ).card ≤ listedBudget

namespace FirstOccurrenceTrace

variable {Ω Query : Type*} [Fintype Ω] [BEq Query] [LawfulBEq Query]
variable {querySlots : ℕ}

/-- Tight operational adapter.  Case-A floor and Case B are combined before
counting because both are charged to the defining subset-query slot; listed
Case A alone is charged to the defining alpha-query slot. -/
def toTightRigidAttribution
    (F : FirstOccurrenceTrace Ω Query querySlots)
    (listed win bindBreak : Ω → Prop)
    (bindBudget subsetBudget listedBudget : ℕ)
    (hbind : (Finset.filter bindBreak Finset.univ).card ≤ bindBudget)
    (hsubset : ∀ i, (Finset.filter (fun ω =>
      (F.caseA listed win bindBreak i ω ∧ ¬listed ω) ∨
        F.caseB win bindBreak i ω) Finset.univ).card ≤ subsetBudget)
    (hlisted : ∀ i, (Finset.filter (fun ω =>
      F.caseA listed win bindBreak i ω ∧ listed ω)
      Finset.univ).card ≤ listedBudget) :
    TightRigidAttribution Ω querySlots where
  win := win
  bindBreak := bindBreak
  subsetCase i ω :=
    (F.caseA listed win bindBreak i ω ∧ ¬listed ω) ∨
      F.caseB win bindBreak i ω
  listedCase i ω := F.caseA listed win bindBreak i ω ∧ listed ω
  bindBudget := bindBudget
  subsetBudget := subsetBudget
  listedBudget := listedBudget
  cover ω hwin := by
    by_cases hbindω : bindBreak ω
    · exact Or.inl hbindω
    right
    rcases lt_or_gt_of_ne (F.idxOf_ne ω) with hbefore | hafter
    · by_cases hlistedω : listed ω
      · right
        let i : Fin querySlots := F.alphaSlot ω
        exact ⟨i, ⟨hwin, hbindω, hbefore,
          Or.inr ⟨hlistedω, rfl⟩⟩, hlistedω⟩
      · left
        let i : Fin querySlots := F.subsetSlot ω
        exact ⟨i, Or.inl ⟨⟨hwin, hbindω, hbefore,
          Or.inl ⟨hlistedω, rfl⟩⟩, hlistedω⟩⟩
    · left
      let i : Fin querySlots := F.subsetSlot ω
      exact ⟨i, Or.inr ⟨hwin, hbindω, rfl, hafter⟩⟩
  bind_card := hbind
  subset_card := by
    intro i
    convert hsubset i using 1
    congr 1
    ext ω
    simp
  listed_card := by
    intro i
    convert hlisted i using 1
    congr 1
    ext ω
    simp

end FirstOccurrenceTrace

namespace TightRigidAttribution

variable {Ω : Type*} [Fintype Ω] {querySlots : ℕ}

/-- Tight ROM union: one outer first-occurrence factor, with the two H₂ order
branches already combined before their common baseline is charged. -/
theorem rom_compiler_card_le (R : TightRigidAttribution Ω querySlots) :
    (Finset.filter R.win Finset.univ).card ≤
      R.bindBudget + querySlots * (R.subsetBudget + R.listedBudget) := by
  classical
  let subsets : Finset Ω := Finset.biUnion Finset.univ
    (fun i => Finset.filter (R.subsetCase i) Finset.univ)
  let listed : Finset Ω := Finset.biUnion Finset.univ
    (fun i => Finset.filter (R.listedCase i) Finset.univ)
  calc
    (Finset.filter R.win Finset.univ).card ≤
        ((Finset.filter R.bindBreak Finset.univ ∪ subsets) ∪ listed).card := by
      apply Finset.card_le_card
      intro ω hω
      rcases R.cover ω (Finset.mem_filter.mp hω).2 with hbind | hsubset | hlisted
      · exact Finset.mem_union_left _
          (Finset.mem_union_left _ (Finset.mem_filter.mpr ⟨Finset.mem_univ _, hbind⟩))
      · obtain ⟨i, hi⟩ := hsubset
        exact Finset.mem_union_left _ (Finset.mem_union_right _
          (Finset.mem_biUnion.mpr ⟨i, Finset.mem_univ _,
            Finset.mem_filter.mpr ⟨Finset.mem_univ _, hi⟩⟩))
      · obtain ⟨i, hi⟩ := hlisted
        exact Finset.mem_union_right _
          (Finset.mem_biUnion.mpr ⟨i, Finset.mem_univ _,
            Finset.mem_filter.mpr ⟨Finset.mem_univ _, hi⟩⟩)
    _ ≤ (Finset.filter R.bindBreak Finset.univ).card +
          subsets.card + listed.card := by
      exact (Finset.card_union_le _ _).trans
        (Nat.add_le_add_right (Finset.card_union_le _ _) _)
    _ ≤ R.bindBudget + querySlots * R.subsetBudget +
          querySlots * R.listedBudget := by
      apply Nat.add_le_add
      · exact Nat.add_le_add R.bind_card (by
          calc
            subsets.card ≤ ∑ i ∈ Finset.univ,
                (Finset.filter (R.subsetCase i) Finset.univ).card :=
              Finset.card_biUnion_le
            _ ≤ ∑ _i : Fin querySlots, R.subsetBudget :=
              Finset.sum_le_sum fun i _ => R.subset_card i
            _ = querySlots * R.subsetBudget := by simp)
      · calc
          listed.card ≤ ∑ i ∈ Finset.univ,
              (Finset.filter (R.listedCase i) Finset.univ).card :=
            Finset.card_biUnion_le
          _ ≤ ∑ _i : Fin querySlots, R.listedBudget :=
            Finset.sum_le_sum fun i _ => R.listed_card i
          _ = querySlots * R.listedBudget := by simp
    _ = R.bindBudget + querySlots * (R.subsetBudget + R.listedBudget) := by ring

end TightRigidAttribution

/-! ## Fully unified query-slot ledger

At a fixed lazy-sampling slot, the query's domain is determined before its
answer is read.  Hence the H₁-charged and H₂-charged branches are a
prefix-measurable case split, not two independent bad events.  A tight
protocol proof supplies one bound for their union and pays it once. -/

structure UnifiedRigidAttribution (Ω : Type*) (querySlots : ℕ) [Fintype Ω] where
  win : Ω → Prop
  bindBreak : Ω → Prop
  queryCase : Fin querySlots → Ω → Prop
  bindBudget : ℕ
  queryBudget : ℕ
  cover : ∀ ω, win ω → bindBreak ω ∨ ∃ i, queryCase i ω
  bind_card : (Finset.filter bindBreak Finset.univ).card ≤ bindBudget
  query_card : ∀ i,
    (Finset.filter (queryCase i) Finset.univ).card ≤ queryBudget

namespace FirstOccurrenceTrace

variable {Ω Query : Type*} [Fintype Ω] [BEq Query] [LawfulBEq Query]
variable {querySlots : ℕ}

/-- Canonical first-occurrence adapter with all three order/response branches
combined before counting. -/
def toUnifiedRigidAttribution
    (F : FirstOccurrenceTrace Ω Query querySlots)
    (listed win bindBreak : Ω → Prop)
    (bindBudget queryBudget : ℕ)
    (hbind : (Finset.filter bindBreak Finset.univ).card ≤ bindBudget)
    (hquery : ∀ i, (Finset.filter (fun ω ↦
      F.caseA listed win bindBreak i ω ∨
        F.caseB win bindBreak i ω) Finset.univ).card ≤ queryBudget) :
    UnifiedRigidAttribution Ω querySlots where
  win := win
  bindBreak := bindBreak
  queryCase i ω := F.caseA listed win bindBreak i ω ∨
    F.caseB win bindBreak i ω
  bindBudget := bindBudget
  queryBudget := queryBudget
  cover ω hwin := by
    by_cases hbindω : bindBreak ω
    · exact Or.inl hbindω
    right
    rcases lt_or_gt_of_ne (F.idxOf_ne ω) with hbefore | hafter
    · by_cases hlisted : listed ω
      · exact ⟨F.alphaSlot ω, Or.inl
          ⟨hwin, hbindω, hbefore, Or.inr ⟨hlisted, rfl⟩⟩⟩
      · exact ⟨F.subsetSlot ω, Or.inl
          ⟨hwin, hbindω, hbefore, Or.inl ⟨hlisted, rfl⟩⟩⟩
    · exact ⟨F.subsetSlot ω, Or.inr ⟨hwin, hbindω, rfl, hafter⟩⟩
  bind_card := hbind
  query_card := by
    intro i
    convert hquery i using 1
    congr 1
    ext ω
    simp

end FirstOccurrenceTrace

namespace UnifiedRigidAttribution

variable {Ω : Type*} [Fintype Ω] {querySlots : ℕ}

/-- Fully tight outer ROM union: binding once, then one unified budget for
each possible first-occurrence slot. -/
theorem rom_compiler_card_le (R : UnifiedRigidAttribution Ω querySlots) :
    (Finset.filter R.win Finset.univ).card ≤
      R.bindBudget + querySlots * R.queryBudget := by
  classical
  let cases : Finset Ω := Finset.biUnion Finset.univ
    (fun i ↦ Finset.filter (R.queryCase i) Finset.univ)
  calc
    (Finset.filter R.win Finset.univ).card ≤
        (Finset.filter R.bindBreak Finset.univ ∪ cases).card := by
      apply Finset.card_le_card
      intro ω hω
      rcases R.cover ω (Finset.mem_filter.mp hω).2 with hbind | hcase
      · exact Finset.mem_union_left _
          (Finset.mem_filter.mpr ⟨Finset.mem_univ _, hbind⟩)
      · obtain ⟨i, hi⟩ := hcase
        exact Finset.mem_union_right _
          (Finset.mem_biUnion.mpr ⟨i, Finset.mem_univ _,
            Finset.mem_filter.mpr ⟨Finset.mem_univ _, hi⟩⟩)
    _ ≤ (Finset.filter R.bindBreak Finset.univ).card + cases.card :=
      Finset.card_union_le _ _
    _ ≤ R.bindBudget + querySlots * R.queryBudget := by
      apply Nat.add_le_add R.bind_card
      calc
        cases.card ≤ ∑ i ∈ Finset.univ,
            (Finset.filter (R.queryCase i) Finset.univ).card :=
          Finset.card_biUnion_le
        _ ≤ ∑ _i : Fin querySlots, R.queryBudget :=
          Finset.sum_le_sum fun i _ ↦ R.query_card i
        _ = querySlots * R.queryBudget := by simp

theorem rom_compiler_ratio_le [Nonempty Ω]
    (R : UnifiedRigidAttribution Ω querySlots) :
    ((Finset.filter R.win Finset.univ).card : ℚ) / Fintype.card Ω ≤
      (R.bindBudget + querySlots * R.queryBudget : ℕ) /
        (Fintype.card Ω : ℚ) := by
  have hΩ : (0 : ℚ) < Fintype.card Ω := by exact_mod_cast Fintype.card_pos
  exact div_le_div_of_nonneg_right
    (by exact_mod_cast R.rom_compiler_card_le) hΩ.le

end UnifiedRigidAttribution

/-! ## Exact-density unified query-slot ledger -/

/-- Rational form of the unified ledger.  It accepts exact per-slot densities,
so profile integrals need not be rounded to natural cardinality budgets. -/
structure UnifiedRigidRatioAttribution
    (Ω : Type*) (querySlots : ℕ) [Fintype Ω] where
  winSet : Finset Ω
  bindSet : Finset Ω
  querySet : Fin querySlots → Finset Ω
  bindEpsilon : ℚ
  queryEpsilon : ℚ
  cover : ∀ ω ∈ winSet, ω ∈ bindSet ∨ ∃ i, ω ∈ querySet i
  bind_ratio : (bindSet.card : ℚ) / Fintype.card Ω ≤ bindEpsilon
  query_ratio : ∀ i, ((querySet i).card : ℚ) /
    Fintype.card Ω ≤ queryEpsilon

namespace FirstOccurrenceTrace

variable {Ω Query : Type*} [Fintype Ω] [BEq Query] [LawfulBEq Query]
variable {querySlots : ℕ}

/-- Canonical first-occurrence adapter for exact per-slot densities. -/
def toUnifiedRigidRatioAttribution [Nonempty Ω]
    (F : FirstOccurrenceTrace Ω Query querySlots)
    (listed win bindBreak : Ω → Prop)
    (queryCase : Fin querySlots → Ω → Prop)
    (winSet bindSet : Finset Ω) (querySet : Fin querySlots → Finset Ω)
    (hwinSet : ∀ ω, ω ∈ winSet ↔ win ω)
    (hbindSet : ∀ ω, ω ∈ bindSet ↔ bindBreak ω)
    (hquerySet : ∀ i ω, ω ∈ querySet i ↔ queryCase i ω)
    (hcase : ∀ i ω, queryCase i ω ↔
      F.caseA listed win bindBreak i ω ∨ F.caseB win bindBreak i ω)
    (bindEpsilon queryEpsilon : ℚ)
    (hbind : (bindSet.card : ℚ) / Fintype.card Ω ≤ bindEpsilon)
    (hquery : ∀ i, ((querySet i).card : ℚ) /
      Fintype.card Ω ≤ queryEpsilon) :
    UnifiedRigidRatioAttribution Ω querySlots where
  winSet := winSet
  bindSet := bindSet
  querySet := querySet
  bindEpsilon := bindEpsilon
  queryEpsilon := queryEpsilon
  cover ω hω := by
    have hwin := (hwinSet ω).1 hω
    by_cases hbindω : bindBreak ω
    · exact Or.inl ((hbindSet ω).2 hbindω)
    right
    rcases lt_or_gt_of_ne (F.idxOf_ne ω) with hbefore | hafter
    · by_cases hlisted : listed ω
      · exact ⟨F.alphaSlot ω, (hquerySet (F.alphaSlot ω) ω).2
          ((hcase (F.alphaSlot ω) ω).2 (Or.inl
            ⟨hwin, hbindω, hbefore, Or.inr ⟨hlisted, rfl⟩⟩))⟩
      · exact ⟨F.subsetSlot ω, (hquerySet (F.subsetSlot ω) ω).2
          ((hcase (F.subsetSlot ω) ω).2 (Or.inl
            ⟨hwin, hbindω, hbefore, Or.inl ⟨hlisted, rfl⟩⟩))⟩
    · exact ⟨F.subsetSlot ω, (hquerySet (F.subsetSlot ω) ω).2
        ((hcase (F.subsetSlot ω) ω).2
          (Or.inr ⟨hwin, hbindω, rfl, hafter⟩))⟩
  bind_ratio := hbind
  query_ratio := hquery

end FirstOccurrenceTrace

namespace UnifiedRigidRatioAttribution

variable {Ω : Type*} [Fintype Ω] [Nonempty Ω] {querySlots : ℕ}

/-- Exact rational ROM union: binding once and one unified A/B density per
possible first-occurrence slot. -/
theorem rom_compiler_ratio_le
    (R : UnifiedRigidRatioAttribution Ω querySlots) :
    (R.winSet.card : ℚ) / Fintype.card Ω ≤
      R.bindEpsilon + querySlots * R.queryEpsilon := by
  classical
  let cases : Finset Ω := Finset.biUnion Finset.univ
    (fun i ↦ R.querySet i)
  have hcover : R.winSet.card ≤ R.bindSet.card + cases.card := by
    calc
      R.winSet.card ≤ (R.bindSet ∪ cases).card := by
        apply Finset.card_le_card
        intro ω hω
        rcases R.cover ω hω with hbind | ⟨i, hi⟩
        · exact Finset.mem_union_left _ hbind
        · exact Finset.mem_union_right _
            (Finset.mem_biUnion.mpr ⟨i, Finset.mem_univ _, hi⟩)
      _ ≤ R.bindSet.card + cases.card :=
        Finset.card_union_le _ _
  have hcases : ((cases.card : ℚ) / Fintype.card Ω) ≤
      querySlots * R.queryEpsilon := by
    have hcard : cases.card ≤ ∑ i : Fin querySlots,
        (R.querySet i).card := by
      exact Finset.card_biUnion_le
    have hΩ : (0 : ℚ) < Fintype.card Ω := by
      exact_mod_cast Fintype.card_pos
    calc
      (cases.card : ℚ) / Fintype.card Ω ≤
          ((∑ i : Fin querySlots,
            (R.querySet i).card : ℕ) : ℚ) /
              Fintype.card Ω :=
        div_le_div_of_nonneg_right (by exact_mod_cast hcard) hΩ.le
      _ = ∑ i : Fin querySlots,
          ((R.querySet i).card : ℚ) /
            Fintype.card Ω := by
        push_cast
        simp only [div_eq_mul_inv]
        rw [Finset.sum_mul]
      _ ≤ ∑ _i : Fin querySlots, R.queryEpsilon :=
        Finset.sum_le_sum (fun i _ ↦ R.query_ratio i)
      _ = querySlots * R.queryEpsilon := by simp
  have hΩ : (0 : ℚ) < Fintype.card Ω := by
    exact_mod_cast Fintype.card_pos
  calc
    (R.winSet.card : ℚ) / Fintype.card Ω ≤
        ((R.bindSet.card + cases.card : ℕ) : ℚ) /
          Fintype.card Ω :=
      div_le_div_of_nonneg_right (by exact_mod_cast hcover) hΩ.le
    _ = (R.bindSet.card : ℚ) /
          Fintype.card Ω + (cases.card : ℚ) / Fintype.card Ω := by
      push_cast
      ring
    _ ≤ R.bindEpsilon + querySlots * R.queryEpsilon :=
      add_le_add R.bind_ratio hcases

end UnifiedRigidRatioAttribution

/-! ## The chained compiler bound

Stated here rather than beside `ChainedTrace` because it consumes
`RigidAttribution.rom_compiler_card_le`. -/

namespace ChainedTrace

variable {Ω Query : Type*} [Fintype Ω] [BEq Query] [LawfulBEq Query]
variable {querySlots : ℕ}

/-- **The chained response-rigid ROM compiler.**

`Bcs.RigidAttribution.rom_compiler_card_le` with the case-B term gone: the union
bound is over the binding failure and the two case-A charges only.  Nothing else
about the accounting changes -- the floor is still charged at the fresh `H₂` slot
and the listed excess at the fresh `H₁` slot.
-/
theorem rom_compiler_card_le (F : ChainedTrace Ω Query querySlots)
    (listed win bindBreak : Ω → Prop)
    (bindBudget caseAFloorBudget caseAListedBudget : ℕ)
    (hbind : (Finset.filter bindBreak Finset.univ).card ≤ bindBudget)
    (hcaseA : ∀ i, (Finset.filter (F.caseA listed win bindBreak i) Finset.univ).card ≤
      caseAFloorBudget + caseAListedBudget) :
    (Finset.filter win Finset.univ).card ≤
      bindBudget + querySlots * (caseAFloorBudget + caseAListedBudget) := by
  have h := (F.toRigidAttribution listed win bindBreak bindBudget caseAFloorBudget
    caseAListedBudget hbind hcaseA).rom_compiler_card_le
  simpa [toRigidAttribution, FirstOccurrenceTrace.toRigidAttribution] using h

/-- Probability form. -/
theorem rom_compiler_ratio_le [Nonempty Ω] (F : ChainedTrace Ω Query querySlots)
    (listed win bindBreak : Ω → Prop)
    (bindBudget caseAFloorBudget caseAListedBudget : ℕ)
    (hbind : (Finset.filter bindBreak Finset.univ).card ≤ bindBudget)
    (hcaseA : ∀ i, (Finset.filter (F.caseA listed win bindBreak i) Finset.univ).card ≤
      caseAFloorBudget + caseAListedBudget) :
    ((Finset.filter win Finset.univ).card : ℚ) / Fintype.card Ω ≤
      (bindBudget + querySlots * (caseAFloorBudget + caseAListedBudget) : ℕ) /
        (Fintype.card Ω : ℚ) := by
  have hΩ : (0 : ℚ) < Fintype.card Ω := by exact_mod_cast Fintype.card_pos
  have hcard := F.rom_compiler_card_le listed win bindBreak bindBudget
    caseAFloorBudget caseAListedBudget hbind hcaseA
  exact div_le_div_of_nonneg_right (by exact_mod_cast hcard) (le_of_lt hΩ)

end ChainedTrace

end Bcs
