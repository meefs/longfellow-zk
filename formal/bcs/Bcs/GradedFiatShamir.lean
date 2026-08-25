import Bcs.GradedRoundByRound
import Merkle.LazyTape

/-!
# Discharging `escape`: a grinding adversary is a graded pair

`Bcs.GradedPair` takes `escape` as a field, and this file supplies it for a Fiat--Shamir
adversary: an adaptive `Tree` over the challenge oracle, grinding as much as its budget allows.
This is the graded twin of `Bcs.Grinding.toRbrCore`, and it is where the two grinding strategies
of a two-round protocol -- get lucky on the first challenge, or grind the second -- are shown to
be the *same* event at two slots rather than two separate bad events.

## Why the two ascents are per-query, not per-round

Under Fiat--Shamir a query point **is** a transcript prefix, so "this partial transcript sits at
level `v`" is a predicate on the query, with no history argument.  That is what makes
`Ascend1Query : Q → C → V → Prop` and `Ascend2Query : Q → C → V → Prop` the right types, and it
is why the Ligero adapter does not need a `challengeOfHistory`: the second query point
`H₂(x, root, alpha, response)` carries `alpha`, hence carries its own level.

## What is proved here

Target 6.1's two-round instance -- the pair count at `reach v` rather than `T` -- is
`pair_with_successors_card_le`, and `toGradedPair` discharges `GradedPair.pair_card` from it.  The
counting core is `sum_card_query_budget_le` / `sum_card_query_budget_inter_le`, built on
`slotQuery_disjoint` (from `Merkle.lazyRun_seen_nodup`): a fixed query point occupies at most one
slot per tape, so summing over slots costs one copy of the budget rather than `T` copies.

The proof partitions over the first query point `q₁ ∈ Q`, not over the prefix at slot `i`.  A fiber
decomposition at slot `i` would have to relativise the whole argument to a shorter tape with a
shifted adversary; the events "slot `i`'s query is `q₁` and its answer ascends" are instead
*disjoint over* `q₁`, so their counts sum to one slot-`i` budget.

## The one step that is not a count

`chain` is the deterministic content -- an accepting proof on which extraction failed queried a
point whose answer set the level, and *later* a point at that level whose answer accepted.  It is a
field for the same reason `Bcs.Grinding.chain` is: it is where the protocol's own reasoning and the
verifier's recomputation go.  Everything else here is the conversion from "some **queried point**"
to "some **slot**", which is `Merkle.RandomOracle.slotQuery_eq` and nothing else, applied twice.

`chain` carries the slot order `i < j` because the compiler chains: `H₂`'s input contains `H₁`'s
answer, so the second query cannot occupy the earlier slot.  That is the same fact
`Bcs.ChainedTrace.chained` records, one abstraction down.
-/

set_option autoImplicit false
set_option relaxedAutoImplicit false

namespace Bcs

open Finset Merkle.RandomOracle
open scoped Classical

/--
**A grinding Fiat--Shamir adversary against a two-ascent state function.**

`adversary` is the adaptive program, `t` bounds its queries and `T` the tape.  `Ascend1Query q c v`
says the answer `c` at point `q` puts the state at level `v`; `Ascend2Query q c v` says `q` sits at
level `v` and the answer `c` makes the verifier accept.
-/
structure GradedGrinding (C : Type) [Fintype C] (Q A : Type) [DecidableEq Q] [Fintype Q]
    (V : Type) [Fintype V] [DecidableEq V] (t T : ℕ)
    (Accepts : (Fin T → C) → Prop) (Fails : Prop) where
  /-- The adaptive program, making at most `t` queries. -/
  adversary : Tree Q C A t
  /-- The answer an out-of-range slot would give; never read. -/
  dflt : C
  /-- The first ascent, at a query point. -/
  Ascend1Query : Q → C → V → Prop
  /-- The second ascent, at a query point that already sits at level `v`. -/
  Ascend2Query : Q → C → V → Prop
  /-- Per-level budget for the first ascent. -/
  beta1 : V → ℕ
  /-- Per-level budget for the second ascent. -/
  beta2 : V → ℕ
  /-- From any point, at most `beta1 v` answers reach level `v`. -/
  ascend1_bound : ∀ (q : Q) (v : V),
    (univ.filter fun c : C => Ascend1Query q c v).card ≤ beta1 v
  /-- From any level-`v` point, at most `beta2 v` answers accept. -/
  ascend2_bound : ∀ (q : Q) (v : V),
    (univ.filter fun c : C => Ascend2Query q c v).card ≤ beta2 v
  /-- **The reachable-successor bound.**  From a query point that has just reached level `v`, how
  many *digest-distinct* level-`v` follow-up points the adversary can form.

  This is where rigidity is spent, and chaining is load-bearing: because `H₂`'s input contains the
  batching challenge, a level-`v` successor of `q₁` is `(x, root, alpha, gamma)` with `alpha` pinned
  by `q₁`, so the successors are indexed by the valid responses at level `v` -- a list bound, not
  the adversary's query budget. -/
  reach : V → ℕ
  /-- The level-`v` successors of a point, as a finite set. -/
  successors : Q → V → Finset Q
  successors_card : ∀ (q : Q) (v : V), (successors q v).card ≤ reach v
  /-- The level whose accepting set absorbs a whole saturated family.  With a monotone cover this
  is the largest saturated level. -/
  topOf : Finset V → V
  /-- **The second ascent is nested in the level.**  An answer accepting at a saturated level also
  accepts at that family's top -- which is what a monotone cover means, and what lets the clamped
  charge be paid **once** rather than summed over levels.

  This is the factoring the clamp needs: `Ascend2Query` must be *purely* the acceptance event, with
  "the history sits at level `v`" carried by `successors` instead.  A predicate that pins the level
  exactly is not nested and cannot supply this. -/
  ascend2_nested : ∀ (sat : Finset V) (q : Q) (c : C) (v : V), v ∈ sat →
    Ascend2Query q c v → Ascend2Query q c (topOf sat)
  /-- The tape is long enough for a pair of distinct slots. -/
  two_le : 2 ≤ T
  /-- **The deterministic core.**  An accepting run on which extraction failed made both ascents,
  at two queried points, in slot order, with the second a level-`v` successor of the first. -/
  chain : ∀ tape : Fin T → C, Accepts tape → Fails →
    ∃ (v : V) (i j : Fin T) (q₁ q₂ : Q), i.val < j.val ∧
      (lazyRun tape dflt adversary []).2.1[i.val]? = some q₁ ∧
      (lazyRun tape dflt adversary []).2.1[j.val]? = some q₂ ∧
      q₂ ∈ successors q₁ v ∧
      Ascend1Query q₁ (tape i) v ∧ Ascend2Query q₂ (tape j) v

/--
**Slot-injectivity.**  A lazy run's seen-list is `Nodup` (`Merkle.lazyRun_seen_nodup`), so at most
`S.card` slots can carry a query drawn from `S`.

This is the ingredient the fan-out step needs: it is what turns "the adversary can form at most
`reach v` distinct level-`v` successor points" into "at most `reach v` *slots* can carry a level-`v`
second ascent".  Without it the union over second-ascent slots costs the whole tape length, which
is the difference between Target 6.1 and the inert `T²` bound.
-/
theorem card_slots_with_query_mem_le {Q : Type} [DecidableEq Q] {T : ℕ}
    (L : List Q) (hnodup : L.Nodup) (S : Finset Q) :
    (univ.filter fun j : Fin T => ∃ q ∈ S, L[j.val]? = some q).card ≤ S.card := by
  classical
  rcases S.eq_empty_or_nonempty with rfl | ⟨q0, hq0⟩
  · simp
  · refine Finset.card_le_card_of_injOn (fun j => (L[j.val]?).getD q0) ?_ ?_
    · intro j hj
      obtain ⟨q, hqS, hq⟩ := (Finset.mem_filter.mp hj).2
      simpa [hq] using hqS
    · intro a ha b hb hab
      have hab' : (L[a.val]?).getD q0 = (L[b.val]?).getD q0 := hab
      obtain ⟨qa, -, hqa⟩ := (Finset.mem_filter.mp (Finset.mem_coe.mp ha)).2
      obtain ⟨qb, -, hqb⟩ := (Finset.mem_filter.mp (Finset.mem_coe.mp hb)).2
      rw [hqa, hqb] at hab'
      have hq : qa = qb := by simpa using hab'
      have hga : L[a.val]? = L[b.val]? := by rw [hqa, hqb, hq]
      obtain ⟨hlt, -⟩ := List.getElem?_eq_some_iff.mp hqa
      exact Fin.ext ((List.getElem?_inj hlt hnodup).mp hga)

/-! ## The per-query disjointness core

The counting step that makes the fan-out worth anything.  A union bound over the tape's `T` slots
would charge the adversary's whole query budget; what is true instead is that a *fixed* query point
occupies at most one slot per tape, so summing over slots costs `1`, not `T`.
-/

section PerQuery

variable {C Q A : Type} [Fintype C] [DecidableEq C] [DecidableEq Q] {t T : ℕ}

omit [Fintype C] [DecidableEq C] in
/-- `slotQuery` at a slot of a real tape is that slot's entry in the run's seen-list. -/
theorem slotQuery_at_slot (dflt : C) (adv : Tree Q C A t) (tape : Fin T → C) (i : Fin T) :
    slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape i)
      = (lazyRun tape dflt adv []).2.1[i.val]? := by
  rw [show Sumcheck.extract_prefix tape i
      = (fun l : Fin i.val => tape ⟨l.val, lt_trans l.isLt i.isLt⟩) from rfl]
  exact slotQuery_eq dflt adv (le_of_lt i.isLt) tape

omit [DecidableEq C] in
/-- **One query, one slot.**  The tapes putting `q` at slot `j₁` and those putting it at `j₂` are
disjoint when `j₁ ≠ j₂`: the seen-list has no duplicates. -/
theorem slotQuery_disjoint (dflt : C) (adv : Tree Q C A t) (q : Q) {j₁ j₂ : Fin T}
    (hne : j₁ ≠ j₂) :
    Disjoint
      (univ.filter fun tape : Fin T → C =>
        slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j₁) = some q)
      (univ.filter fun tape : Fin T → C =>
        slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j₂) = some q) := by
  classical
  rw [Finset.disjoint_left]
  intro tape h1 h2
  simp only [mem_filter, mem_univ, true_and] at h1 h2
  rw [slotQuery_at_slot dflt adv tape j₁] at h1
  rw [slotQuery_at_slot dflt adv tape j₂] at h2
  have hnodup : ((lazyRun tape dflt adv []).2.1).Nodup :=
    lazyRun_seen_nodup tape dflt adv [] List.nodup_nil
  obtain ⟨hlt, -⟩ := List.getElem?_eq_some_iff.mp h1
  exact hne (Fin.ext ((List.getElem?_inj hlt hnodup).mp (h1.trans h2.symm)))

/-- **Summing over slots costs one tape's worth, not `T`.** -/
theorem sum_card_slotQuery_le (dflt : C) (adv : Tree Q C A t) (q : Q) :
    ∑ j : Fin T, (univ.filter fun tape : Fin T → C =>
        slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q).card
      ≤ Fintype.card C ^ T := by
  classical
  rw [← Finset.card_biUnion (fun j₁ _ j₂ _ hne => slotQuery_disjoint dflt adv q hne)]
  calc (Finset.biUnion (univ : Finset (Fin T)) fun j =>
        univ.filter fun tape : Fin T → C =>
          slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q).card
      ≤ (univ : Finset (Fin T → C)).card := Finset.card_le_card (Finset.subset_univ _)
    _ = Fintype.card C ^ T := by simp

/-- **The budget cuts each slot's share by `beta / |C|`.**  Stated multiplied out, so no division. -/
theorem card_slot_budget_mul_le (dflt : C) (adv : Tree Q C A t) (q : Q) (j : Fin T)
    (P : (Fin j.val → C) → C → Prop) (beta : ℕ)
    (hP : ∀ pref : Fin j.val → C, (univ.filter fun c => P pref c).card ≤ beta) :
    (univ.filter fun tape : Fin T → C =>
        slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
          P (Sumcheck.extract_prefix tape j) (tape j)).card * Fintype.card C
      ≤ beta * (univ.filter fun tape : Fin T → C =>
        slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q).card := by
  classical
  have hA : (univ.filter fun tape : Fin T → C =>
        slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
          P (Sumcheck.extract_prefix tape j) (tape j)).card
      ≤ (univ.filter fun pr : (Fin j.val → C) × C =>
          slotQuery (T := T) dflt adv pr.1 = some q ∧ P pr.1 pr.2).card *
            Fintype.card C ^ (T - 1 - j.val) := by
    refine le_trans (le_trans (Finset.card_le_card ?_)
      (le_of_eq (Sumcheck.card_filter_prefix_r T j
        (fun pref c => slotQuery (T := T) dflt adv pref = some q ∧ P pref c))))
      (by gcongr)
    intro x hx
    simp only [mem_filter, mem_univ, true_and] at hx ⊢
    exact hx
  have hB : (univ.filter fun pr : (Fin j.val → C) × C =>
          slotQuery (T := T) dflt adv pr.1 = some q).card *
            Fintype.card C ^ (T - 1 - j.val)
      ≤ (univ.filter fun tape : Fin T → C =>
          slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q).card := by
    refine le_trans (by gcongr)
      (le_trans (le_of_eq (Sumcheck.card_filter_prefix_r T j
        (fun pref (_ : C) => slotQuery (T := T) dflt adv pref = some q)).symm)
        (Finset.card_le_card ?_))
    intro x hx
    simp only [mem_filter, mem_univ, true_and] at hx ⊢
    exact hx
  have key : (univ.filter fun pr : (Fin j.val → C) × C =>
        slotQuery (T := T) dflt adv pr.1 = some q ∧ P pr.1 pr.2).card * Fintype.card C
      ≤ beta * (univ.filter fun pr : (Fin j.val → C) × C =>
          slotQuery (T := T) dflt adv pr.1 = some q).card := by
    rw [Bcs.card_filter_prod_fst (fun pr : (Fin j.val → C) × C =>
        slotQuery (T := T) dflt adv pr.1 = some q ∧ P pr.1 pr.2),
      Bcs.card_filter_prod_fst (fun pr : (Fin j.val → C) × C =>
        slotQuery (T := T) dflt adv pr.1 = some q)]
    rw [Finset.sum_mul, Finset.mul_sum]
    refine Finset.sum_le_sum ?_
    intro pref _
    by_cases hq : slotQuery (T := T) dflt adv pref = some q
    · have hleft : (univ.filter fun c : C =>
          slotQuery (T := T) dflt adv pref = some q ∧ P pref c)
          = univ.filter fun c : C => P pref c := by
        apply Finset.filter_congr
        intro c _
        simp [hq]
      have hright : (univ.filter fun c : C =>
          slotQuery (T := T) dflt adv pref = some q) = (univ : Finset C) :=
        Finset.filter_true_of_mem fun c _ => hq
      rw [hleft, hright, Finset.card_univ]
      exact Nat.mul_le_mul_right _ (hP pref)
    · have hleft : (univ.filter fun c : C =>
          slotQuery (T := T) dflt adv pref = some q ∧ P pref c) = ∅ :=
        Finset.filter_false_of_mem fun c _ hcon => hq hcon.1
      simp [hleft]
  calc (univ.filter fun tape : Fin T → C =>
        slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
          P (Sumcheck.extract_prefix tape j) (tape j)).card * Fintype.card C
      ≤ ((univ.filter fun pr : (Fin j.val → C) × C =>
          slotQuery (T := T) dflt adv pr.1 = some q ∧ P pr.1 pr.2).card *
            Fintype.card C ^ (T - 1 - j.val)) * Fintype.card C := by gcongr
    _ = ((univ.filter fun pr : (Fin j.val → C) × C =>
          slotQuery (T := T) dflt adv pr.1 = some q ∧ P pr.1 pr.2).card * Fintype.card C) *
            Fintype.card C ^ (T - 1 - j.val) := by ring
    _ ≤ (beta * (univ.filter fun pr : (Fin j.val → C) × C =>
          slotQuery (T := T) dflt adv pr.1 = some q).card) *
            Fintype.card C ^ (T - 1 - j.val) := by gcongr
    _ = beta * ((univ.filter fun pr : (Fin j.val → C) × C =>
          slotQuery (T := T) dflt adv pr.1 = some q).card *
            Fintype.card C ^ (T - 1 - j.val)) := by ring
    _ ≤ beta * (univ.filter fun tape : Fin T → C =>
          slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q).card := by
        gcongr

/-- **Disjointness, with an arbitrary side event.**  Summing over slots costs one copy of any
event the summands are contained in -- not `T` copies. -/
theorem sum_card_slotQuery_subset_le (dflt : C) (adv : Tree Q C A t) (q : Q)
    (Ev : Fin T → (Fin T → C) → Prop) (R : (Fin T → C) → Prop)
    (hsub : ∀ (j : Fin T) (tape : Fin T → C),
      slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q →
        Ev j tape → R tape) :
    ∑ j : Fin T, (univ.filter fun tape : Fin T → C =>
        slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
          Ev j tape).card
      ≤ (univ.filter R).card := by
  classical
  have hdisj : ∀ j₁ ∈ (univ : Finset (Fin T)), ∀ j₂ ∈ (univ : Finset (Fin T)), j₁ ≠ j₂ →
      Disjoint
        (univ.filter fun tape : Fin T → C =>
          slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j₁) = some q ∧ Ev j₁ tape)
        (univ.filter fun tape : Fin T → C =>
          slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j₂) = some q ∧
            Ev j₂ tape) := by
    intro j₁ _ j₂ _ hne
    refine Finset.disjoint_left.mpr ?_
    intro tape h1 h2
    simp only [mem_filter, mem_univ, true_and] at h1 h2
    exact (Finset.disjoint_left.mp (slotQuery_disjoint dflt adv q hne))
      (mem_filter.mpr ⟨mem_univ _, h1.1⟩) (mem_filter.mpr ⟨mem_univ _, h2.1⟩)
  rw [← Finset.card_biUnion hdisj]
  apply Finset.card_le_card
  intro tape htape
  obtain ⟨j, -, hj⟩ := Finset.mem_biUnion.mp htape
  simp only [mem_filter, mem_univ, true_and] at hj ⊢
  exact hsub j tape hj.1 hj.2

/-- **The budget step, with a prefix-measurable side condition.**  `S` is read off the prefix at
the same slot, so it survives the fiber decomposition untouched. -/
theorem card_slot_budget_inter_mul_le (dflt : C) (adv : Tree Q C A t) (q : Q) (j : Fin T)
    (S : (Fin j.val → C) → Prop) (P : (Fin j.val → C) → C → Prop) (beta : ℕ)
    (hP : ∀ pref : Fin j.val → C, (univ.filter fun c => P pref c).card ≤ beta) :
    (univ.filter fun tape : Fin T → C =>
        (slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
            S (Sumcheck.extract_prefix tape j)) ∧
          P (Sumcheck.extract_prefix tape j) (tape j)).card * Fintype.card C
      ≤ beta * (univ.filter fun tape : Fin T → C =>
        slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
          S (Sumcheck.extract_prefix tape j)).card := by
  classical
  have hA : (univ.filter fun tape : Fin T → C =>
        (slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
            S (Sumcheck.extract_prefix tape j)) ∧
          P (Sumcheck.extract_prefix tape j) (tape j)).card
      ≤ (univ.filter fun pr : (Fin j.val → C) × C =>
          (slotQuery (T := T) dflt adv pr.1 = some q ∧ S pr.1) ∧ P pr.1 pr.2).card *
            Fintype.card C ^ (T - 1 - j.val) := by
    refine le_trans (le_trans (Finset.card_le_card ?_)
      (le_of_eq (Sumcheck.card_filter_prefix_r T j
        (fun pref c => (slotQuery (T := T) dflt adv pref = some q ∧ S pref) ∧ P pref c))))
      (by gcongr)
    intro x hx
    simp only [mem_filter, mem_univ, true_and] at hx ⊢
    exact hx
  have hB : (univ.filter fun pr : (Fin j.val → C) × C =>
          slotQuery (T := T) dflt adv pr.1 = some q ∧ S pr.1).card *
            Fintype.card C ^ (T - 1 - j.val)
      ≤ (univ.filter fun tape : Fin T → C =>
          slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
            S (Sumcheck.extract_prefix tape j)).card := by
    refine le_trans (by gcongr)
      (le_trans (le_of_eq (Sumcheck.card_filter_prefix_r T j
        (fun pref (_ : C) => slotQuery (T := T) dflt adv pref = some q ∧ S pref)).symm)
        (Finset.card_le_card ?_))
    intro x hx
    simp only [mem_filter, mem_univ, true_and] at hx ⊢
    exact hx
  have key : (univ.filter fun pr : (Fin j.val → C) × C =>
        (slotQuery (T := T) dflt adv pr.1 = some q ∧ S pr.1) ∧ P pr.1 pr.2).card *
          Fintype.card C
      ≤ beta * (univ.filter fun pr : (Fin j.val → C) × C =>
          slotQuery (T := T) dflt adv pr.1 = some q ∧ S pr.1).card := by
    rw [Bcs.card_filter_prod_fst (fun pr : (Fin j.val → C) × C =>
        (slotQuery (T := T) dflt adv pr.1 = some q ∧ S pr.1) ∧ P pr.1 pr.2),
      Bcs.card_filter_prod_fst (fun pr : (Fin j.val → C) × C =>
        slotQuery (T := T) dflt adv pr.1 = some q ∧ S pr.1)]
    rw [Finset.sum_mul, Finset.mul_sum]
    refine Finset.sum_le_sum ?_
    intro pref _
    by_cases hq : slotQuery (T := T) dflt adv pref = some q ∧ S pref
    · have hleft : (univ.filter fun c : C =>
          (slotQuery (T := T) dflt adv pref = some q ∧ S pref) ∧ P pref c)
          = univ.filter fun c : C => P pref c := by
        apply Finset.filter_congr
        intro c _
        simp [hq]
      have hright : (univ.filter fun c : C =>
          slotQuery (T := T) dflt adv pref = some q ∧ S pref) = (univ : Finset C) :=
        Finset.filter_true_of_mem fun c _ => hq
      rw [hleft, hright, Finset.card_univ]
      exact Nat.mul_le_mul_right _ (hP pref)
    · have hleft : (univ.filter fun c : C =>
          (slotQuery (T := T) dflt adv pref = some q ∧ S pref) ∧ P pref c) = ∅ :=
        Finset.filter_false_of_mem fun c _ hcon => hq hcon.1
      simp [hleft]
  calc (univ.filter fun tape : Fin T → C =>
        (slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
            S (Sumcheck.extract_prefix tape j)) ∧
          P (Sumcheck.extract_prefix tape j) (tape j)).card * Fintype.card C
      ≤ ((univ.filter fun pr : (Fin j.val → C) × C =>
          (slotQuery (T := T) dflt adv pr.1 = some q ∧ S pr.1) ∧ P pr.1 pr.2).card *
            Fintype.card C ^ (T - 1 - j.val)) * Fintype.card C := by gcongr
    _ = ((univ.filter fun pr : (Fin j.val → C) × C =>
          (slotQuery (T := T) dflt adv pr.1 = some q ∧ S pr.1) ∧ P pr.1 pr.2).card *
            Fintype.card C) * Fintype.card C ^ (T - 1 - j.val) := by ring
    _ ≤ (beta * (univ.filter fun pr : (Fin j.val → C) × C =>
          slotQuery (T := T) dflt adv pr.1 = some q ∧ S pr.1).card) *
            Fintype.card C ^ (T - 1 - j.val) := by gcongr
    _ = beta * ((univ.filter fun pr : (Fin j.val → C) × C =>
          slotQuery (T := T) dflt adv pr.1 = some q ∧ S pr.1).card *
            Fintype.card C ^ (T - 1 - j.val)) := by ring
    _ ≤ beta * (univ.filter fun tape : Fin T → C =>
          slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
            S (Sumcheck.extract_prefix tape j)).card := by gcongr

/--
**The per-query bound with a side event.**  For one query point `q`, one prefix-measurable side
condition `S`, and any tape-level event `R` the side conditions imply:

`(∑_j #{ slot j carries q ∧ S ∧ P_j }) * |C| ≤ beta * #{R}`.

At `R := #{ the first ascent happened at slot i }`, whose own count is `beta1 * |C|^(T-1)`, this is
the composition step: it turns the pair into `beta1 * beta2 * |C|^(T-2)` *per query point*, so
unioning over the `reach v` successors gives Target 6.1's factor.
-/
theorem sum_card_query_budget_inter_le (dflt : C) (adv : Tree Q C A t) (q : Q)
    (S : ∀ j : Fin T, (Fin j.val → C) → Prop)
    (P : ∀ j : Fin T, (Fin j.val → C) → C → Prop) (beta : ℕ)
    (hP : ∀ (j : Fin T) (pref : Fin j.val → C),
      (univ.filter fun c => P j pref c).card ≤ beta)
    (R : (Fin T → C) → Prop)
    (hSR : ∀ (j : Fin T) (tape : Fin T → C),
      slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q →
        S j (Sumcheck.extract_prefix tape j) → R tape) :
    (∑ j : Fin T, (univ.filter fun tape : Fin T → C =>
        (slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
            S j (Sumcheck.extract_prefix tape j)) ∧
          P j (Sumcheck.extract_prefix tape j) (tape j)).card) * Fintype.card C
      ≤ beta * (univ.filter R).card := by
  classical
  calc (∑ j : Fin T, (univ.filter fun tape : Fin T → C =>
        (slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
            S j (Sumcheck.extract_prefix tape j)) ∧
          P j (Sumcheck.extract_prefix tape j) (tape j)).card) * Fintype.card C
      = ∑ j : Fin T, ((univ.filter fun tape : Fin T → C =>
          (slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
              S j (Sumcheck.extract_prefix tape j)) ∧
            P j (Sumcheck.extract_prefix tape j) (tape j)).card * Fintype.card C) := by
        rw [Finset.sum_mul]
    _ ≤ ∑ j : Fin T, beta * (univ.filter fun tape : Fin T → C =>
          slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
            S j (Sumcheck.extract_prefix tape j)).card :=
        Finset.sum_le_sum fun j _ =>
          card_slot_budget_inter_mul_le dflt adv q j (S j) (P j) beta (hP j)
    _ = beta * ∑ j : Fin T, (univ.filter fun tape : Fin T → C =>
          slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
            S j (Sumcheck.extract_prefix tape j)).card := by rw [Finset.mul_sum]
    _ ≤ beta * (univ.filter R).card := by
        refine Nat.mul_le_mul_left _ ?_
        exact sum_card_slotQuery_subset_le dflt adv q
          (fun j tape => S j (Sumcheck.extract_prefix tape j)) R hSR

/--
**The per-query bound.**  Over all slots, a fixed query point contributes at most
`beta * |C|^(T-1)` -- one slot's worth, not `T`.

This is the lemma the fan-out step is built from: unioning it over the at most `reach v` level-`v`
successors gives `reach v * beta * |C|^(T-1)` where a slot union bound would have given
`T * beta * |C|^(T-1)`.
-/
theorem sum_card_query_budget_le (dflt : C) (adv : Tree Q C A t) (q : Q)
    (P : ∀ j : Fin T, (Fin j.val → C) → C → Prop) (beta : ℕ)
    (hP : ∀ (j : Fin T) (pref : Fin j.val → C),
      (univ.filter fun c => P j pref c).card ≤ beta) (hT : 1 ≤ T) :
    ∑ j : Fin T, (univ.filter fun tape : Fin T → C =>
        slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
          P j (Sumcheck.extract_prefix tape j) (tape j)).card
      ≤ beta * Fintype.card C ^ (T - 1) := by
  classical
  have hCpos : 0 < Fintype.card C := Fintype.card_pos_iff.mpr ⟨dflt⟩
  have hpow : Fintype.card C ^ T = Fintype.card C ^ (T - 1) * Fintype.card C := by
    rw [← pow_succ]; congr 1; omega
  refine Nat.le_of_mul_le_mul_right ?_ hCpos
  calc (∑ j : Fin T, (univ.filter fun tape : Fin T → C =>
          slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
            P j (Sumcheck.extract_prefix tape j) (tape j)).card) * Fintype.card C
      = ∑ j : Fin T, ((univ.filter fun tape : Fin T → C =>
          slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
            P j (Sumcheck.extract_prefix tape j) (tape j)).card * Fintype.card C) := by
        rw [Finset.sum_mul]
    _ ≤ ∑ j : Fin T, beta * (univ.filter fun tape : Fin T → C =>
          slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q).card :=
        Finset.sum_le_sum fun j _ =>
          card_slot_budget_mul_le dflt adv q j (P j) beta (hP j)
    _ = beta * ∑ j : Fin T, (univ.filter fun tape : Fin T → C =>
          slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q).card := by
        rw [Finset.mul_sum]
    _ ≤ beta * Fintype.card C ^ T :=
        Nat.mul_le_mul_left _ (sum_card_slotQuery_le dflt adv q)
    _ = beta * Fintype.card C ^ (T - 1) * Fintype.card C := by rw [hpow]; ring

/-- The first ascent's data, read off a *later* slot's prefix.  Stated as an existential over the
order proof rather than a `dite`, so destructuring it is one `obtain`. -/
def sideAt {C Q A : Type} [DecidableEq Q] {t T : ℕ} (dflt : C) (adv : Tree Q C A t)
    (A1 : Q → C → Prop) (i : Fin T) (q₁ : Q) (j : Fin T) (pref : Fin j.val → C) : Prop :=
  ∃ h : i.val < j.val,
    slotQuery (T := T) dflt adv (Sumcheck.extract_prefix pref ⟨i.val, h⟩) = some q₁ ∧
      A1 q₁ (pref ⟨i.val, h⟩)

/--
**The eligible-pair count: Target 6.1's two-round instance.**

For a fixed first-ascent slot `i`, the pair of ascents costs `reach * beta1 * beta2 * |C|^(T-2)` --
the *fan-out*, not the tape length.

The proof partitions over the first query point `q₁ ∈ Q` rather than over the prefix at slot `i`.
That is the step that makes it work: a fiber decomposition at slot `i` would have to relativise the
whole per-query argument to a shorter tape with a shifted adversary, whereas the events
`{ slot i's query is q₁ and its answer ascends }` are **disjoint over `q₁`**, so summing their
counts costs one copy of the slot-`i` budget rather than `|Q|` copies.  With `q₁` fixed the
successor set is fixed, and `sum_card_query_budget_inter_le` applies once per successor.
-/
theorem pair_with_successors_card_le [Fintype Q] (dflt : C) (adv : Tree Q C A t)
    (A1 A2 : Q → C → Prop) (succ : Q → Finset Q) (beta1 beta2 reach : ℕ)
    (hsucc : ∀ q₁ : Q, (succ q₁).card ≤ reach)
    (h1 : ∀ q : Q, (univ.filter fun c : C => A1 q c).card ≤ beta1)
    (h2 : ∀ q : Q, (univ.filter fun c : C => A2 q c).card ≤ beta2)
    (i : Fin T) (hT : 2 ≤ T) :
    (univ.filter fun tape : Fin T → C =>
      ∃ q₁ : Q, slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape i) = some q₁ ∧
        A1 q₁ (tape i) ∧
        ∃ (j : Fin T) (q₂ : Q), i.val < j.val ∧
          slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q₂ ∧
          q₂ ∈ succ q₁ ∧ A2 q₂ (tape j)).card
      ≤ reach * (beta1 * beta2) * Fintype.card C ^ (T - 2) := by
  classical
  have hCpos : 0 < Fintype.card C := Fintype.card_pos_iff.mpr ⟨dflt⟩
  -- the slot-`i` events, one per first query point
  set R : Q → (Fin T → C) → Prop := fun q₁ tape =>
    slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape i) = some q₁ ∧ A1 q₁ (tape i)
    with hR
  -- the side condition at a later slot, read off that slot's prefix
  -- STEP 1 : the slot-`i` events are disjoint over `q₁`, so their counts sum to one budget
  have step1 : ∑ q₁ : Q, (univ.filter (R q₁)).card ≤ beta1 * Fintype.card C ^ (T - 1) := by
    have hdisj : ∀ a ∈ (univ : Finset Q), ∀ b ∈ (univ : Finset Q), a ≠ b →
        Disjoint (univ.filter (R a)) (univ.filter (R b)) := by
      intro a _ b _ hne
      refine Finset.disjoint_left.mpr ?_
      intro tape ha hb
      simp only [hR, mem_filter, mem_univ, true_and] at ha hb
      exact hne (Option.some.inj (ha.1.symm.trans hb.1))
    rw [← Finset.card_biUnion hdisj]
    refine le_trans (Finset.card_le_card ?_)
      (Sumcheck.slot_bad_card_le i beta1
        (fun pref c => ∃ q₁ : Q, slotQuery (T := T) dflt adv pref = some q₁ ∧ A1 q₁ c) ?_)
    · intro tape htape
      obtain ⟨q₁, -, hq₁⟩ := Finset.mem_biUnion.mp htape
      simp only [hR, mem_filter, mem_univ, true_and] at hq₁ ⊢
      exact ⟨q₁, hq₁.1, hq₁.2⟩
    · intro pref
      by_cases hex : ∃ q₁ : Q, slotQuery (T := T) dflt adv pref = some q₁
      · obtain ⟨q₁, hq₁⟩ := hex
        refine le_trans (Finset.card_le_card ?_) (h1 q₁)
        intro c hc
        simp only [mem_filter, mem_univ, true_and] at hc ⊢
        obtain ⟨q', hq', hA⟩ := hc
        exact (Option.some.inj (hq'.symm.trans hq₁)) ▸ hA
      · refine le_trans (Finset.card_le_card (t := (∅ : Finset C)) ?_) (by simp)
        intro c hc
        simp only [mem_filter, mem_univ, true_and] at hc
        obtain ⟨q', hq', -⟩ := hc
        exact absurd ⟨q', hq'⟩ hex
  -- STEP 2 : one successor at a time
  have step2 : ∀ (q₁ q : Q),
      (∑ j : Fin T, (univ.filter fun tape : Fin T → C =>
          (slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
              sideAt dflt adv A1 i q₁ j (Sumcheck.extract_prefix tape j)) ∧
            A2 q (tape j)).card) * Fintype.card C
        ≤ beta2 * (univ.filter (R q₁)).card := by
    intro q₁ q
    refine le_trans (sum_card_query_budget_inter_le dflt adv q (sideAt dflt adv A1 i q₁)
      (fun _ _ c => A2 q c) beta2 (fun _ _ => h2 q) (R q₁)
      (fun j tape hsq hSj => by
        obtain ⟨hij, hq, hA⟩ := hSj
        exact ⟨hq, hA⟩)) ?_
    gcongr
  -- STEP 3 : cover, then assemble
  have hcover : (univ.filter fun tape : Fin T → C =>
      ∃ q₁ : Q, slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape i) = some q₁ ∧
        A1 q₁ (tape i) ∧
        ∃ (j : Fin T) (q₂ : Q), i.val < j.val ∧
          slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q₂ ∧
          q₂ ∈ succ q₁ ∧ A2 q₂ (tape j))
      ⊆ (univ : Finset Q).biUnion fun q₁ => (succ q₁).biUnion fun q =>
          (univ : Finset (Fin T)).biUnion fun j =>
            univ.filter fun tape : Fin T → C =>
              (slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
                  sideAt dflt adv A1 i q₁ j (Sumcheck.extract_prefix tape j)) ∧
                A2 q (tape j) := by
    intro tape htape
    simp only [mem_filter, mem_univ, true_and] at htape
    obtain ⟨q₁, hq₁, hA1, j, q₂, hij, hq₂, hmem, hA2⟩ := htape
    refine Finset.mem_biUnion.mpr ⟨q₁, mem_univ _, ?_⟩
    refine Finset.mem_biUnion.mpr ⟨q₂, hmem, ?_⟩
    refine Finset.mem_biUnion.mpr ⟨j, mem_univ _, ?_⟩
    simp only [mem_filter, mem_univ, true_and]
    exact ⟨⟨hq₂, hij, hq₁, hA1⟩, hA2⟩
  refine Nat.le_of_mul_le_mul_right ?_ hCpos
  have hpow : Fintype.card C ^ (T - 1) = Fintype.card C ^ (T - 2) * Fintype.card C := by
    rw [← pow_succ]; congr 1; omega
  calc (univ.filter fun tape : Fin T → C =>
        ∃ q₁ : Q, slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape i) = some q₁ ∧
          A1 q₁ (tape i) ∧
          ∃ (j : Fin T) (q₂ : Q), i.val < j.val ∧
            slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q₂ ∧
            q₂ ∈ succ q₁ ∧ A2 q₂ (tape j)).card * Fintype.card C
      ≤ (∑ q₁ : Q, ∑ q ∈ succ q₁, ∑ j : Fin T,
          (univ.filter fun tape : Fin T → C =>
            (slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
                sideAt dflt adv A1 i q₁ j (Sumcheck.extract_prefix tape j)) ∧
              A2 q (tape j)).card) * Fintype.card C := by
        refine Nat.mul_le_mul_right _ ?_
        refine le_trans (Finset.card_le_card hcover) ?_
        refine le_trans Finset.card_biUnion_le (Finset.sum_le_sum ?_)
        intro q₁ _
        refine le_trans Finset.card_biUnion_le (Finset.sum_le_sum ?_)
        intro q _
        exact Finset.card_biUnion_le
    _ = ∑ q₁ : Q, ∑ q ∈ succ q₁,
          ((∑ j : Fin T, (univ.filter fun tape : Fin T → C =>
            (slotQuery (T := T) dflt adv (Sumcheck.extract_prefix tape j) = some q ∧
                sideAt dflt adv A1 i q₁ j (Sumcheck.extract_prefix tape j)) ∧
              A2 q (tape j)).card) * Fintype.card C) := by
        rw [Finset.sum_mul]
        exact Finset.sum_congr rfl fun q₁ _ => by rw [Finset.sum_mul]
    _ ≤ ∑ q₁ : Q, ∑ _q ∈ succ q₁, beta2 * (univ.filter (R q₁)).card :=
        Finset.sum_le_sum fun q₁ _ => Finset.sum_le_sum fun q _ => step2 q₁ q
    _ = ∑ q₁ : Q, (succ q₁).card * (beta2 * (univ.filter (R q₁)).card) := by
        exact Finset.sum_congr rfl fun q₁ _ => by simp [Finset.sum_const]
    _ ≤ ∑ q₁ : Q, reach * (beta2 * (univ.filter (R q₁)).card) :=
        Finset.sum_le_sum fun q₁ _ => Nat.mul_le_mul_right _ (hsucc q₁)
    _ = reach * beta2 * ∑ q₁ : Q, (univ.filter (R q₁)).card := by
        rw [Finset.mul_sum]
        exact Finset.sum_congr rfl fun q₁ _ => by ring
    _ ≤ reach * beta2 * (beta1 * Fintype.card C ^ (T - 1)) := by gcongr
    _ = reach * (beta1 * beta2) * Fintype.card C ^ (T - 2) * Fintype.card C := by
        rw [hpow]; ring

end PerQuery

namespace GradedGrinding

variable {C Q A V : Type} [Fintype C] [DecidableEq C] [DecidableEq Q] [Fintype Q]
variable [Fintype V] [DecidableEq V]
variable {t T : ℕ} {Accepts : (Fin T → C) → Prop} {Fails : Prop}

/-- A per-slot ascent predicate: the query the adversary made at this slot, and what its answer
did.  Prefix-measurable by its type, because `slotQuery` reads only the prefix. -/
private def slotAscend (G : GradedGrinding C Q A V t T Accepts Fails)
    (P : Q → C → V → Prop) (m : ℕ) (pref : Fin m → C) (c : C) (v : V) : Prop :=
  ∃ q : Q, slotQuery (T := T) G.dflt G.adversary pref = some q ∧ P q c v

omit [DecidableEq C] in
/-- The budget transfers from query points to slots unchanged: a slot either carries a query, in
which case its escape set is that query's, or carries none, in which case it is empty. -/
private theorem slotAscend_card (G : GradedGrinding C Q A V t T Accepts Fails)
    (P : Q → C → V → Prop) (beta : V → ℕ)
    (hbound : ∀ (q : Q) (v : V), (univ.filter fun c : C => P q c v).card ≤ beta v)
    (m : ℕ) (pref : Fin m → C) (v : V) :
    (univ.filter fun c : C => G.slotAscend P m pref c v).card ≤ beta v := by
  classical
  by_cases hex : ∃ q : Q, slotQuery (T := T) G.dflt G.adversary pref = some q
  · obtain ⟨q, hq⟩ := hex
    refine le_trans (Finset.card_le_card
      (t := univ.filter fun c : C => P q c v) ?_) (hbound q v)
    intro c hc
    simp only [mem_filter, mem_univ, true_and, slotAscend] at hc ⊢
    obtain ⟨q', hq', hP⟩ := hc
    exact (Option.some.inj (hq'.symm.trans hq)) ▸ hP
  · refine le_trans (Finset.card_le_card (t := (∅ : Finset C)) ?_) (by simp)
    intro c hc
    simp only [mem_filter, mem_univ, true_and, slotAscend] at hc
    obtain ⟨q', hq', -⟩ := hc
    exact absurd ⟨q', hq'⟩ hex

omit [DecidableEq C] in
/-- The query at slot `i` of the real run, read off the prefix.  This is `slotQuery_eq` in the
form the two `escape` obligations consume. -/
private theorem slotQuery_at (G : GradedGrinding C Q A V t T Accepts Fails)
    (tape : Fin T → C) (i : Fin T) :
    slotQuery (T := T) G.dflt G.adversary (Sumcheck.extract_prefix tape i)
      = (lazyRun tape G.dflt G.adversary []).2.1[i.val]? := by
  rw [show Sumcheck.extract_prefix tape i
      = (fun l : Fin i.val => tape ⟨l.val, lt_trans l.isLt i.isLt⟩) from rfl]
  exact slotQuery_eq G.dflt G.adversary (le_of_lt i.isLt) tape

/--
**A grinding adversary is a graded pair.**

`escape` is discharged: `chain` names two queried points and `slotQuery_eq` turns them into two
slots.  The budgets are unchanged, so `GradedPair.graded_card_le` and `graded_ratio_le` apply at
the protocol's own per-level numbers -- and the `saturated` clamp is still free to be optimized by
the caller.
-/
noncomputable def toGradedPair (G : GradedGrinding C Q A V t T Accepts Fails) :
    GradedPair C V T Accepts Fails where
  ascend1 := G.slotAscend G.Ascend1Query
  ascend2 := G.slotAscend G.Ascend2Query
  beta1 := G.beta1
  beta2 := G.beta2
  ascend1_card m pref v :=
    G.slotAscend_card G.Ascend1Query G.beta1 G.ascend1_bound m pref v
  ascend2_card m pref v :=
    G.slotAscend_card G.Ascend2Query G.beta2 G.ascend2_bound m pref v
  Linked m₁ m₂ pref₁ pref₂ v :=
    ∃ q₁ q₂ : Q, slotQuery (T := T) G.dflt G.adversary pref₁ = some q₁ ∧
      slotQuery (T := T) G.dflt G.adversary pref₂ = some q₂ ∧ q₂ ∈ G.successors q₁ v
  betaSat sat := G.beta2 (G.topOf sat)
  betaSat_card sat m pref :=
    betaSat_of_nested (G.slotAscend G.Ascend2Query) (G.topOf sat) (G.beta2 (G.topOf sat)) sat
      (fun m pref c v hv hasc => by
        obtain ⟨q, hq, hA⟩ := hasc
        exact ⟨q, hq, G.ascend2_nested sat q c v hv hA⟩)
      (fun m pref => G.slotAscend_card G.Ascend2Query G.beta2 G.ascend2_bound m pref _)
      m pref
  pairSum sat := ∑ v ∈ satᶜ, G.reach v * (G.beta1 v * G.beta2 v)
  pair_sum sat i := by
    refine pair_sum_of_pointwise (V := V) (T := T)
      (G.slotAscend G.Ascend1Query) (G.slotAscend G.Ascend2Query)
      (fun _ _ pref₁ pref₂ v => ∃ q₁ q₂ : Q,
        slotQuery (T := T) G.dflt G.adversary pref₁ = some q₁ ∧
          slotQuery (T := T) G.dflt G.adversary pref₂ = some q₂ ∧ q₂ ∈ G.successors q₁ v)
      (fun v => G.reach v * (G.beta1 v * G.beta2 v)) sat i ?_
    intro v
    refine le_trans (Finset.card_le_card ?_)
      (pair_with_successors_card_le G.dflt G.adversary
        (fun q c => G.Ascend1Query q c v) (fun q c => G.Ascend2Query q c v)
        (fun q => G.successors q v) (G.beta1 v) (G.beta2 v) (G.reach v)
        (fun q₁ => G.successors_card q₁ v)
        (fun q => G.ascend1_bound q v) (fun q => G.ascend2_bound q v) i G.two_le)
    intro tape htape
    simp only [mem_filter, mem_univ, true_and, slotAscend] at htape ⊢
    obtain ⟨⟨q₁, hq₁, ha1⟩, j, hij, ⟨q₁', q₂', hq₁', hq₂', hmem⟩, ⟨q₂, hq₂, ha2⟩⟩ := htape
    have hqq : q₁' = q₁ := Option.some.inj (hq₁'.symm.trans hq₁)
    have hqq2 : q₂' = q₂ := Option.some.inj (hq₂'.symm.trans hq₂)
    have hmem' : q₂ ∈ G.successors q₁ v := by rw [← hqq, ← hqq2]; exact hmem
    exact ⟨q₁, hq₁, ha1, j, q₂, hij, hq₂, hmem', ha2⟩
  escape tape hacc hfail := by
    obtain ⟨v, i, j, q₁, q₂, hij, h1, h2, hmem, ha1, ha2⟩ := G.chain tape hacc hfail
    exact ⟨v, i, j, hij,
      ⟨q₁, (G.slotQuery_at tape i).trans h1, ha1⟩,
      ⟨q₁, q₂, (G.slotQuery_at tape i).trans h1, (G.slotQuery_at tape j).trans h2, hmem⟩,
      ⟨q₂, (G.slotQuery_at tape j).trans h2, ha2⟩⟩

/--
**The graded grinding bound.**

```
Pr[ accept ∧ extraction fails ]
  ≤ T² · (∑ v ∉ saturated, beta1 v · beta2 v) / |C|²
      + T · (∑ v ∈ saturated, beta2 v) / |C|
```

The first term is the split-grinding charge and the second the clamped one.  Read as advantage per
unit of work the pair term is `(∑ reach · beta1 · beta2) / |C|²`: the surviving factor is the
*fan-out*, not the query budget, which is the content of `pair_with_successors_card_le`.
-/
theorem graded_grinding_ratio_le [Nonempty C]
    (G : GradedGrinding C Q A V t T Accepts Fails) (saturated : Finset V) (hT : 2 ≤ T) :
    ((univ.filter fun tape : Fin T → C => Accepts tape ∧ Fails).card : ℚ)
        / (Fintype.card C : ℚ) ^ T
      ≤ ((T * (∑ v ∈ saturatedᶜ, G.reach v * (G.beta1 v * G.beta2 v)) : ℕ) : ℚ)
            / (Fintype.card C : ℚ) ^ 2
        + ((T * G.beta2 (G.topOf saturated) : ℕ) : ℚ) / (Fintype.card C : ℚ) :=
  G.toGradedPair.graded_ratio_le saturated hT

end GradedGrinding
end Bcs
