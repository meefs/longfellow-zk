import Mathlib.Algebra.BigOperators.Intervals
import Merkle.RandomOracle

/-!
# Lazy sampling: adaptive executions on a fixed slot layout

This is the step that `ROMBindingGame` assumes and that `ExtractionROM` will need in exactly the
same form: **connecting a syntactically bounded adaptive execution to a fixed family of
answer-tape slots.**

The difficulty is that an adaptive adversary chooses *which* query to make after seeing earlier
answers, so the set of queried inputs is a function of the tape.  A union bound over "the pairs the
adversary happens to query" is therefore a union bound over a tape-dependent family, which is not
what `answerTape_pairCollision_card_le` — or any counting argument — can consume.

Lazy sampling resolves it.  Answer the `i`-th *distinct* query from tape slot `i`.  Then

* repeats read the same slot, so the oracle stays a function;
* distinct queries read distinct slots, so a collision in the trace is a collision of the tape at
  two distinct slots;
* and the slot *indices* are `0, 1, 2, …` regardless of the tape.

So the covering family is `slotPairs T t = {(i,j) : i < j < t}` — fixed, independent of both the
tape and the adversary.  Adaptivity moves the *contents* of the slots, never their indices.  That
is `traceCollision_pairCollision`, and `lazy_traceCollision_card_le` is the counting corollary.
-/

open Finset

set_option autoImplicit false
set_option relaxedAutoImplicit false

namespace Merkle

namespace RandomOracle

universe uQ uD uA

variable {Q : Type uQ} {D : Type uD} {A : Type uA}

/-! ## The fixed slot family -/

/-- Ordered pairs of distinct slots below `t`.  Independent of the tape and of the adversary: this
is the whole point of lazy sampling. -/
def slotPairs (T t : ℕ) : Finset (Fin T × Fin T) :=
  Finset.univ.filter fun p : Fin T × Fin T => p.1.val < p.2.val ∧ p.2.val < t

theorem slotPairs_distinct {T t : ℕ} : ∀ p ∈ slotPairs T t, p.1 ≠ p.2 := by
  intro p hp hEq
  have h := (Finset.mem_filter.mp hp).2.1
  rw [hEq] at h
  exact lt_irrefl _ h

/-- The sharp birthday count: `|{(i,j) : i < j < t}| = t(t-1)/2`. -/
theorem slotPairs_card_le (T t : ℕ) : (slotPairs T t).card ≤ t * (t - 1) / 2 := by
  classical
  -- send a slot pair to the pair of its underlying naturals
  have hinj : Set.InjOn (fun p : Fin T × Fin T => (p.1.val, p.2.val)) (slotPairs T t) := by
    intro p _ q _ h
    exact Prod.ext (Fin.val_injective (congrArg Prod.fst h))
      (Fin.val_injective (congrArg Prod.snd h))
  have himg : (slotPairs T t).image (fun p : Fin T × Fin T => (p.1.val, p.2.val)) ⊆
      (Finset.range t).biUnion fun j => (Finset.range j).image fun i => (i, j) := by
    intro x hx
    obtain ⟨p, hp, rfl⟩ := Finset.mem_image.mp hx
    obtain ⟨hlt, hjt⟩ := (Finset.mem_filter.mp hp).2
    exact Finset.mem_biUnion.mpr ⟨p.2.val, Finset.mem_range.mpr hjt,
      Finset.mem_image.mpr ⟨p.1.val, Finset.mem_range.mpr hlt, rfl⟩⟩
  have hcard : (slotPairs T t).card =
      ((slotPairs T t).image (fun p : Fin T × Fin T => (p.1.val, p.2.val))).card :=
    (Finset.card_image_of_injOn hinj).symm
  have hbound : ((Finset.range t).biUnion
      fun j => (Finset.range j).image fun i => (i, j)).card ≤ ∑ j ∈ Finset.range t, j := by
    refine (Finset.card_biUnion_le).trans (Finset.sum_le_sum ?_)
    intro j _
    exact (Finset.card_image_le).trans (by simp)
  have hgauss : (∑ j ∈ Finset.range t, j) = t * (t - 1) / 2 := by
    have h := Finset.sum_range_id_mul_two t
    omega
  rw [hcard]
  exact (Finset.card_le_card himg).trans (hbound.trans (le_of_eq hgauss))

/-- Trace collisions are decidable, which the counting statement needs in order to filter on
them. -/
instance traceCollisionDecidable [DecidableEq Q] [DecidableEq D] (tr : List (Q × D)) :
    Decidable (TraceCollision tr) := by
  unfold TraceCollision
  infer_instance

/-! ## Lazy execution -/

section Lazy

variable [DecidableEq Q] {T : ℕ}

/-- Answer read from slot `i`.  Out-of-range slots read `dflt`; `lazyRun_slot_lt` shows that never
happens once the query budget fits the tape. -/
def tapeAt (tape : Fin T → D) (dflt : D) (i : ℕ) : D :=
  if h : i < T then tape ⟨i, h⟩ else dflt

/-- **Lazy-sampling execution against a fixed answer tape.**

`seen` lists the distinct queries so far in order of first occurrence, so a query's slot is its
index there.  Repeats reuse their slot — which is what keeps the oracle a function — and fresh
queries take the next unused one. -/
def lazyRun (tape : Fin T → D) (dflt : D) :
    {fuel : ℕ} → Tree Q D A fuel → List Q → A × List Q × List (Q × D)
  | _, .done a, seen => (a, seen, [])
  | _, .query q next, seen =>
      let seen' := if q ∈ seen then seen else seen ++ [q]
      let y := tapeAt tape dflt (seen'.idxOf q)
      let out := lazyRun tape dflt (next y) seen'
      (out.1, out.2.1, (q, y) :: out.2.2)

@[simp] theorem lazyRun_done (tape : Fin T → D) (dflt : D) {fuel : ℕ} (a : A) (seen : List Q) :
    lazyRun tape dflt (Tree.done (fuel := fuel) a : Tree Q D A fuel) seen = (a, seen, []) := rfl

theorem lazyRun_query (tape : Fin T → D) (dflt : D) {fuel : ℕ} (q : Q)
    (next : D → Tree Q D A fuel) (seen : List Q) :
    lazyRun tape dflt (Tree.query q next) seen =
      (let seen' := if q ∈ seen then seen else seen ++ [q]
       let y := tapeAt tape dflt (seen'.idxOf q)
       let out := lazyRun tape dflt (next y) seen'
       (out.1, out.2.1, (q, y) :: out.2.2)) := rfl

/-- The seen-list only grows, and only at the end.  This is what makes a slot permanent: an index
assigned early is still that query's index at the end of the execution. -/
theorem lazyRun_seen_prefix (tape : Fin T → D) (dflt : D) :
    ∀ {fuel : ℕ} (c : Tree Q D A fuel) (seen : List Q),
      seen <+: (lazyRun tape dflt c seen).2.1
  | _, .done _, seen => List.prefix_refl seen
  | _, .query q next, seen => by
      rw [lazyRun_query]
      refine List.IsPrefix.trans ?_ (lazyRun_seen_prefix tape dflt (next _) _)
      by_cases h : q ∈ seen
      · simp [h]
      · simp [h]

/-- At most `fuel` fresh queries, so at most `fuel` new slots. -/
theorem lazyRun_seen_length_le (tape : Fin T → D) (dflt : D) :
    ∀ {fuel : ℕ} (c : Tree Q D A fuel) (seen : List Q),
      (lazyRun tape dflt c seen).2.1.length ≤ seen.length + fuel
  | _, .done _, seen => by simp
  | _, .query q next, seen => by
      rw [lazyRun_query]
      have ih := lazyRun_seen_length_le tape dflt (next
        (tapeAt tape dflt ((if q ∈ seen then seen else seen ++ [q]).idxOf q)))
        (if q ∈ seen then seen else seen ++ [q])
      by_cases h : q ∈ seen <;> simp only [h, if_true, if_false] at ih ⊢ <;> simp at ih ⊢ <;> omega

/-- One trace entry per query, so the trace is no longer than the query budget.  Unlike
`lazyRun_seen_length_le` this counts *all* queries, repeats included, which is what bounds the size of
an execution's query *set* uniformly in the tape. -/
theorem lazyRun_trace_length_le (tape : Fin T → D) (dflt : D) :
    ∀ {fuel : ℕ} (c : Tree Q D A fuel) (seen : List Q),
      (lazyRun tape dflt c seen).2.2.length ≤ fuel
  | _, .done _, seen => by simp
  | _, .query q next, seen => by
      rw [lazyRun_query]
      have ih := lazyRun_trace_length_le tape dflt (next
        (tapeAt tape dflt ((if q ∈ seen then seen else seen ++ [q]).idxOf q)))
        (if q ∈ seen then seen else seen ++ [q])
      simp only [List.length_cons]
      omega

/-- The seen-list grows by at most one entry per query, so it is bounded by the **trace** length, not
just by the fuel.  For an execution that skips most of its budget — a pruned reconstruction, which
hashes only the opened paths — this is far sharper than `lazyRun_seen_length_le`, and it is what lets a
slot family be sized by paths rather than by the whole tree. -/
theorem lazyRun_seen_length_le_trace (tape : Fin T → D) (dflt : D) :
    ∀ {fuel : ℕ} (c : Tree Q D A fuel) (seen : List Q),
      (lazyRun tape dflt c seen).2.1.length ≤
        seen.length + (lazyRun tape dflt c seen).2.2.length
  | _, .done _, seen => by simp
  | _, .query q next, seen => by
      rw [lazyRun_query]
      have ih := lazyRun_seen_length_le_trace tape dflt (next
        (tapeAt tape dflt ((if q ∈ seen then seen else seen ++ [q]).idxOf q)))
        (if q ∈ seen then seen else seen ++ [q])
      by_cases h : q ∈ seen <;> simp only [h, if_true, if_false] at ih ⊢ <;> simp at ih ⊢ <;> omega

/-- Trace-length form of `lazyRun_slot_lt`. -/
theorem lazyRun_slot_lt_trace (tape : Fin T → D) (dflt : D) {fuel : ℕ} (c : Tree Q D A fuel)
    (seen : List Q) (r : Q) (hr : r ∈ (lazyRun tape dflt c seen).2.1) :
    (lazyRun tape dflt c seen).2.1.idxOf r <
      seen.length + (lazyRun tape dflt c seen).2.2.length :=
  lt_of_lt_of_le (List.idxOf_lt_length_of_mem hr)
    (lazyRun_seen_length_le_trace tape dflt c seen)

/-- Distinct queries keep distinct slots. -/
theorem lazyRun_seen_nodup (tape : Fin T → D) (dflt : D) :
    ∀ {fuel : ℕ} (c : Tree Q D A fuel) (seen : List Q), seen.Nodup →
      (lazyRun tape dflt c seen).2.1.Nodup
  | _, .done _, seen, h => h
  | _, .query q next, seen, h => by
      rw [lazyRun_query]
      refine lazyRun_seen_nodup tape dflt (next _) _ ?_
      by_cases hq : q ∈ seen
      · simpa [hq] using h
      · simp only [hq, if_false]
        refine List.nodup_append.mpr ⟨h, by simp, ?_⟩
        intro a ha b hb heq
        simp only [List.mem_singleton] at hb
        subst hb
        exact hq (heq ▸ ha)

/-- **Every recorded answer is the tape at that query's permanent slot.**

Stated against the *final* seen-list, which is what makes the slot well defined for the whole
execution rather than only at the moment of the query. -/
theorem lazyRun_trace_slot (tape : Fin T → D) (dflt : D) :
    ∀ {fuel : ℕ} (c : Tree Q D A fuel) (seen : List Q),
      ∀ qa ∈ (lazyRun tape dflt c seen).2.2,
        qa.1 ∈ (lazyRun tape dflt c seen).2.1 ∧
        qa.2 = tapeAt tape dflt ((lazyRun tape dflt c seen).2.1.idxOf qa.1)
  | _, .done _, seen => by simp
  | _, .query q next, seen => by
      rw [lazyRun_query]
      intro qa hqa
      set seen' := if q ∈ seen then seen else seen ++ [q] with hseen'
      set y := tapeAt tape dflt (seen'.idxOf q) with hy
      have hmemq : q ∈ seen' := by
        by_cases hq : q ∈ seen
        · simp [hseen', hq]
        · simp [hseen', hq]
      have hpref : seen' <+: (lazyRun tape dflt (next y) seen').2.1 :=
        lazyRun_seen_prefix tape dflt (next y) seen'
      -- a slot assigned in `seen'` survives to the end of the execution
      have hstable : ∀ r ∈ seen', (lazyRun tape dflt (next y) seen').2.1.idxOf r
          = seen'.idxOf r := by
        intro r hr
        obtain ⟨rest, hrest⟩ := hpref
        rw [← hrest, List.idxOf_append_of_mem hr]
      simp only [List.mem_cons] at hqa
      rcases hqa with rfl | htail
      · refine ⟨?_, ?_⟩
        · exact (List.IsPrefix.subset hpref) hmemq
        · rw [hstable _ hmemq]
      · obtain ⟨hmem, hval⟩ := lazyRun_trace_slot tape dflt (next y) seen' qa htail
        exact ⟨hmem, hval⟩

/-! ### The tape past a phase's slots

A run handed a base of length `L` that it never queries reads only slots `L, L+1, …`.  `shiftTape L`
is that suffix presented as a tape in its own right, so such a run can be restated as a run from the
*empty* base — and its output then depends on the original tape only through the high slots.  That is
the independence a digest-guessing count needs: nothing an earlier phase computed can influence it. -/

/-- The tape from slot `L` onwards. -/
def shiftTape (L : ℕ) (tape : Fin T → D) (dflt : D) : Fin T → D :=
  fun i => tapeAt tape dflt (L + i.val)

@[simp] theorem tapeAt_shiftTape (L : ℕ) (tape : Fin T → D) (dflt : D) (j : ℕ) :
    tapeAt (shiftTape L tape dflt) dflt j = tapeAt tape dflt (L + j) := by
  rw [tapeAt]
  split_ifs with hj
  · rfl
  · rw [tapeAt, dif_neg (by omega)]

/-- The shifted tape sees only the high slots, so changing a slot below `L` does not change it. -/
theorem shiftTape_congr (L : ℕ) (tape tape' : Fin T → D) (dflt : D)
    (h : ∀ i : Fin T, L ≤ i.val → tape i = tape' i) :
    shiftTape L tape dflt = shiftTape L tape' dflt := by
  funext i
  rw [shiftTape, shiftTape, tapeAt, tapeAt]
  split_ifs with hlt
  · exact h ⟨L + i.val, hlt⟩ (Nat.le_add_right L i.val)
  · rfl

/-- **Early queries take early slots.**  A query among the first `N` of an execution occupies a slot
below `seen.length + N`, because slots are handed out in order of first occurrence.

This is what "already determined when slot `j` is read" means in the slot model: if every query a value
depends on lies in the first `N` of the run, and `j ≥ seen.length + N`, then that value is a function of
the tape *off* slot `j`, which is exactly `HitTarget`'s obligation. -/
theorem lazyRun_slot_lt_of_mem_take (tape : Fin T → D) (dflt : D) :
    ∀ {fuel : ℕ} (c : Tree Q D A fuel) (seen : List Q) (N : ℕ),
      ∀ q ∈ ((lazyRun tape dflt c seen).2.2.map Prod.fst).take N,
        (lazyRun tape dflt c seen).2.1.idxOf q < seen.length + N
  | _, .done _, _, _, q, hq => by simp at hq
  | _, .query _ _, _, 0, q, hq => by simp at hq
  | _, .query q₀ next, seen, (N + 1), q, hq => by
      rw [lazyRun_query] at hq ⊢
      dsimp only at hq ⊢
      simp only [List.map_cons, List.take_succ_cons, List.mem_cons] at hq
      set seen' := if q₀ ∈ seen then seen else seen ++ [q₀] with hseen'
      set y := tapeAt tape dflt (seen'.idxOf q₀) with hy
      have hmemq : q₀ ∈ seen' := by
        by_cases h : q₀ ∈ seen
        · simp [hseen', h]
        · simp [hseen', h]
      have hpref : seen' <+: (lazyRun tape dflt (next y) seen').2.1 :=
        lazyRun_seen_prefix tape dflt (next y) seen'
      have hstable : ∀ r ∈ seen',
          (lazyRun tape dflt (next y) seen').2.1.idxOf r = seen'.idxOf r := by
        intro r hr
        obtain ⟨rest, hrest⟩ := hpref
        rw [← hrest, List.idxOf_append_of_mem hr]
      have hseenlen : seen'.length ≤ seen.length + 1 := by
        by_cases h : q₀ ∈ seen
        · simp [hseen', h]
        · simp [hseen', h]
      rcases hq with rfl | hq
      · rw [hstable _ hmemq]
        have h1 := List.idxOf_lt_length_of_mem hmemq
        omega
      · have ih := lazyRun_slot_lt_of_mem_take tape dflt (next y) seen' N q hq
        omega

/-- Every slot used lies below the query budget, so the tape is never read out of range and
`tapeAt`'s default branch is dead. -/
theorem lazyRun_slot_lt (tape : Fin T → D) (dflt : D) {fuel : ℕ} (c : Tree Q D A fuel)
    (seen : List Q) (r : Q) (hr : r ∈ (lazyRun tape dflt c seen).2.1) :
    (lazyRun tape dflt c seen).2.1.idxOf r < seen.length + fuel :=
  lt_of_lt_of_le (List.idxOf_lt_length_of_mem hr) (lazyRun_seen_length_le tape dflt c seen)

/-! ## The covering theorem -/

/-- **Adaptive trace collisions are covered by a fixed slot family.**

A `t`-query lazy execution that produces a trace collision forces the tape to repeat at two
distinct slots below `t`.  The family `slotPairs T t` does not mention the tape, the adversary, or
the execution — which is exactly what `answerTape_pairCollision_card_le` needs, and exactly what a
tape-dependent union bound could not provide. -/
theorem traceCollision_pairCollision (tape : Fin T → D) (dflt : D) {t : ℕ}
    (c : Tree Q D A t) (ht : t ≤ T)
    (hcol : TraceCollision (lazyRun tape dflt c []).2.2) :
    PairCollision T (slotPairs T t) tape := by
  classical
  obtain ⟨qa₀, h₀, qa₁, h₁, hne, hans⟩ := hcol
  obtain ⟨hmem₀, hval₀⟩ := lazyRun_trace_slot tape dflt c [] qa₀ h₀
  obtain ⟨hmem₁, hval₁⟩ := lazyRun_trace_slot tape dflt c [] qa₁ h₁
  set final := (lazyRun tape dflt c []).2.1 with hfinal
  -- distinct queries occupy distinct slots, because `final` has no duplicates
  have hnodup : final.Nodup := lazyRun_seen_nodup tape dflt c [] List.nodup_nil
  have hslotne : final.idxOf qa₀.1 ≠ final.idxOf qa₁.1 := by
    intro h
    exact hne ((List.idxOf_inj hmem₀).mp h)
  -- both slots are below the budget
  have hlt₀ : final.idxOf qa₀.1 < t := by
    have := lazyRun_slot_lt tape dflt c [] qa₀.1 hmem₀
    simpa using this
  have hlt₁ : final.idxOf qa₁.1 < t := by
    have := lazyRun_slot_lt tape dflt c [] qa₁.1 hmem₁
    simpa using this
  -- and the tape agrees there
  have htape : tape ⟨final.idxOf qa₀.1, lt_of_lt_of_le hlt₀ ht⟩
      = tape ⟨final.idxOf qa₁.1, lt_of_lt_of_le hlt₁ ht⟩ := by
    have e₀ : qa₀.2 = tape ⟨final.idxOf qa₀.1, lt_of_lt_of_le hlt₀ ht⟩ := by
      rw [hval₀, tapeAt, dif_pos (lt_of_lt_of_le hlt₀ ht)]
    have e₁ : qa₁.2 = tape ⟨final.idxOf qa₁.1, lt_of_lt_of_le hlt₁ ht⟩ := by
      rw [hval₁, tapeAt, dif_pos (lt_of_lt_of_le hlt₁ ht)]
    rw [← e₀, ← e₁]; exact hans
  -- order the two slots to land in `slotPairs`
  set i₀ : Fin T := ⟨final.idxOf qa₀.1, lt_of_lt_of_le hlt₀ ht⟩
  set i₁ : Fin T := ⟨final.idxOf qa₁.1, lt_of_lt_of_le hlt₁ ht⟩
  have hvalne : i₀.val ≠ i₁.val := hslotne
  rcases Nat.lt_or_ge i₀.val i₁.val with hlt | hge
  · exact ⟨(i₀, i₁), Finset.mem_filter.mpr ⟨Finset.mem_univ _, hlt, hlt₁⟩, htape⟩
  · have hlt' : i₁.val < i₀.val := by omega
    exact ⟨(i₁, i₀), Finset.mem_filter.mpr ⟨Finset.mem_univ _, hlt', hlt₀⟩, htape.symm⟩

/-- **The own-collision bound.**

A `t`-query adaptive adversary produces a trace collision on at most `t(t-1)/2 · |D|^(T-1)` of the
`|D|^T` answer tapes — the sharp birthday count, with no assumption connecting the adversary to the
slot layout, because lazy sampling supplies that connection.

This is `ROMBindingGame`'s `own_card` field, discharged. -/
theorem lazy_traceCollision_card_le [Fintype Q] [Fintype D] [DecidableEq D]
    (dflt : D) {t : ℕ} (c : Tree Q D A t) (ht : t ≤ T) :
    (Finset.univ.filter fun tape : Fin T → D =>
        TraceCollision (lazyRun tape dflt c []).2.2).card
      ≤ t * (t - 1) / 2 * (Fintype.card D) ^ (T - 1) := by
  classical
  calc
    (Finset.univ.filter fun tape : Fin T → D =>
          TraceCollision (lazyRun tape dflt c []).2.2).card
        ≤ (Finset.univ.filter (PairCollision (D := D) T (slotPairs T t))).card := by
          apply Finset.card_le_card
          intro tape htape
          simp only [Finset.mem_filter, Finset.mem_univ, true_and] at htape ⊢
          exact traceCollision_pairCollision tape dflt c ht htape
    _ ≤ (slotPairs T t).card * (Fintype.card D) ^ (T - 1) :=
        answerTape_pairCollision_card_le T (slotPairs T t) slotPairs_distinct
    _ ≤ t * (t - 1) / 2 * (Fintype.card D) ^ (T - 1) :=
        Nat.mul_le_mul_right _ (slotPairs_card_le T t)

end Lazy

end RandomOracle

end Merkle
