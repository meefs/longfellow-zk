import Mathlib.Algebra.BigOperators.Intervals
import Merkle.RandomOracle

/-!
# Lazy sampling: adaptive executions on a fixed slot layout

This is the step every random-oracle bound here needs: **connecting a syntactically bounded adaptive execution to a fixed family of
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
is `traceCollision_pairCollision`.
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

/-! ### Distinct queries receive the tape verbatim

The bridge from the *hash-oracle* model to the *coin-tape* model.  `Bcs.Rbr` and the Fiat–Shamir
zero-knowledge statements treat a round's challenge as a tape coordinate; the deployed protocol
obtains it by hashing a transcript prefix.  These agree exactly when the queries are **distinct**,
which the honest Fiat–Shamir prover's are — each round hashes a longer prefix.

`lazyRun_trace_slot` says an answer is the tape at its query's permanent slot; the content here is
that for distinct queries in a known order those slots are `0, 1, 2, …`, so the answer sequence *is*
the tape.  Nothing is assumed and nothing is paid: the coin-tape model is realised.
-/

/--
**A run whose distinct queries are `qs` receives the tape in order.**

The answer recorded at `qs k` is tape slot `k`.  So the challenge sequence a Fiat–Shamir prover
derives by hashing is the coin tape, coordinate for coordinate.
-/
theorem lazyRun_answer_eq_tape {L : ℕ} (tape : Fin T → D) (dflt : D)
    {fuel : ℕ} (c : Tree Q D A fuel) (qs : Fin L → Q) (hinj : Function.Injective qs)
    (hseen : (lazyRun tape dflt c []).2.1 = List.ofFn qs)
    {k : Fin L} (hk : k.val < T)
    {qa : Q × D} (hqa : qa ∈ (lazyRun tape dflt c []).2.2) (hq : qa.1 = qs k) :
    qa.2 = tape ⟨k.val, hk⟩ := by
  obtain ⟨-, hval⟩ := lazyRun_trace_slot tape dflt c [] qa hqa
  have hlen : k.val < (List.ofFn qs).length := by simp
  have helem : (List.ofFn qs)[k.val] = qs k := by simp
  have hidx : List.idxOf (qs k) (List.ofFn qs) = k.val := by
    have h := (List.nodup_ofFn.mpr hinj).idxOf_getElem k.val hlen
    rwa [helem] at h
  rw [hval, hseen, hq, hidx, tapeAt, dif_pos hk]

/-! ### A program that asks a fixed sequence

`lazyRun_answer_eq_tape` needs to know an execution's distinct queries.  For the honest Fiat–Shamir
prover they are known in advance: one hash per round, at a strictly longer prefix.  `askFin` is that
program and `lazyRun_seen_askFin` computes its seen-list, so the hypothesis becomes a theorem.
-/

/-- The program that asks `qs 0, qs 1, …, qs (L-1)` in order.  Its fuel is exactly `L`. -/
def askFin : (L : ℕ) → (qs : Fin L → Q) → Tree Q D Unit L
  | 0, _ => .done ()
  | L + 1, qs => .query (qs 0) fun _ => askFin L fun i => qs i.succ

/--
**Its distinct queries are `qs`, in order.**

So a prover that hashes a fresh point each round has seen-list `List.ofFn qs`, which is exactly what
`lazyRun_answer_eq_tape` asks for.
-/
theorem lazyRun_seen_askFin (tape : Fin T → D) (dflt : D) :
    ∀ (L : ℕ) (qs : Fin L → Q) (seen : List Q), (∀ i, qs i ∉ seen) → Function.Injective qs →
      (lazyRun tape dflt (askFin L qs) seen).2.1 = seen ++ List.ofFn qs
  | 0, qs, seen, _, _ => by simp [askFin]
  | L + 1, qs, seen, hfresh, hinj => by
      rw [askFin, lazyRun_query]
      have hq0 : qs 0 ∉ seen := hfresh 0
      simp only [if_neg hq0]
      have hfresh' : ∀ i : Fin L, qs i.succ ∉ seen ++ [qs 0] := by
        intro i hmem
        rcases List.mem_append.mp hmem with h | h
        · exact hfresh i.succ h
        · exact absurd (hinj (by simpa using h)) (Fin.succ_ne_zero i)
      have hinj' : Function.Injective fun i : Fin L => qs i.succ :=
        fun a b hab => Fin.succ_injective L (hinj hab)
      rw [lazyRun_seen_askFin tape dflt L (fun i => qs i.succ) _ hfresh' hinj']
      rw [List.ofFn_succ, List.append_assoc]
      rfl

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

/-! ## Slots are determined by the slots before them

The fact a Fiat--Shamir adversary needs, and the reason lazy sampling is the right model for one:

> **the query occupying slot `j` is a function of the tape's slots `< j`.**

`lazyRun` assigns the `j`-th *distinct* query the `j`-th slot, so which query lands in slot `j` is
decided before slot `j` is read — an adaptive adversary chooses *what* to ask from what it has been
told, and it has been told slots `0 … j-1`.  That is the prefix-measurability a round-by-round
argument against a grinding prover requires: the bad event at slot `j` is "the query made at slot `j`
was doomed and its answer escaped", and the first half has to be a function of the prefix.

`lazyRun_seen_take_congr` is the statement; the `+ 1` in it is the point, since slot `j`'s *query* is
fixed by the slots before it even though slot `j`'s *answer* is not.  `slotQuery` packages it as
data.
-/

/-- A prefix of a longer list has the same `take n` as the longer list, once the prefix is at least
`n` long.  The list-level content of "a slot, once assigned, stays assigned". -/
private theorem take_eq_of_prefix_of_length_le {α : Type*} {l l' : List α} (h : l <+: l') {n : ℕ}
    (hn : n ≤ l.length) : l'.take n = l.take n := by
  rw [List.prefix_iff_eq_take.mp h, List.take_take, Nat.min_eq_left (le_trans hn (by simp))]

/--
**Slots are decided before they are read.**

If two tapes agree on every slot below `j`, the two lazy executions agree on the first `j + 1`
distinct queries.  So slot `j`'s query is a function of slots `0 … j-1`, which is what makes the
bad event at slot `j` prefix-measurable.

The induction is on the adversary's tree.  At each query the slot read is either below `j`, where the
two tapes agree and the executions stay in lockstep, or at least `j`, in which case `seen` already
has `j + 1` entries — the query that went into slot `j` is already in the list — and both runs can
only extend it.
-/
theorem lazyRun_seen_take_congr (tape tape' : Fin T → D) (dflt : D) (j : ℕ)
    (hagree : ∀ i : Fin T, i.val < j → tape i = tape' i) :
    ∀ {fuel : ℕ} (c : Tree Q D A fuel) (seen : List Q),
      (lazyRun tape dflt c seen).2.1.take (j + 1)
        = (lazyRun tape' dflt c seen).2.1.take (j + 1)
  | _, .done _, seen => by simp
  | _, .query q next, seen => by
      classical
      rw [lazyRun_query, lazyRun_query]
      set seen' := if q ∈ seen then seen else seen ++ [q] with hseen'
      by_cases hslot : seen'.idxOf q < j
      · -- the slot read is below `j`: the tapes agree there, so the runs stay in lockstep
        have hy : tapeAt tape dflt (seen'.idxOf q) = tapeAt tape' dflt (seen'.idxOf q) := by
          unfold tapeAt
          by_cases hlt : seen'.idxOf q < T
          · simp only [dif_pos hlt]
            exact hagree ⟨seen'.idxOf q, hlt⟩ hslot
          · simp only [dif_neg hlt]
        simp only [hy]
        exact lazyRun_seen_take_congr tape tape' dflt j hagree (next _) seen'
      · -- the slot read is at or above `j`: `seen'` already fixes the first `j + 1` entries
        have hlen : j + 1 ≤ seen'.length := by
          have hmem : q ∈ seen' := by
            by_cases h : q ∈ seen
            · simp [hseen', h]
            · simp [hseen', h]
          have := List.idxOf_lt_length_of_mem (l := seen') hmem
          omega
        have hpref := lazyRun_seen_prefix tape dflt (next
          (tapeAt tape dflt (seen'.idxOf q))) seen'
        have hpref' := lazyRun_seen_prefix tape' dflt (next
          (tapeAt tape' dflt (seen'.idxOf q))) seen'
        rw [take_eq_of_prefix_of_length_le hpref hlen,
          take_eq_of_prefix_of_length_le hpref' hlen]

/-- If a second tape agrees on every slot used by the first lazy execution,
then the complete executions agree, including the output.  The bound is the
actual final distinct-query count, not the syntactic fuel, so this also covers
an adversary that stops early before verifier-appended defining queries. -/
theorem lazyRun_eq_of_agree_below_seen_length
    (tape tape' : Fin T → D) (dflt : D) :
    ∀ {fuel : ℕ} (c : Tree Q D A fuel) (seen : List Q),
      (∀ i : Fin T,
        i.val < (lazyRun tape dflt c seen).2.1.length → tape i = tape' i) →
      lazyRun tape dflt c seen = lazyRun tape' dflt c seen
  | _, .done _, _seen, _hagree => rfl
  | _, .query q next, seen, hagree => by
      rw [lazyRun_query, lazyRun_query]
      let seen' := if q ∈ seen then seen else seen ++ [q]
      let slot := seen'.idxOf q
      have hmem : q ∈ seen' := by
        by_cases hq : q ∈ seen <;> simp [seen', hq]
      have hslotSeen : slot < seen'.length := by
        exact List.idxOf_lt_length_of_mem hmem
      let answer := tapeAt tape dflt slot
      have hpref := lazyRun_seen_prefix tape dflt (next answer) seen'
      have hseenFinal : seen'.length ≤
          (lazyRun tape dflt (next answer) seen').2.1.length := by
        exact List.IsPrefix.length_le hpref
      have hanswer : tapeAt tape dflt slot = tapeAt tape' dflt slot := by
        unfold tapeAt
        by_cases hslot : slot < T
        · simp only [dif_pos hslot]
          exact hagree ⟨slot, hslot⟩ (hslotSeen.trans_le hseenFinal)
        · simp only [dif_neg hslot]
      have hrecursive := lazyRun_eq_of_agree_below_seen_length
        tape tape' dflt (next answer) seen' (by
          intro i hi
          exact hagree i hi)
      change
        (let out := lazyRun tape dflt (next answer) seen'
         (out.1, out.2.1, (q, answer) :: out.2.2)) =
        (let otherAnswer := tapeAt tape' dflt slot
         let out := lazyRun tape' dflt (next otherAnswer) seen'
         (out.1, out.2.1, (q, otherAnswer) :: out.2.2))
      rw [← hanswer, hrecursive]

/-! ## The slot's query, as data -/

/-- Extend a prefix of slots to a whole tape by padding with `dflt`. -/
def pad (dflt : D) {j : ℕ} (pref : Fin j → D) : Fin T → D :=
  fun i => if h : i.val < j then pref ⟨i.val, h⟩ else dflt

theorem pad_agree (dflt : D) {j : ℕ} (pref : Fin j → D) (i : Fin T)
    (hi : i.val < j) : pad (T := T) dflt pref i = pref ⟨i.val, hi⟩ := by
  simp only [pad, dif_pos hi]

/--
**The query at slot `j`, read off the prefix.**

`none` when the adversary never reaches a `j`-th distinct query — it stopped early, or repeated
itself — in which case slot `j` is never read and there is nothing to be doomed about.
-/
noncomputable def slotQuery (dflt : D) {fuel : ℕ} (c : Tree Q D A fuel) {j : ℕ}
    (pref : Fin j → D) : Option Q :=
  (lazyRun (pad (T := T) dflt pref) dflt c []).2.1[j]?

/--
**It is the real run's slot-`j` query.**

So a predicate written against `slotQuery` — a function of the prefix, by its type — is a predicate
about what the adversary actually asked at that slot.  This is the bridge from
`lazyRun_seen_take_congr` to `Bcs.RbrCore.bad`.
-/
theorem slotQuery_eq (dflt : D) {fuel : ℕ} (c : Tree Q D A fuel) {j : ℕ} (hj : j ≤ T)
    (tape : Fin T → D) :
    slotQuery (T := T) dflt c (fun i : Fin j => tape ⟨i.val, lt_of_lt_of_le i.isLt hj⟩)
      = (lazyRun tape dflt c []).2.1[j]? := by
  classical
  have hagree : ∀ i : Fin T, i.val < j →
      pad (T := T) dflt (fun i : Fin j => tape ⟨i.val, lt_of_lt_of_le i.isLt hj⟩) i = tape i := by
    intro i hi
    rw [pad_agree dflt _ i hi]
  have h := lazyRun_seen_take_congr
    (pad (T := T) dflt (fun i : Fin j => tape ⟨i.val, lt_of_lt_of_le i.isLt hj⟩))
    tape dflt j hagree c []
  unfold slotQuery
  rw [← List.getElem?_take_of_lt (by omega : j < j + 1), h,
    List.getElem?_take_of_lt (by omega : j < j + 1)]

end Lazy

end RandomOracle

end Merkle
