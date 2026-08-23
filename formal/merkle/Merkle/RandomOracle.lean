import Mathlib.Tactic.SetNotationForOrder
import Mathlib.Data.Fintype.BigOperators
import Mathlib.Data.Tree.Basic
import Mathlib.Algebra.Order.Ring.Nat
import Mathlib.Algebra.Order.BigOperators.Group.Finset

/-!
# Bounded adaptive random-oracle executions

An oracle adversary is an answer-branching query tree. Unlike a function of a
complete oracle, this syntax exposes the exact adaptive query bound. The
finite counting lemmas below are reusable by binding and hiding games.
-/

open Finset

set_option autoImplicit false
set_option relaxedAutoImplicit false

namespace Merkle

namespace RandomOracle

universe uQ uD uA

/-- An adaptive oracle program making at most `fuel` queries. `done` may stop
early; `query` chooses its continuation after seeing the answer. -/
inductive Tree (Q : Type uQ) (D : Type uD) (A : Type uA) : ℕ → Type _ where
  | done {fuel : ℕ} (a : A) : Tree Q D A fuel
  | query {fuel : ℕ} (q : Q) (next : D → Tree Q D A fuel) :
      Tree Q D A (fuel + 1)

/-- Execute an adaptive tree against a total oracle, recording queries and
answers in execution order. -/
def Tree.run {Q : Type uQ} {D : Type uD} {A : Type uA} {fuel : ℕ} :
    Tree Q D A fuel → (Q → D) → A × List (Q × D)
  | .done a, _ => (a, [])
  | .query q next, H =>
      let y := H q
      let out := (next y).run H
      (out.1, (q, y) :: out.2)

@[simp] theorem Tree.run_done {Q : Type uQ} {D : Type uD} {A : Type uA}
    {fuel : ℕ} (a : A) (H : Q → D) :
    (Tree.done (fuel := fuel) a : Tree Q D A fuel).run H = (a, []) := rfl

@[simp] theorem Tree.run_query {Q : Type uQ} {D : Type uD} {A : Type uA}
    {fuel : ℕ} (q : Q) (next : D → Tree Q D A fuel) (H : Q → D) :
    (Tree.query q next).run H =
      let out := (next (H q)).run H
      (out.1, (q, H q) :: out.2) := rfl

/-- Execution never exceeds the syntactic query budget. -/
theorem Tree.trace_length_le {Q : Type uQ} {D : Type uD} {A : Type uA}
    {fuel : ℕ} (c : Tree Q D A fuel) (H : Q → D) :
    (c.run H).2.length ≤ fuel := by
  induction c with
  | done a => simp
  | @query fuel q next ih =>
      simp only [Tree.run_query, List.length_cons]
      have htail := ih (H q)
      omega

/-- Every answer in an execution trace is the answer of the oracle used for
that execution. -/
theorem Tree.trace_sound {Q : Type uQ} {D : Type uD} {A : Type uA}
    {fuel : ℕ} (c : Tree Q D A fuel) (H : Q → D) :
    ∀ qa ∈ (c.run H).2, qa.2 = H qa.1 := by
  induction c with
  | done a => simp
  | @query fuel q next ih =>
      intro qa hqa
      simp only [Tree.run_query, List.mem_cons] at hqa
      rcases hqa with rfl | htail
      · rfl
      · exact ih (H q) qa htail

/-- Oracle extensionality only on the actually executed trace suffices to
replay the same adaptive execution. -/
theorem Tree.run_congr_on_trace {Q : Type uQ} {D : Type uD} {A : Type uA}
    {fuel : ℕ} (c : Tree Q D A fuel) (H H' : Q → D)
    (hagrees : ∀ qa ∈ (c.run H).2, H' qa.1 = qa.2) :
    c.run H' = c.run H := by
  induction c with
  | done a => rfl
  | @query fuel q next ih =>
      have hq : H' q = H q := by
        have := hagrees (q, H q) (by simp [Tree.run_query])
        exact this
      simp only [Tree.run_query, hq]
      have htail : ∀ qa ∈ ((next (H q)).run H).2, H' qa.1 = qa.2 := by
        intro qa hqa
        apply hagrees qa
        simp only [Tree.run_query, List.mem_cons]
        exact Or.inr hqa
      rw [ih (H q) htail]

/-! ### Programming

Programming an oracle is replacing its answers on a designated finite set of inputs.  The whole
content is that it is **undetectable unless the adversary asks**: if an execution's trace never
presents a programmed input, reprogramming leaves the execution — output and trace alike — unchanged.

This is where the simulator's licence comes from, in the hiding argument and in any Fiat–Shamir
simulator that has to force a challenge.  Nothing here is about Merkle trees or about any particular
programmed set: `Merkle.MH.reprogramLeaves` is the instance at the honest leaf inputs.

Note which representation programming acts on.  An oracle here is a *function* `Q → D`, and
programming patches the function.  Counting happens in the tape representation
(`Merkle.LazyTape.lazyRun`), where the sample space is finite; the two are bridged by taking the
oracle to be a tape-indexed *family* of functions, which is the shape `run_congr_off_programQueried`
below has.  Patching tape slots directly would be wrong: `lazyRun` indexes the tape by first-query
order, so the input-to-slot map depends on the adversary's own behaviour.
-/

/-- The oracle `H`, with the inputs in `P` answered by `fresh` instead. -/
def reprogram {Q : Type uQ} {D : Type uD} [DecidableEq Q]
    (P : Finset Q) (H fresh : Q → D) : Q → D :=
  fun x => if x ∈ P then fresh x else H x

@[simp] theorem reprogram_of_not_mem {Q : Type uQ} {D : Type uD} [DecidableEq Q]
    (P : Finset Q) (H fresh : Q → D) (x : Q) (hx : x ∉ P) :
    reprogram P H fresh x = H x := by
  rw [reprogram, if_neg hx]

/--
**Programming is undetectable unless asked.**

If the execution under `H` never queries a programmed input, then it is *identical* under the
programmed oracle — same output, same trace.  An equality, not a bound: the bound comes later, from
counting the sample points where the execution does query one.
-/
theorem Tree.run_congr_off_programmed {Q : Type uQ} {D : Type uD} {A : Type uA}
    [DecidableEq Q] {fuel : ℕ} (P : Finset Q) (H fresh : Q → D)
    (c : Tree Q D A fuel)
    (hmiss : ∀ qa ∈ (c.run H).2, qa.1 ∉ P) :
    c.run (reprogram P H fresh) = c.run H := by
  refine Tree.run_congr_on_trace c H _ fun qa hqa => ?_
  rw [reprogram_of_not_mem P H fresh qa.1 (hmiss qa hqa)]
  exact (Tree.trace_sound c H qa hqa).symm

/-- The sample points whose execution does query a programmed input: the detection event, as a
definition.  Both the oracle and the programmed set may depend on the sample point — the oracle
because a tape indexes a family of functions, the set because a simulator chooses what to program
after seeing its own coins. -/
noncomputable def programQueried {Q : Type uQ} {D : Type uD} {A : Type uA}
    [DecidableEq Q] [Fintype D] [DecidableEq D] {fuel T : ℕ}
    (P : (Fin T → D) → Finset Q) (oracle : (Fin T → D) → Q → D)
    (c : Tree Q D A fuel) : Finset (Fin T → D) := by
  classical
  exact Finset.univ.filter fun ω => ∃ qa ∈ (c.run (oracle ω)).2, qa.1 ∈ P ω

/-- Off the detection event the execution is unchanged, stated over the tape. -/
theorem run_congr_off_programQueried {Q : Type uQ} {D : Type uD} {A : Type uA}
    [DecidableEq Q] [Fintype D] [DecidableEq D] {fuel T : ℕ}
    (P : (Fin T → D) → Finset Q) (oracle fresh : (Fin T → D) → Q → D)
    (c : Tree Q D A fuel) (ω : Fin T → D)
    (hω : ω ∉ programQueried P oracle c) :
    c.run (reprogram (P ω) (oracle ω) (fresh ω)) = c.run (oracle ω) := by
  classical
  refine Tree.run_congr_off_programmed (P ω) (oracle ω) (fresh ω) c ?_
  intro qa hqa
  rw [programQueried] at hω
  simp only [Finset.mem_filter, Finset.mem_univ, true_and, not_exists] at hω
  intro hmem
  exact hω qa ⟨hqa, hmem⟩

/-- A trace collision uses two distinct queried inputs with the same recorded
answer. -/
def TraceCollision {Q : Type uQ} {D : Type uD} (tr : List (Q × D)) : Prop :=
  ∃ qa₀ ∈ tr, ∃ qa₁ ∈ tr, qa₀.1 ≠ qa₁.1 ∧ qa₀.2 = qa₁.2

/-- A collision in an adaptive execution trace is a non-injectivity witness
for the total oracle. -/
theorem Tree.not_injective_of_traceCollision
    {Q : Type uQ} {D : Type uD} {A : Type uA}
    {fuel : ℕ} (c : Tree Q D A fuel) (H : Q → D)
    (hcol : TraceCollision (c.run H).2) : ¬Function.Injective H := by
  rcases hcol with ⟨qa₀, h₀, qa₁, h₁, hne, hans⟩
  intro hinj
  apply hne
  apply hinj
  rw [← Tree.trace_sound c H qa₀ h₀, ← Tree.trace_sound c H qa₁ h₁]
  exact hans

/-- A regression example whose second query genuinely depends on the first
answer. -/
def adaptiveSecondQuery : Tree (Fin 3) Bool Bool 2 :=
  .query 0 (fun b => .query (if b then 1 else 2) (fun b' => .done b'))

example (H : Fin 3 → Bool) (h : H 0 = true) :
    ((adaptiveSecondQuery.run H).2.map Prod.fst) = [0, 1] := by
  simp [adaptiveSecondQuery, h]

example (H : Fin 3 → Bool) (h : H 0 = false) :
    ((adaptiveSecondQuery.run H).2.map Prod.fst) = [0, 2] := by
  simp [adaptiveSecondQuery, h]

/-! ## Finite oracle counting -/

variable {Q : Type uQ} {D : Type uD}

/-- Restrict an oracle away from one coordinate. -/
def eraseCoord (q₁ : Q) (H : Q → D) : {q : Q // q ≠ q₁} → D :=
  fun q => H q.val

/-- If answers at two distinct coordinates are constrained equal, erasing
one of those coordinates remains injective: the erased answer is determined
by the retained one. -/
theorem eraseCoord_injective_on_equal [DecidableEq Q]
    (q₀ q₁ : Q) (hne : q₀ ≠ q₁) :
    Function.Injective (fun H : {H : Q → D // H q₀ = H q₁} =>
      eraseCoord q₁ H.val) := by
  intro H G heq
  apply Subtype.ext
  funext q
  by_cases hq : q = q₁
  · subst q
    rw [← H.property, ← G.property]
    exact congrFun heq ⟨q₀, hne⟩
  · exact congrFun heq ⟨q, hq⟩

/-- A fixed pair of distinct oracle inputs agrees on at most a `1/|D|`
fraction of all finite oracles, stated as a cardinality inequality. -/
theorem fixed_pair_card_le [Fintype Q] [DecidableEq Q]
    [Fintype D] [DecidableEq D]
    (q₀ q₁ : Q) (hne : q₀ ≠ q₁) :
    (Finset.filter (fun H : Q → D => H q₀ = H q₁) Finset.univ).card ≤
      (Fintype.card D) ^ (Fintype.card Q - 1) := by
  rw [← Fintype.card_subtype]
  calc
    Fintype.card {H : Q → D // H q₀ = H q₁}
        ≤ Fintype.card ({q : Q // q ≠ q₁} → D) :=
      Fintype.card_le_of_injective _ (eraseCoord_injective_on_equal q₀ q₁ hne)
    _ = (Fintype.card D) ^ Fintype.card {q : Q // q ≠ q₁} := by
      rw [Fintype.card_fun]
    _ = (Fintype.card D) ^ (Fintype.card Q - 1) := by
      congr 1
      simp

/-- Coarse birthday bound obtained by a union bound over ordered distinct
pairs. The sharper unordered-pair factor `1/2` can be layered on later; this
form is sufficient as a conservative adaptive answer-tape bound. -/
theorem noninjective_card_le_square [Fintype Q] [DecidableEq Q]
    [Fintype D] [DecidableEq D] :
    (Finset.filter (fun H : Q → D => ¬Function.Injective H)
      Finset.univ).card ≤
      Fintype.card Q * Fintype.card Q *
        (Fintype.card D) ^ (Fintype.card Q - 1) := by
  classical
  let pairs : Finset (Q × Q) :=
    (Finset.univ ×ˢ Finset.univ).filter (fun p => p.1 ≠ p.2)
  let Bad : (Q × Q) → (Q → D) → Prop := fun p H => H p.1 = H p.2
  have hevent :
      Finset.filter (fun H : Q → D => ¬Function.Injective H) Finset.univ =
      Finset.filter (fun H : Q → D => ∃ p ∈ pairs, Bad p H) Finset.univ := by
    ext H
    simp only [Finset.mem_filter, Finset.mem_univ, true_and]
    constructor
    · intro h
      rw [Function.not_injective_iff] at h
      rcases h with ⟨q₀, q₁, heq, hne⟩
      exact ⟨(q₀, q₁), by simp [pairs, hne], heq⟩
    · rintro ⟨⟨q₀, q₁⟩, hp, heq⟩ hinj
      have hne : q₀ ≠ q₁ := by simpa [pairs] using hp
      exact hne (hinj heq)
  rw [hevent]
  calc
    (Finset.filter (fun H : Q → D => ∃ p ∈ pairs, Bad p H)
        Finset.univ).card
        ≤ ∑ p ∈ pairs,
            (Finset.filter (Bad p) Finset.univ).card :=
      by
        let pieces : Q × Q → Finset (Q → D) :=
          fun p => Finset.filter (Bad p) Finset.univ
        have hp : Finset.filter
              (fun H : Q → D => ∃ p ∈ pairs, Bad p H) Finset.univ =
            pairs.biUnion pieces := by
          ext H
          simp [pieces]
        rw [hp]
        exact Finset.card_biUnion_le
    _ ≤ ∑ _p ∈ pairs,
          (Fintype.card D) ^ (Fintype.card Q - 1) := by
      apply Finset.sum_le_sum
      intro p hp
      change (Finset.filter (fun H : Q → D => H p.1 = H p.2)
        Finset.univ).card ≤ (Fintype.card D) ^ (Fintype.card Q - 1)
      exact fixed_pair_card_le (D := D) p.1 p.2
        (by simpa [pairs] using hp)
    _ = pairs.card * (Fintype.card D) ^ (Fintype.card Q - 1) := by simp
    _ ≤ (Fintype.card Q * Fintype.card Q) *
          (Fintype.card D) ^ (Fintype.card Q - 1) := by
      apply Nat.mul_le_mul_right
      calc
        pairs.card ≤ (Finset.univ ×ˢ (Finset.univ : Finset Q)).card :=
          Finset.card_le_card (Finset.filter_subset _ _)
        _ = Fintype.card Q * Fintype.card Q := by simp
    _ = Fintype.card Q * Fintype.card Q *
          (Fintype.card D) ^ (Fintype.card Q - 1) := rfl

/-- Conservative `t`-answer-tape birthday bound used by lazy-sampling
executions. Adaptive query choices do not affect this count because the tape
coordinates are sampled independently before execution. -/
theorem answerTape_birthday_card_le_square [Fintype D] [DecidableEq D]
    (t : ℕ) :
    (Finset.filter (fun answers : Fin t → D =>
      ¬Function.Injective answers) Finset.univ).card ≤
      t * t * (Fintype.card D) ^ (t - 1) := by
  simpa using (noninjective_card_le_square (Q := Fin t) (D := D))

/-- Exact fresh-pair kernel on an answer tape. -/
theorem answerTape_fixed_pair_card_le [Fintype D] [DecidableEq D]
    (t : ℕ) (i j : Fin t) (hne : i ≠ j) :
    (Finset.filter (fun answers : Fin t → D => answers i = answers j)
      Finset.univ).card ≤
      (Fintype.card D) ^ (t - 1) := by
  simpa using fixed_pair_card_le (D := D) i j hne

/-- The event that one of a finite collection of distinct answer-tape
coordinate pairs receives equal answers.  The pairs themselves are fixed by
the experiment layout; which pair witnesses failure may depend on all earlier
adaptive answers. -/
def PairCollision (T : ℕ) (pairs : Finset (Fin T × Fin T))
    (answers : Fin T → D) : Prop :=
  ∃ p ∈ pairs, answers p.1 = answers p.2

instance pairCollisionDecidable [DecidableEq D]
    (T : ℕ) (pairs : Finset (Fin T × Fin T)) :
    DecidablePred (PairCollision (D := D) T pairs) := by
  intro answers
  unfold PairCollision
  infer_instance

/-- Union bound for an arbitrary fixed family of answer-tape pairs.  This is
the useful fresh-coordinate lemma: adaptivity affects the queries stored in
the slots, but not the fact that each pair of distinct fresh slots agrees on
only a `1/|D|` fraction of tapes. -/
theorem answerTape_pairCollision_card_le
    [Fintype D] [DecidableEq D]
    (T : ℕ) (pairs : Finset (Fin T × Fin T))
    (hne : ∀ p ∈ pairs, p.1 ≠ p.2) :
    (Finset.filter (PairCollision (D := D) T pairs) Finset.univ).card ≤
      pairs.card * (Fintype.card D) ^ (T - 1) := by
  classical
  calc
    (Finset.filter (PairCollision (D := D) T pairs) Finset.univ).card ≤
        ∑ p ∈ pairs,
          (Finset.filter (fun answers : Fin T → D =>
            answers p.1 = answers p.2) Finset.univ).card := by
      let pieces : (Fin T × Fin T) → Finset (Fin T → D) :=
        fun p => Finset.filter (fun answers =>
          answers p.1 = answers p.2) Finset.univ
      have heq : Finset.filter (PairCollision T pairs) Finset.univ =
          pairs.biUnion pieces := by
        ext answers
        simp [PairCollision, pieces]
      rw [heq]
      exact Finset.card_biUnion_le
    _ ≤ ∑ _p ∈ pairs, (Fintype.card D) ^ (T - 1) := by
      exact Finset.sum_le_sum (fun p hp =>
        answerTape_fixed_pair_card_le T p.1 p.2 (hne p hp))
    _ = pairs.card * (Fintype.card D) ^ (T - 1) := by simp

/-- Generic union bound for a finite family of oracle bad events. -/
theorem card_iUnion_bad_le [Fintype Q] [DecidableEq Q]
    [Fintype D] [DecidableEq D]
    {ι : Type*} [DecidableEq ι]
    (s : Finset ι) (Bad : ι → (Q → D) → Prop)
    [∀ i, DecidablePred (Bad i)] :
    (Finset.filter (fun H => ∃ i ∈ s, Bad i H) Finset.univ).card ≤
      ∑ i ∈ s, (Finset.filter (Bad i) Finset.univ).card := by
  classical
  let pieces : ι → Finset (Q → D) :=
    fun i => Finset.filter (Bad i) Finset.univ
  have heq : Finset.filter (fun H => ∃ i ∈ s, Bad i H) Finset.univ =
      s.biUnion pieces := by
    ext H
    simp [pieces]
  rw [heq]
  exact Finset.card_biUnion_le

/-- A fixed set of guesses hits an injectively encoded uniform secret on at
most one secret per guess. This is the deterministic counting core of the
salt one-time lemma. -/
theorem injective_secret_hit_card_le
    {S : Type*} [Fintype S] [DecidableEq S]
    [Fintype Q] [DecidableEq Q]
    (encode : S → Q) (hinj : Function.Injective encode)
    (guesses : Finset Q) :
    (Finset.filter (fun s : S => encode s ∈ guesses) Finset.univ).card ≤
      guesses.card := by
  let f : {s : S // encode s ∈ guesses} → {q : Q // q ∈ guesses} :=
    fun s => ⟨encode s.val, s.property⟩
  have hf : Function.Injective f := by
    intro s t h
    apply Subtype.ext
    exact hinj (congrArg Subtype.val h)
  rw [← Fintype.card_subtype]
  simpa using Fintype.card_le_of_injective f hf

/-! ## Finite coupling interface -/

/-- Under a common finite coupling, every distinguisher's real acceptance
count is at most its simulated acceptance count plus the number of samples on
which the coupled views differ. -/
theorem real_count_le_sim_add_disagreement
    {Ω : Type*} {V : Type*}
    [Fintype Ω] [DecidableEq Ω] [DecidableEq V]
    (real sim : Ω → V) (P : V → Prop) [DecidablePred P] :
    (Finset.filter (fun ω => P (real ω)) Finset.univ).card ≤
      (Finset.filter (fun ω => P (sim ω)) Finset.univ).card +
      (Finset.filter (fun ω => real ω ≠ sim ω) Finset.univ).card := by
  let realEvent := Finset.filter (fun ω => P (real ω)) Finset.univ
  let simEvent := Finset.filter (fun ω => P (sim ω)) Finset.univ
  let bad := Finset.filter (fun ω => real ω ≠ sim ω) Finset.univ
  calc
    realEvent.card ≤ (simEvent ∪ bad).card := by
      apply Finset.card_le_card
      intro ω hω
      have hreal : P (real ω) := by simpa [realEvent] using hω
      by_cases hsim : P (sim ω)
      · exact Finset.mem_union_left _ (by simp [simEvent, hsim])
      · apply Finset.mem_union_right
        simp only [bad, Finset.mem_filter, Finset.mem_univ, true_and]
        intro heq
        apply hsim
        rwa [← heq]
    _ ≤ simEvent.card + bad.card := Finset.card_union_le _ _

/-- Symmetric half of the finite coupling bound. Together with the preceding
theorem this bounds the absolute distinguishing-count gap. -/
theorem sim_count_le_real_add_disagreement
    {Ω : Type*} {V : Type*}
    [Fintype Ω] [DecidableEq Ω] [DecidableEq V]
    (real sim : Ω → V) (P : V → Prop) [DecidablePred P] :
    (Finset.filter (fun ω => P (sim ω)) Finset.univ).card ≤
      (Finset.filter (fun ω => P (real ω)) Finset.univ).card +
      (Finset.filter (fun ω => real ω ≠ sim ω) Finset.univ).card := by
  simpa [ne_comm] using
    (real_count_le_sim_add_disagreement sim real P)

/-! ## Counting closeness and certified couplings -/

/-- Two views on a common finite uniform sample space are `eps`-close when
the chosen coupling disagrees on at most `eps` samples.  Its probability
interpretation is `eps / |Ω|`; keeping numerators avoids division and all
zero-denominator side conditions in the core lemmas. -/
def CountingClose {Ω : Type*} {V : Type*} [Fintype Ω]
    [DecidableEq Ω] [DecidableEq V]
    (eps : ℕ) (real sim : Ω → V) : Prop :=
  (Finset.filter (fun ω => real ω ≠ sim ω) Finset.univ).card ≤ eps

/-- A bad-event certificate is the form produced by lazy-sampling and hybrid
arguments: the coupled views agree off `bad`, whose size is bounded. -/
structure CouplingCertificate {Ω : Type*} {V : Type*}
    [Fintype Ω] [DecidableEq Ω]
    (eps : ℕ) (real sim : Ω → V) where
  bad : Finset Ω
  bad_card : bad.card ≤ eps
  agrees : ∀ ω ∉ bad, real ω = sim ω

/-- A certified good-outside-bad coupling gives counting closeness. -/
theorem CountingClose.of_certificate
    {Ω : Type*} {V : Type*}
    [Fintype Ω] [DecidableEq Ω] [DecidableEq V]
    {eps : ℕ} {real sim : Ω → V}
    (cert : CouplingCertificate eps real sim) :
    CountingClose eps real sim := by
  calc
    (Finset.filter (fun ω => real ω ≠ sim ω) Finset.univ).card ≤
        cert.bad.card := by
      apply Finset.card_le_card
      intro ω hω
      simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hω
      by_contra hnot
      exact hω (cert.agrees ω hnot)
    _ ≤ eps := cert.bad_card

/-- Counting closeness bounds both directions of every distinguisher's
acceptance-count gap. -/
theorem CountingClose.distinguisher
    {Ω : Type*} {V : Type*}
    [Fintype Ω] [DecidableEq Ω] [DecidableEq V]
    {eps : ℕ} {real sim : Ω → V}
    (hclose : CountingClose eps real sim)
    (P : V → Prop) [DecidablePred P] :
    (Finset.filter (fun ω => P (real ω)) Finset.univ).card ≤
        (Finset.filter (fun ω => P (sim ω)) Finset.univ).card + eps ∧
      (Finset.filter (fun ω => P (sim ω)) Finset.univ).card ≤
        (Finset.filter (fun ω => P (real ω)) Finset.univ).card + eps := by
  constructor
  · exact (real_count_le_sim_add_disagreement real sim P).trans
      (Nat.add_le_add_left hclose _)
  · exact (sim_count_le_real_add_disagreement real sim P).trans
      (Nat.add_le_add_left hclose _)

/-- Hybrid/triangle rule on a common coupling space. -/
theorem CountingClose.trans
    {Ω : Type*} {V : Type*}
    [Fintype Ω] [DecidableEq Ω] [DecidableEq V]
    {e₀ e₁ : ℕ} {v₀ v₁ v₂ : Ω → V}
    (h₀ : CountingClose e₀ v₀ v₁)
    (h₁ : CountingClose e₁ v₁ v₂) :
    CountingClose (e₀ + e₁) v₀ v₂ := by
  let bad₀ := Finset.filter (fun ω => v₀ ω ≠ v₁ ω) Finset.univ
  let bad₁ := Finset.filter (fun ω => v₁ ω ≠ v₂ ω) Finset.univ
  calc
    (Finset.filter (fun ω => v₀ ω ≠ v₂ ω) Finset.univ).card ≤
        (bad₀ ∪ bad₁).card := by
      apply Finset.card_le_card
      intro ω hω
      simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hω
      by_cases hmid : v₀ ω = v₁ ω
      · apply Finset.mem_union_right
        simp only [bad₁, Finset.mem_filter, Finset.mem_univ, true_and]
        intro hlast
        exact hω (hmid.trans hlast)
      · exact Finset.mem_union_left _ (by simp [bad₀, hmid])
    _ ≤ bad₀.card + bad₁.card := Finset.card_union_le _ _
    _ ≤ e₀ + e₁ := Nat.add_le_add h₀ h₁

/-- Exact ratio form of finite statistical closeness.  It states that the
disagreement probability is at most `numer / denom` by cross multiplication,
and therefore remains meaningful when the sample space contains arbitrary
additional oracle, simulator, or adversary coins. -/
def CountingCloseRatio {Ω : Type*} {V : Type*} [Fintype Ω]
    [DecidableEq Ω] [DecidableEq V]
    (numer denom : ℕ) (real sim : Ω → V) : Prop :=
  (Finset.filter (fun ω => real ω ≠ sim ω) Finset.univ).card * denom ≤
    numer * Fintype.card Ω

/-- A good-outside-bad coupling plus a normalized bound on `bad` yields an
exact statistical-distance ratio. -/
theorem CountingCloseRatio.of_bad
    {Ω : Type*} {V : Type*}
    [Fintype Ω] [DecidableEq Ω] [DecidableEq V]
    (numer denom : ℕ) (real sim : Ω → V) (bad : Finset Ω)
    (hbad : bad.card * denom ≤ numer * Fintype.card Ω)
    (hagrees : ∀ ω ∉ bad, real ω = sim ω) :
    CountingCloseRatio numer denom real sim := by
  have hsub : Finset.filter (fun ω => real ω ≠ sim ω) Finset.univ ⊆ bad := by
    intro ω hω
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hω
    by_contra hnot
    exact hω (hagrees ω hnot)
  exact (Nat.mul_le_mul_right denom (Finset.card_le_card hsub)).trans hbad

/-- Ratio closeness bounds the cross-multiplied acceptance counts of every
distinguisher in both directions. -/
theorem CountingCloseRatio.distinguisher
    {Ω : Type*} {V : Type*}
    [Fintype Ω] [DecidableEq Ω] [DecidableEq V]
    {numer denom : ℕ} {real sim : Ω → V}
    (hclose : CountingCloseRatio numer denom real sim)
    (P : V → Prop) [DecidablePred P] :
    (Finset.filter (fun ω => P (real ω)) Finset.univ).card * denom ≤
        (Finset.filter (fun ω => P (sim ω)) Finset.univ).card * denom +
          numer * Fintype.card Ω ∧
      (Finset.filter (fun ω => P (sim ω)) Finset.univ).card * denom ≤
        (Finset.filter (fun ω => P (real ω)) Finset.univ).card * denom +
          numer * Fintype.card Ω := by
  let disagree :=
    (Finset.filter (fun ω => real ω ≠ sim ω) Finset.univ).card
  have hr := real_count_le_sim_add_disagreement real sim P
  have hs := sim_count_le_real_add_disagreement real sim P
  constructor
  · calc
      (Finset.filter (fun ω => P (real ω)) Finset.univ).card * denom ≤
          ((Finset.filter (fun ω => P (sim ω)) Finset.univ).card +
            disagree) * denom := Nat.mul_le_mul_right denom hr
      _ = (Finset.filter (fun ω => P (sim ω)) Finset.univ).card * denom +
            disagree * denom := Nat.add_mul _ _ _
      _ ≤ (Finset.filter (fun ω => P (sim ω)) Finset.univ).card * denom +
            numer * Fintype.card Ω := Nat.add_le_add_left hclose _
  · calc
      (Finset.filter (fun ω => P (sim ω)) Finset.univ).card * denom ≤
          ((Finset.filter (fun ω => P (real ω)) Finset.univ).card +
            disagree) * denom := Nat.mul_le_mul_right denom hs
      _ = (Finset.filter (fun ω => P (real ω)) Finset.univ).card * denom +
            disagree * denom := Nat.add_mul _ _ _
      _ ≤ (Finset.filter (fun ω => P (real ω)) Finset.univ).card * denom +
            numer * Fintype.card Ω := Nat.add_le_add_left hclose _

end RandomOracle

end Merkle
