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
