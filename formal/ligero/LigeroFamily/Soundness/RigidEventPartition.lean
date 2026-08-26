import LigeroFamily.Soundness.EventPartition
import LigeroFamily.Soundness.AgreementProfile
import LigeroFamily.Soundness.PolicyEventPartition
import LigeroFamily.Soundness.RigidResponseList
import LigeroFamily.Soundness.ResponseAgreement
import Bcs.ResponseRigid
import Bcs.TypedFiatShamir
import Merkle.PrefixBinding
import Mathlib.Tactic.DeriveFintype

/-!
# Three semantic events as input to the response-rigid compiler

The Ligero event trichotomy is independent of random-oracle query order.  This
module refines each semantic event by the two possible first-occurrence orders
and aggregates the resulting six cells into `Bcs.RigidAttribution`.

No new ROM counting theorem is introduced: `toRigidAttribution` is an adapter
to the existing audited compiler.
-/

namespace LigeroFamily

open Finset
/-- The three semantic causes of a bad accepting Ligero transcript. -/
inductive SemanticEventKind
  | allErrors
  | linearErrors
  | badAlpha
  deriving DecidableEq, Fintype

noncomputable def eventSet {Ω : Type*} [Fintype Ω]
    (event : Ω → Prop) : Finset Ω := by
  classical
  exact univ.filter event

namespace ThreeEventPartition

def event {Ω : Type*} (P : ThreeEventPartition Ω) :
    SemanticEventKind → Ω → Prop
  | .allErrors => P.allErrors
  | .linearErrors => P.linearErrors
  | .badAlpha => P.badAlpha

theorem event_cases {Ω : Type*} (P : ThreeEventPartition Ω) (ω : Ω) :
    P.allErrors ω ∨ P.linearErrors ω ∨ P.badAlpha ω ↔
      ∃ kind, P.event kind ω := by
  constructor
  · rintro (hall | hlinear | hbad)
    · exact ⟨.allErrors, hall⟩
    · exact ⟨.linearErrors, hlinear⟩
    · exact ⟨.badAlpha, hbad⟩
  · rintro ⟨kind, hkind⟩
    cases kind with
    | allErrors => exact Or.inl hkind
    | linearErrors => exact Or.inr (Or.inl hkind)
    | badAlpha => exact Or.inr (Or.inr hkind)

end ThreeEventPartition

/-- First-occurrence attribution retaining the semantic event label.

`caseA` means the batching hash occurred first; `caseB` means the query-set
hash occurred first.  The event soundness fields make explicit that query
order refines, rather than replaces, the Ligero trichotomy.
-/
structure RigidThreeEventLedger (Ω : Type*) [Fintype Ω] (querySlots : ℕ) where
  partition : ThreeEventPartition Ω
  bindBreak : Ω → Prop
  caseA : SemanticEventKind → Fin querySlots → Ω → Prop
  caseB : SemanticEventKind → Fin querySlots → Ω → Prop
  bindBudget : ℕ
  caseAFloorBudget : SemanticEventKind → ℕ
  caseAListedBudget : SemanticEventKind → ℕ
  caseBAlphaLastBudget : SemanticEventKind → ℕ
  cover : ∀ ω, partition.win ω → bindBreak ω ∨
    ∃ kind i, caseA kind i ω ∨ caseB kind i ω
  caseA_sound : ∀ kind i ω, caseA kind i ω → partition.event kind ω
  caseB_sound : ∀ kind i ω, caseB kind i ω → partition.event kind ω
  bind_card : (eventSet bindBreak).card ≤ bindBudget
  caseA_card : ∀ kind i,
    (eventSet (caseA kind i)).card ≤
      caseAFloorBudget kind + caseAListedBudget kind
  caseB_card : ∀ kind i,
    (eventSet (caseB kind i)).card ≤ caseBAlphaLastBudget kind

namespace RigidThreeEventLedger

variable {Ω : Type*} [Fintype Ω] {querySlots : ℕ}

def aggregateCaseA
    (L : RigidThreeEventLedger Ω querySlots) (i : Fin querySlots) (ω : Ω) : Prop :=
  ∃ kind, L.caseA kind i ω

def aggregateCaseB
    (L : RigidThreeEventLedger Ω querySlots) (i : Fin querySlots) (ω : Ω) : Prop :=
  ∃ kind, L.caseB kind i ω

theorem aggregateCaseA_card_le (L : RigidThreeEventLedger Ω querySlots)
    (i : Fin querySlots) :
    (eventSet (L.aggregateCaseA i)).card ≤
      (∑ kind, L.caseAFloorBudget kind) +
        ∑ kind, L.caseAListedBudget kind := by
  classical
  let cells : Finset Ω := univ.biUnion fun kind : SemanticEventKind =>
    eventSet (L.caseA kind i)
  calc
    (univ.filter (L.aggregateCaseA i)).card ≤ cells.card := by
      apply Finset.card_le_card
      intro ω hω
      obtain ⟨kind, hkind⟩ := (Finset.mem_filter.mp hω).2
      exact Finset.mem_biUnion.mpr ⟨kind, Finset.mem_univ _,
        Finset.mem_filter.mpr ⟨Finset.mem_univ _, hkind⟩⟩
    _ ≤ ∑ kind : SemanticEventKind,
        (eventSet (L.caseA kind i)).card := by
      dsimp [cells]
      exact Finset.card_biUnion_le
    _ ≤ ∑ kind,
        (L.caseAFloorBudget kind + L.caseAListedBudget kind) :=
      Finset.sum_le_sum fun kind _ => L.caseA_card kind i
    _ = (∑ kind, L.caseAFloorBudget kind) +
        ∑ kind, L.caseAListedBudget kind := by
      rw [Finset.sum_add_distrib]

theorem aggregateCaseB_card_le (L : RigidThreeEventLedger Ω querySlots)
    (i : Fin querySlots) :
    (eventSet (L.aggregateCaseB i)).card ≤
      ∑ kind, L.caseBAlphaLastBudget kind := by
  classical
  let cells : Finset Ω := univ.biUnion fun kind : SemanticEventKind =>
    eventSet (L.caseB kind i)
  calc
    (univ.filter (L.aggregateCaseB i)).card ≤ cells.card := by
      apply Finset.card_le_card
      intro ω hω
      obtain ⟨kind, hkind⟩ := (Finset.mem_filter.mp hω).2
      exact Finset.mem_biUnion.mpr ⟨kind, Finset.mem_univ _,
        Finset.mem_filter.mpr ⟨Finset.mem_univ _, hkind⟩⟩
    _ ≤ ∑ kind : SemanticEventKind,
        (eventSet (L.caseB kind i)).card := by
      dsimp [cells]
      exact Finset.card_biUnion_le
    _ ≤ ∑ kind, L.caseBAlphaLastBudget kind :=
      Finset.sum_le_sum fun kind _ => L.caseB_card kind i

/-- Forget the semantic label after summing its three per-event budgets while
preserving the compiler's floor/listed/alpha-last split. -/
noncomputable def toRigidAttribution
    (L : RigidThreeEventLedger Ω querySlots) :
    Bcs.RigidAttribution Ω querySlots where
  win := L.partition.win
  bindBreak := L.bindBreak
  caseA := L.aggregateCaseA
  caseB := L.aggregateCaseB
  bindBudget := L.bindBudget
  caseAFloorBudget := ∑ kind, L.caseAFloorBudget kind
  caseAListedBudget := ∑ kind, L.caseAListedBudget kind
  caseBAlphaLastBudget := ∑ kind, L.caseBAlphaLastBudget kind
  cover ω hwin := by
    rcases L.cover ω hwin with hbind | ⟨kind, i, hA | hB⟩
    · exact Or.inl hbind
    · exact Or.inr (Or.inl ⟨i, kind, hA⟩)
    · exact Or.inr (Or.inr ⟨i, kind, hB⟩)
  bind_card := L.bind_card
  caseA_card i := by
    simpa [eventSet] using L.aggregateCaseA_card_le i
  caseB_card i := by
    simpa [eventSet] using L.aggregateCaseB_card_le i

/-- Finite-ROM cardinality bound with the three semantic budgets visible. -/
theorem rom_compiler_card_le (L : RigidThreeEventLedger Ω querySlots) :
    L.partition.winSet.card ≤
      L.bindBudget + querySlots *
        ((∑ kind, L.caseAFloorBudget kind) +
          (∑ kind, L.caseAListedBudget kind) +
          ∑ kind, L.caseBAlphaLastBudget kind) := by
  classical
  convert L.toRigidAttribution.rom_compiler_card_le using 1 <;>
    simp [toRigidAttribution, ThreeEventPartition.winSet]

/-- Probability form of the three-event response-rigid compiler. -/
theorem rom_compiler_ratio_le [Nonempty Ω]
    (L : RigidThreeEventLedger Ω querySlots) :
    (L.partition.winSet.card : ℚ) / Fintype.card Ω ≤
      (L.bindBudget + querySlots *
        ((∑ kind, L.caseAFloorBudget kind) +
          (∑ kind, L.caseAListedBudget kind) +
          ∑ kind, L.caseBAlphaLastBudget kind) : ℕ) /
            (Fintype.card Ω : ℚ) := by
  classical
  convert L.toRigidAttribution.rom_compiler_ratio_le using 1 <;>
    simp [toRigidAttribution, ThreeEventPartition.winSet]

end RigidThreeEventLedger

/-! ## Canonical first-occurrence constructor -/

namespace FirstOccurrenceEventLedger

variable {Ω Query : Type*} [Fintype Ω] [BEq Query] [LawfulBEq Query]
variable {querySlots : ℕ}

/-- Case A with the semantic Ligero event retained as a label. -/
def semanticCaseA (trace : Bcs.FirstOccurrenceTrace Ω Query querySlots)
    (partition : ThreeEventPartition Ω)
    (listed : SemanticEventKind → Ω → Prop) (bindBreak : Ω → Prop)
    (kind : SemanticEventKind) (i : Fin querySlots) (ω : Ω) : Prop :=
  partition.event kind ω ∧
    trace.caseA (listed kind) partition.win bindBreak i ω

/-- Case B with the semantic Ligero event retained as a label. -/
def semanticCaseB (trace : Bcs.FirstOccurrenceTrace Ω Query querySlots)
    (partition : ThreeEventPartition Ω) (bindBreak : Ω → Prop)
    (kind : SemanticEventKind) (i : Fin querySlots) (ω : Ω) : Prop :=
  partition.event kind ω ∧ trace.caseB partition.win bindBreak i ω

/-- Construct the complete three-event compiler input from a canonical
first-occurrence trace and event-specific cardinality bounds.

The operational order split is discharged here.  Callers only prove the
event-specific case-A and case-B counts.
-/
noncomputable def ofFirstOccurrence
    (trace : Bcs.FirstOccurrenceTrace Ω Query querySlots)
    (partition : ThreeEventPartition Ω)
    (listed : SemanticEventKind → Ω → Prop) (bindBreak : Ω → Prop)
    (bindBudget : ℕ)
    (caseAFloorBudget caseAListedBudget caseBAlphaLastBudget :
      SemanticEventKind → ℕ)
    (hbind : (eventSet bindBreak).card ≤ bindBudget)
    (hcaseA : ∀ kind i,
      (eventSet (semanticCaseA trace partition listed bindBreak kind i)).card ≤
        caseAFloorBudget kind + caseAListedBudget kind)
    (hcaseB : ∀ kind i,
      (eventSet (semanticCaseB trace partition bindBreak kind i)).card ≤
        caseBAlphaLastBudget kind) :
    RigidThreeEventLedger Ω querySlots where
  partition := partition
  bindBreak := bindBreak
  caseA := semanticCaseA trace partition listed bindBreak
  caseB := semanticCaseB trace partition bindBreak
  bindBudget := bindBudget
  caseAFloorBudget := caseAFloorBudget
  caseAListedBudget := caseAListedBudget
  caseBAlphaLastBudget := caseBAlphaLastBudget
  cover ω hwin := by
    by_cases hbindω : bindBreak ω
    · exact Or.inl hbindω
    · right
      have hevent : ∃ kind, partition.event kind ω :=
        (partition.event_cases ω).mp (partition.win_iff ω |>.mp hwin)
      obtain ⟨kind, hkind⟩ := hevent
      rcases lt_or_gt_of_ne (trace.idxOf_ne ω) with hbefore | hafter
      · by_cases hlisted : listed kind ω
        · let i : Fin querySlots :=
            ⟨(trace.trace ω).idxOf (trace.alphaQuery ω), trace.alpha_idx_lt ω⟩
          exact ⟨kind, i, Or.inl ⟨hkind, hwin, hbindω, hbefore,
            Or.inr ⟨hlisted, rfl⟩⟩⟩
        · let i : Fin querySlots :=
            ⟨(trace.trace ω).idxOf (trace.subsetQuery ω), trace.subset_idx_lt ω⟩
          exact ⟨kind, i, Or.inl ⟨hkind, hwin, hbindω, hbefore,
            Or.inl ⟨hlisted, rfl⟩⟩⟩
      · let i : Fin querySlots :=
          ⟨(trace.trace ω).idxOf (trace.subsetQuery ω), trace.subset_idx_lt ω⟩
        exact ⟨kind, i, Or.inr ⟨hkind, hwin, hbindω, rfl, hafter⟩⟩
  caseA_sound kind i ω hcase := hcase.1
  caseB_sound kind i ω hcase := hcase.1
  bind_card := hbind
  caseA_card := hcaseA
  caseB_card := hcaseB

end FirstOccurrenceEventLedger

/-! ## Theorem-derived typed-tape counts -/

namespace FirstOccurrenceEventLedger.TypedCounts

open Bcs.TypedFiatShamir

variable {Alpha Query : Type*} [Fintype Alpha] [DecidableEq Alpha]
variable [BEq Query] [LawfulBEq Query]
variable {n r T : ℕ}

/-! ## Prefix binding to the concrete Ligero oracle -/








theorem prefixBoundSchemeOpening_eq_claim
    {F CheckedMask DirectMask Salt D Enc Out RunOut : Type*}
    [Field F] [Inhabited Salt] [Inhabited D]
    [DecidableEq D] [DecidableEq Enc]
    {nw nq repetitions prefixFuel runFuel : ℕ}
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F CheckedMask DirectMask nw nq repetitions) D Enc)
    (game : Merkle.MH.PrefixBindingGame
      (Out := Out) (RunOut := RunOut) codec n T prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec)
    (answers : Fin T → D) (query : QuerySet n r)
    (hcoordinates : (game.claim answers).I = query.coordinates)
    (haccept : Merkle.MH.Accepts
      (codec.withOracle (game.oracle answers)) n (game.root answers)
      (game.claim answers).I (game.claim answers).a
      (game.claim answers).pf)
    (hgood : ¬game.Bad dec answers) :
    openSchemeOracle
        (SchemeOracle.ofColumns (game.boundMessage dec answers)) query =
      fun j ↦ (game.claim answers).a j.1 := by
  funext j
  rw [openSchemeOracle_ofColumns]
  by_contra hne
  apply hgood
  refine ⟨haccept, ⟨j.1, ?_, hne⟩⟩
  rw [hcoordinates]
  exact j.2

/-- Policy-level form of `prefixBoundSchemeOpening_eq_claim`: any Ligero
acceptance check performed against an accepted claimed Merkle opening can be
transported to the prefix-extracted total oracle, without an oracle-link
hypothesis. -/
theorem policy_accepts_of_prefixBinding
    {F Equations CheckedMask DirectMask Alpha Response Salt D Enc Out RunOut : Type*}
    [Field F] [Fintype Equations] [Fintype CheckedMask]
    [Inhabited Salt] [Inhabited D] [DecidableEq D] [DecidableEq Enc]
    {logicalWidth w nw nq repetitions prefixFuel runFuel : ℕ}
    (code : MultiplicativeCode F r w n)
    (layout : ConstraintLayout F logicalWidth w)
    (policy : SchemeProtocolPolicy (Equations := Equations) code layout
      Alpha Response CheckedMask DirectMask nw nq repetitions)
    (statement : ConstraintSystem F nw nq logicalWidth Equations)
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F CheckedMask DirectMask nw nq repetitions) D Enc)
    (game : Merkle.MH.PrefixBindingGame
      (Out := Out) (RunOut := RunOut) codec n T prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec)
    (answers : Fin T → D) (alpha : Alpha) (response : Response)
    (query : QuerySet n r)
    (hcoordinates : (game.claim answers).I = query.coordinates)
    (hmerkle : Merkle.MH.Accepts
      (codec.withOracle (game.oracle answers)) n (game.root answers)
      (game.claim answers).I (game.claim answers).a
      (game.claim answers).pf)
    (hgood : ¬game.Bad dec answers)
    (haccept : policy.accepts statement alpha response query
      (fun j ↦ (game.claim answers).a j.1)) :
    policy.accepts statement alpha response query
      (openSchemeOracle
        (SchemeOracle.ofColumns (game.boundMessage dec answers)) query) := by
  rw [prefixBoundSchemeOpening_eq_claim codec game dec answers query
    hcoordinates hmerkle hgood]
  exact haccept

/-- Query-dependent opening form of `policy_accepts_of_prefixBinding`.
The current FS tape selects the later Merkle run and claim, while the target
classifier oracle may use any reference index because the family shares one
root-exposure phase. -/
theorem policy_accepts_of_prefixBindingFamily
    {F Equations CheckedMask DirectMask Alpha Response Salt D Enc Index
      Out RunOut : Type*}
    [Field F] [Fintype Equations] [Fintype CheckedMask]
    [Inhabited Salt] [Inhabited D] [DecidableEq D] [DecidableEq Enc]
    {logicalWidth w nw nq repetitions prefixFuel runFuel : ℕ}
    (code : MultiplicativeCode F r w n)
    (layout : ConstraintLayout F logicalWidth w)
    (policy : SchemeProtocolPolicy (Equations := Equations) code layout
      Alpha Response CheckedMask DirectMask nw nq repetitions)
    (statement : ConstraintSystem F nw nq logicalWidth Equations)
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F CheckedMask DirectMask nw nq repetitions) D Enc)
    (family : Merkle.MH.PrefixBindingFamily
      (Out := Out) (RunOut := RunOut) codec Index n T prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec)
    (reference current : Index) (answers : Fin T → D)
    (alpha : Alpha) (response : Response) (query : QuerySet n r)
    (hcoordinates : ((family.game current).claim answers).I = query.coordinates)
    (hmerkle : Merkle.MH.Accepts
      (codec.withOracle ((family.game current).oracle answers)) n
      ((family.game current).root answers)
      ((family.game current).claim answers).I
      ((family.game current).claim answers).a
      ((family.game current).claim answers).pf)
    (hgood : ¬(family.game current).Bad dec answers)
    (haccept : policy.accepts statement alpha response query
      (fun j ↦ ((family.game current).claim answers).a j.1)) :
    policy.accepts statement alpha response query
      (openSchemeOracle
        (SchemeOracle.ofColumns
          ((family.game reference).boundMessage dec answers)) query) := by
  have hcurrent := policy_accepts_of_prefixBinding code layout policy statement
    codec (family.game current) dec answers alpha response query hcoordinates
      hmerkle hgood haccept
  rw [family.boundMessage_game_eq dec current reference answers] at hcurrent
  exact hcurrent

/-! ## Independent Merkle and Fiat--Shamir answer tapes -/

/-- A uniform fiberwise probability bound survives adjoining an independent
finite random tape.  This is the exact product-space lemma used to keep
Merkle-prefix extraction independent of the two typed Fiat--Shamir oracles. -/
theorem product_event_ratio_le_of_fiber
    {A B : Type*} [Fintype A] [Fintype B] [Nonempty A] [Nonempty B]
    (event : A → B → Prop) [∀ a, DecidablePred (event a)]
    (epsilon : ℚ)
    (hfiber : ∀ a, ((Finset.univ.filter (event a)).card : ℚ) /
      Fintype.card B ≤ epsilon) :
    ((Finset.univ.filter fun value : A × B ↦
        event value.1 value.2).card : ℚ) /
          Fintype.card (A × B) ≤ epsilon := by
  classical
  have hA : (0 : ℚ) < Fintype.card A := by
    exact_mod_cast Fintype.card_pos
  have hB : (0 : ℚ) < Fintype.card B := by
    exact_mod_cast Fintype.card_pos
  rw [Bcs.card_filter_prod_fst, Fintype.card_prod]
  push_cast
  rw [div_le_iff₀ (mul_pos hA hB)]
  calc
    (∑ a : A, ((Finset.univ.filter (event a)).card : ℚ))
        ≤ ∑ _a : A, epsilon * Fintype.card B := by
          apply Finset.sum_le_sum
          intro a _
          exact (div_le_iff₀ hB).mp (hfiber a)
    _ = epsilon * (Fintype.card A * Fintype.card B) := by
      simp
      ring

/-- Symmetric form of `product_event_ratio_le_of_fiber`, slicing on the
second independent component. -/
theorem product_event_ratio_le_of_second_fiber
    {A B : Type*} [Fintype A] [Fintype B] [Nonempty A] [Nonempty B]
    (event : A → B → Prop) [∀ b, DecidablePred (fun a ↦ event a b)]
    (epsilon : ℚ)
    (hfiber : ∀ b, ((Finset.univ.filter fun a ↦ event a b).card : ℚ) /
      Fintype.card A ≤ epsilon) :
    ((Finset.univ.filter fun value : A × B ↦
        event value.1 value.2).card : ℚ) /
          Fintype.card (A × B) ≤ epsilon := by
  classical
  have hA : (0 : ℚ) < Fintype.card A := by
    exact_mod_cast Fintype.card_pos
  have hB : (0 : ℚ) < Fintype.card B := by
    exact_mod_cast Fintype.card_pos
  rw [Bcs.card_filter_prod_snd, Fintype.card_prod]
  push_cast
  rw [div_le_iff₀ (mul_pos hA hB)]
  calc
    (∑ b : B, ((Finset.univ.filter fun a : A ↦ event a b).card : ℚ))
        ≤ ∑ _b : B, epsilon * Fintype.card A := by
          apply Finset.sum_le_sum
          intro b _
          exact (div_le_iff₀ hA).mp (hfiber b)
    _ = epsilon * (Fintype.card A * Fintype.card B) := by
      simp
      ring

/-- An event depending only on the first component of an independent product
has exactly its original density. -/
theorem first_projection_event_ratio_eq
    {A B : Type*} [Fintype A] [Fintype B] [Nonempty B]
    (event : A → Prop) [DecidablePred event] :
    ((Finset.univ.filter fun value : A × B ↦ event value.1).card : ℚ) /
        Fintype.card (A × B) =
      ((Finset.univ.filter event).card : ℚ) / Fintype.card A := by
  classical
  have hB : (Fintype.card B : ℚ) ≠ 0 := by
    exact_mod_cast Nat.ne_of_gt (Fintype.card_pos : 0 < Fintype.card B)
  rw [Bcs.card_filter_prod_fst, Fintype.card_prod]
  have hsum :
      (∑ a : A, (Finset.univ.filter fun _b : B ↦ event a).card) =
        (Finset.univ.filter event).card * Fintype.card B := by
    calc
      (∑ a : A, (Finset.univ.filter fun _b : B ↦ event a).card) =
          ∑ a : A, if event a then Fintype.card B else 0 := by
            apply Finset.sum_congr rfl
            intro a _
            by_cases ha : event a <;> simp [ha]
      _ = (Finset.univ.filter event).card * Fintype.card B := by
        rw [← Finset.sum_filter]
        simp
  rw [hsum]
  push_cast
  field_simp [hB]

/-- Exact profile-integrated incidence density for independent `(query,alpha)`
pairs.  This is the threshold-free Case-B kernel: every tail level is backed
by `hdensity`, and the hypergeometric cover is integrated rather than cut at
an assumed universal threshold. -/
theorem profiled_incidence_ratio_le
    [Nonempty Alpha]
    (selected : Finset Alpha) (allowed : Alpha → Finset (Fin n))
    (profile : AgreementProfile n) (q : ℕ) (hq : 0 < q)
    (hdensity : ∀ a ≤ n,
      q * (AgreementProfile.restrictedTailSet selected
        (fun alpha ↦ (allowed alpha).card) a).card ≤
          profile.labelsAtLeast a * Fintype.card Alpha) :
    ((Finset.univ.filter fun pair : QuerySet n r × Alpha ↦
      pair.2 ∈ selected ∧ pair.1.coordinates ⊆ allowed pair.2).card : ℚ) /
        Fintype.card (QuerySet n r × Alpha) ≤
      profile.contribution q n n 0 r := by
  classical
  let agreement : Alpha → ℕ := fun alpha ↦ (allowed alpha).card
  have hagreement (alpha : Alpha) : agreement alpha ≤ n := by
    simpa [agreement] using
      Finset.card_le_card (Finset.subset_univ (allowed alpha))
  have hpairs :
      (Finset.univ.filter fun pair : QuerySet n r × Alpha ↦
        pair.2 ∈ selected ∧ pair.1.coordinates ⊆ allowed pair.2).card =
        ∑ alpha ∈ selected, (agreement alpha).choose r := by
    rw [Bcs.card_filter_prod_snd]
    calc
      ∑ alpha, (Finset.univ.filter fun query : QuerySet n r ↦
          (query, alpha).2 ∈ selected ∧
            (query, alpha).1.coordinates ⊆ allowed (query, alpha).2).card =
          ∑ alpha, if alpha ∈ selected then (agreement alpha).choose r else 0 := by
            apply Finset.sum_congr rfl
            intro alpha _
            by_cases hselected : alpha ∈ selected
            · simp only [hselected, true_and, ↓reduceIte]
              change (queriesWithin (r := r) (allowed alpha)).card = _
              simpa [agreement] using card_queriesWithin (r := r) (allowed alpha)
            · simp [hselected]
      _ = ∑ alpha ∈ selected, (agreement alpha).choose r := by
        rw [← Finset.sum_filter]
        rw [Finset.filter_univ_mem]
  have haverage := profile.restricted_average_coverRatio_le_contribution
    q n n 0 r selected agreement hq
    (fun alpha _ ↦ hagreement alpha) hdensity
  rw [hpairs, Fintype.card_prod, QuerySet.fintype_card]
  push_cast
  calc
    (∑ alpha ∈ selected, ((agreement alpha).choose r : ℚ)) /
          ((n.choose r : ℚ) * Fintype.card Alpha) =
        (∑ alpha ∈ selected,
          AgreementProfile.coverRatio n n 0 r (agreement alpha)) /
            Fintype.card Alpha := by
      rw [show
        (∑ alpha ∈ selected, ((agreement alpha).choose r : ℚ)) /
              ((n.choose r : ℚ) * Fintype.card Alpha) =
            ((∑ alpha ∈ selected, ((agreement alpha).choose r : ℚ)) /
              (n.choose r : ℚ)) / Fintype.card Alpha by ring]
      congr 1
      rw [div_eq_mul_inv, Finset.sum_mul]
      apply Finset.sum_congr rfl
      intro alpha _
      simp only [AgreementProfile.coverRatio, hypergeometricRatio]
      have hzero : n - n - 1 = 0 := by omega
      rw [hzero, Nat.zero_add, min_eq_right (hagreement alpha),
        max_eq_right (Nat.zero_le _)]
      rw [div_eq_mul_inv]
    _ ≤ profile.contribution q n n 0 r := haverage

omit [DecidableEq Alpha] in
/-- Unused projections in two typed oracle answers cancel exactly.  A relation
between the subset projection of the first answer and the alpha projection of
the second has the same density as the underlying independent
`(query,alpha)` relation. -/
theorem answer_pair_incidence_ratio_eq
    {Subset : Type*} [Fintype Subset] [DecidableEq Subset]
    [Nonempty Alpha] [Nonempty Subset]
    (success : Subset → Alpha → Prop) [DecidableRel success] :
    ((Finset.univ.filter fun pair : Answer Alpha Subset × Answer Alpha Subset ↦
      success (subsetAnswer pair.1) (alphaAnswer pair.2)).card : ℚ) /
        Fintype.card (Answer Alpha Subset × Answer Alpha Subset) =
      ((Finset.univ.filter fun pair : Subset × Alpha ↦
        success pair.1 pair.2).card : ℚ) /
          Fintype.card (Subset × Alpha) := by
  classical
  have hfull :
      (Finset.univ.filter fun pair : Answer Alpha Subset × Answer Alpha Subset ↦
        success (subsetAnswer pair.1) (alphaAnswer pair.2)).card =
        Fintype.card (Answer Alpha Subset) *
          (Finset.univ.filter fun pair : Subset × Alpha ↦
            success pair.1 pair.2).card := by
    rw [Bcs.card_filter_prod_fst]
    calc
      ∑ first : Answer Alpha Subset,
          (Finset.univ.filter fun second : Answer Alpha Subset ↦
            success (subsetAnswer first) (alphaAnswer second)).card =
          ∑ first : Answer Alpha Subset,
            Fintype.card Subset *
              (Finset.univ.filter fun alpha : Alpha ↦
                success (subsetAnswer first) alpha).card := by
            apply Finset.sum_congr rfl
            intro first _
            exact alpha_projection_card
              (fun alpha ↦ success (subsetAnswer first) alpha)
      _ = Fintype.card Subset *
          ∑ first : Answer Alpha Subset,
            (Finset.univ.filter fun alpha : Alpha ↦
              success (subsetAnswer first) alpha).card := by
            rw [Finset.mul_sum]
      _ = Fintype.card Subset * Fintype.card Alpha *
          ∑ subset : Subset,
            (Finset.univ.filter fun alpha : Alpha ↦ success subset alpha).card := by
            simp only [Answer, subsetAnswer, Fintype.sum_prod_type]
            simp [Finset.sum_const]
            ring
      _ = Fintype.card (Answer Alpha Subset) *
          (Finset.univ.filter fun pair : Subset × Alpha ↦
            success pair.1 pair.2).card := by
            rw [Bcs.card_filter_prod_fst]
            simp only [Answer, Fintype.card_prod]
            ring
  rw [hfull]
  simp only [Answer, Fintype.card_prod, Nat.cast_mul]
  have hAlpha : (Fintype.card Alpha : ℚ) ≠ 0 := by
    exact_mod_cast Nat.ne_of_gt (Fintype.card_pos : 0 < Fintype.card Alpha)
  have hSubset : (Fintype.card Subset : ℚ) ≠ 0 := by
    exact_mod_cast Nat.ne_of_gt (Fintype.card_pos : 0 < Fintype.card Subset)
  field_simp [hAlpha, hSubset]

omit [DecidableEq Alpha] in
/-- Lift any proved semantic pair-density bound to the full paired-answer
space, with the unused typed-oracle projections cancelling exactly. -/
theorem answer_pair_incidence_ratio_le_of_pair_ratio
    {Subset : Type*} [Fintype Subset] [DecidableEq Subset]
    [Nonempty Alpha] [Nonempty Subset]
    (success : Subset → Alpha → Prop) [DecidableRel success]
    (epsilon : ℚ)
    (hsemantic : ((Finset.univ.filter fun pair : Subset × Alpha ↦
      success pair.1 pair.2).card : ℚ) /
        Fintype.card (Subset × Alpha) ≤ epsilon) :
    ((Finset.univ.filter fun pair : Answer Alpha Subset × Answer Alpha Subset ↦
      success (subsetAnswer pair.1) (alphaAnswer pair.2)).card : ℚ) /
        Fintype.card (Answer Alpha Subset × Answer Alpha Subset) ≤ epsilon :=
  (answer_pair_incidence_ratio_eq success).trans_le hsemantic

omit [DecidableEq Alpha] in
/-- The reversed order used by Case A has the same exact cancellation: alpha
is read from the charged first answer and the subset from the later answer. -/
theorem answer_pair_reverse_incidence_ratio_eq
    {Subset : Type*} [Fintype Subset] [DecidableEq Subset]
    [Nonempty Alpha] [Nonempty Subset]
    (success : Subset → Alpha → Prop) [DecidableRel success] :
    ((Finset.univ.filter fun pair : Answer Alpha Subset × Answer Alpha Subset ↦
      success (subsetAnswer pair.2) (alphaAnswer pair.1)).card : ℚ) /
        Fintype.card (Answer Alpha Subset × Answer Alpha Subset) =
      ((Finset.univ.filter fun pair : Subset × Alpha ↦
        success pair.1 pair.2).card : ℚ) /
          Fintype.card (Subset × Alpha) := by
  classical
  let left : Finset (Answer Alpha Subset × Answer Alpha Subset) :=
    Finset.univ.filter fun pair ↦
      success (subsetAnswer pair.2) (alphaAnswer pair.1)
  let right : Finset (Answer Alpha Subset × Answer Alpha Subset) :=
    Finset.univ.filter fun pair ↦
      success (subsetAnswer pair.1) (alphaAnswer pair.2)
  let swap : (↑left) ≃ (↑right) :=
    { toFun := fun pair ↦ ⟨pair.1.swap, by
        have hp := (Finset.mem_filter.mp pair.2).2
        exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, hp⟩⟩
      invFun := fun pair ↦ ⟨pair.1.swap, by
        have hp := (Finset.mem_filter.mp pair.2).2
        exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, hp⟩⟩
      left_inv := fun _ ↦ rfl
      right_inv := fun _ ↦ rfl }
  have hcard : left.card = right.card := by
    calc
      left.card = Fintype.card (↑left) := by simp
      _ = Fintype.card (↑right) := Fintype.card_congr swap
      _ = right.card := by simp
  change (left.card : ℚ) /
      Fintype.card (Answer Alpha Subset × Answer Alpha Subset) = _
  rw [hcard]
  exact answer_pair_incidence_ratio_eq success

omit [DecidableEq Alpha] in
/-- Reverse-order lift of a proved semantic pair density. -/
theorem answer_pair_reverse_incidence_ratio_le_of_pair_ratio
    {Subset : Type*} [Fintype Subset] [DecidableEq Subset]
    [Nonempty Alpha] [Nonempty Subset]
    (success : Subset → Alpha → Prop) [DecidableRel success]
    (epsilon : ℚ)
    (hsemantic : ((Finset.univ.filter fun pair : Subset × Alpha ↦
      success pair.1 pair.2).card : ℚ) /
        Fintype.card (Subset × Alpha) ≤ epsilon) :
    ((Finset.univ.filter fun pair : Answer Alpha Subset × Answer Alpha Subset ↦
      success (subsetAnswer pair.2) (alphaAnswer pair.1)).card : ℚ) /
        Fintype.card (Answer Alpha Subset × Answer Alpha Subset) ≤ epsilon :=
  (answer_pair_reverse_incidence_ratio_eq success).trans_le hsemantic

omit [DecidableEq Alpha] in
/-- Retaining a final response in Case A costs exactly its semantic list
size, while the two unused typed-answer projections still cancel.  The
denominator deliberately contains only the two oracle answers: summing over
`Response` is the response-list charge that remains visible on the right. -/
theorem answer_response_reverse_incidence_ratio_eq
    {Subset Response : Type*}
    [Fintype Subset] [DecidableEq Subset]
    [Fintype Response] [DecidableEq Response]
    [Nonempty Alpha] [Nonempty Subset]
    (success : Response → Subset → Alpha → Prop)
    [∀ response, DecidableRel (success response)] :
    ((Finset.univ.filter fun value :
        (Answer Alpha Subset × Response) × Answer Alpha Subset ↦
      success value.1.2 (subsetAnswer value.2)
        (alphaAnswer value.1.1)).card : ℚ) /
          (Fintype.card (Answer Alpha Subset) *
            Fintype.card (Answer Alpha Subset)) =
      ((Finset.univ.filter fun value : Response × (Subset × Alpha) ↦
        success value.1 value.2.1 value.2.2).card : ℚ) /
          Fintype.card (Subset × Alpha) := by
  classical
  let full : Finset
      ((Answer Alpha Subset × Response) × Answer Alpha Subset) :=
    Finset.univ.filter fun value ↦
      success value.1.2 (subsetAnswer value.2) (alphaAnswer value.1.1)
  let semantic : Finset (Response × (Subset × Alpha)) :=
    Finset.univ.filter fun value ↦ success value.1 value.2.1 value.2.2
  let split : (↑full) ≃ Answer Alpha Subset × (↑semantic) :=
    { toFun := fun value ↦
        ((alphaAnswer value.1.2, subsetAnswer value.1.1.1),
          ⟨(value.1.1.2,
              (subsetAnswer value.1.2, alphaAnswer value.1.1.1)), by
            exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
              (Finset.mem_filter.mp value.2).2⟩⟩)
      invFun := fun value ↦
        ⟨(((value.2.1.2.2, value.1.2), value.2.1.1),
            (value.1.1, value.2.1.2.1)), by
          exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
            (Finset.mem_filter.mp value.2.2).2⟩⟩
      left_inv := fun value ↦ by
        apply Subtype.ext
        rcases value with
          ⟨⟨⟨⟨alpha, subset⟩, response⟩,
            ⟨unusedAlpha, selectedSubset⟩⟩, hfull⟩
        simp [alphaAnswer, subsetAnswer]
      right_inv := fun value ↦ by
        apply Prod.ext
        · rfl
        · apply Subtype.ext
          rcases value with ⟨⟨unusedAlpha, subset⟩,
            ⟨⟨response, selectedSubset, alpha⟩, hsemantic⟩⟩
          simp [alphaAnswer, subsetAnswer] }
  have hcard : full.card = Fintype.card (Answer Alpha Subset) * semantic.card := by
    calc
      full.card = Fintype.card (↑full) := by simp
      _ = Fintype.card (Answer Alpha Subset × (↑semantic)) :=
        Fintype.card_congr split
      _ = Fintype.card (Answer Alpha Subset) * semantic.card := by simp
  change (full.card : ℚ) /
      (Fintype.card (Answer Alpha Subset) *
        Fintype.card (Answer Alpha Subset)) =
    (semantic.card : ℚ) / Fintype.card (Subset × Alpha)
  rw [hcard]
  simp only [Answer, Fintype.card_prod, Nat.cast_mul]
  have hAlpha : (Fintype.card Alpha : ℚ) ≠ 0 := by
    exact_mod_cast Nat.ne_of_gt (Fintype.card_pos : 0 < Fintype.card Alpha)
  have hSubset : (Fintype.card Subset : ℚ) ≠ 0 := by
    exact_mod_cast Nat.ne_of_gt (Fintype.card_pos : 0 < Fintype.card Subset)
  field_simp [hAlpha, hSubset]

omit [DecidableEq Alpha] in
/-- Inequality form of `answer_response_reverse_incidence_ratio_eq`. -/
theorem answer_response_reverse_incidence_ratio_le
    {Subset Response : Type*}
    [Fintype Subset] [DecidableEq Subset]
    [Fintype Response] [DecidableEq Response]
    [Nonempty Alpha] [Nonempty Subset]
    (success : Response → Subset → Alpha → Prop)
    [∀ response, DecidableRel (success response)]
    (epsilon : ℚ)
    (hsemantic :
      ((Finset.univ.filter fun value : Response × (Subset × Alpha) ↦
        success value.1 value.2.1 value.2.2).card : ℚ) /
          Fintype.card (Subset × Alpha) ≤ epsilon) :
    ((Finset.univ.filter fun value :
        (Answer Alpha Subset × Response) × Answer Alpha Subset ↦
      success value.1.2 (subsetAnswer value.2)
        (alphaAnswer value.1.1)).card : ℚ) /
          (Fintype.card (Answer Alpha Subset) *
            Fintype.card (Answer Alpha Subset)) ≤ epsilon :=
  (answer_response_reverse_incidence_ratio_eq success).trans_le hsemantic

omit [DecidableEq Alpha] in
/-- A proved finite response list multiplies a strategy-uniform independent
`(query, alpha)` density and nothing else.  This is the semantic Case-A
bridge between the Johnson response-list theorem and the profiled MCA master
theorem. -/
theorem response_list_pair_ratio_le
    {Subset Response : Type*}
    [Fintype Subset] [DecidableEq Subset]
    [Fintype Response] [DecidableEq Response]
    [Nonempty Alpha] [Nonempty Subset]
    (responses : Finset Response)
    (success : Response → Subset → Alpha → Prop)
    [∀ response, DecidableRel (success response)]
    (epsilon : ℚ) (listBound : ℕ)
    (hepsilon : 0 ≤ epsilon)
    (hlist : responses.card ≤ listBound)
    (hmember : ∀ response subset alpha,
      success response subset alpha → response ∈ responses)
    (hpairs : ∀ response ∈ responses,
      ((Finset.univ.filter fun pair : Subset × Alpha ↦
        success response pair.1 pair.2).card : ℚ) /
          Fintype.card (Subset × Alpha) ≤ epsilon) :
    ((Finset.univ.filter fun value : Response × (Subset × Alpha) ↦
      success value.1 value.2.1 value.2.2).card : ℚ) /
        Fintype.card (Subset × Alpha) ≤ listBound * epsilon := by
  classical
  have hden : (0 : ℚ) < Fintype.card (Subset × Alpha) := by
    exact_mod_cast Fintype.card_pos
  rw [div_le_iff₀ hden]
  rw [Bcs.card_filter_prod_fst]
  push_cast
  calc
    (∑ response : Response,
        ((Finset.univ.filter fun pair : Subset × Alpha ↦
          success response pair.1 pair.2).card : ℚ))
      ≤ ∑ response : Response,
          if response ∈ responses then
            epsilon * Fintype.card (Subset × Alpha) else 0 := by
        apply Finset.sum_le_sum
        intro response _
        by_cases hresponse : response ∈ responses
        · simp only [hresponse, ↓reduceIte]
          exact (div_le_iff₀ hden).mp (hpairs response hresponse)
        · simp only [hresponse, ↓reduceIte]
          have hempty : (Finset.univ.filter fun pair : Subset × Alpha ↦
              success response pair.1 pair.2) = ∅ := by
            ext pair
            constructor
            · intro hpair
              exact (hresponse (hmember response pair.1 pair.2
                (Finset.mem_filter.mp hpair).2)).elim
            · intro hpair
              simp at hpair
          rw [hempty]
          simp
    _ = responses.card *
          (epsilon * Fintype.card (Subset × Alpha)) := by
        simp
    _ ≤ listBound *
          (epsilon * Fintype.card (Subset × Alpha)) := by
        exact mul_le_mul_of_nonneg_right (by exact_mod_cast hlist)
          (mul_nonneg hepsilon hden.le)
    _ = (listBound * epsilon) *
          Fintype.card (Subset × Alpha) := by ring

omit [Fintype Alpha] [DecidableEq Alpha] in
/-- Uniformly enumerate alpha-indexed response lists by full response
strategies.  The same rank is used across all alphas; missing ranks are filled
with an arbitrary default response. -/
theorem exists_indexed_response_strategies
    {Response : Type*} [Fintype Response] [DecidableEq Response]
    [Nonempty Response]
    (responses : Alpha → Finset Response) (listBound : ℕ)
    (hlist : ∀ alpha, (responses alpha).card ≤ listBound) :
    ∃ strategy : Fin listBound → Alpha → Response,
      ∀ alpha response, response ∈ responses alpha →
        ∃ rank, strategy rank alpha = response := by
  classical
  let default : Response := Classical.choice inferInstance
  let strategy : Fin listBound → Alpha → Response := fun rank alpha ↦
    if h : rank.val < (responses alpha).card then
      ((responses alpha).equivFin.symm ⟨rank.val, h⟩).1
    else default
  refine ⟨strategy, ?_⟩
  intro alpha response hresponse
  let small : Fin (responses alpha).card :=
    (responses alpha).equivFin ⟨response, hresponse⟩
  let rank : Fin listBound :=
    ⟨small.val, small.isLt.trans_le (hlist alpha)⟩
  refine ⟨rank, ?_⟩
  simp only [strategy, rank, small, dif_pos small.isLt]
  exact congrArg Subtype.val
    ((responses alpha).equivFin.symm_apply_apply ⟨response, hresponse⟩)

omit [DecidableEq Alpha] in
/-- An alpha-indexed Johnson list costs its maximum list size times a bound
that holds for every complete response strategy.  This is the correct
response-rigid semantic theorem: it does not replace the indexed lists by an
unproved global response list. -/
theorem indexed_response_lists_pair_ratio_le
    {Subset Response : Type*}
    [Fintype Subset] [DecidableEq Subset]
    [Fintype Response] [DecidableEq Response]
    [Nonempty Alpha] [Nonempty Subset] [Nonempty Response]
    (responses : Alpha → Finset Response)
    (success : Response → Subset → Alpha → Prop)
    [∀ response, DecidableRel (success response)]
    (epsilon : ℚ) (listBound : ℕ)
    (hlist : ∀ alpha, (responses alpha).card ≤ listBound)
    (hmember : ∀ response subset alpha,
      success response subset alpha → response ∈ responses alpha)
    (hstrategy : ∀ strategy : Alpha → Response,
      ((Finset.univ.filter fun pair : Subset × Alpha ↦
        success (strategy pair.2) pair.1 pair.2).card : ℚ) /
          Fintype.card (Subset × Alpha) ≤ epsilon) :
    ((Finset.univ.filter fun value : Response × (Subset × Alpha) ↦
      success value.1 value.2.1 value.2.2).card : ℚ) /
        Fintype.card (Subset × Alpha) ≤ listBound * epsilon := by
  classical
  obtain ⟨strategy, hstrategyCover⟩ :=
    exists_indexed_response_strategies responses listBound hlist
  let full : Finset (Response × (Subset × Alpha)) :=
    Finset.univ.filter fun value ↦ success value.1 value.2.1 value.2.2
  let piece (rank : Fin listBound) : Finset (Response × (Subset × Alpha)) :=
    Finset.univ.filter fun value ↦
      value.1 = strategy rank value.2.2 ∧
        success value.1 value.2.1 value.2.2
  have hcover : full ⊆ Finset.univ.biUnion piece := by
    intro value hvalue
    have hsuccess := (Finset.mem_filter.mp hvalue).2
    obtain ⟨rank, hrank⟩ := hstrategyCover value.2.2 value.1
      (hmember value.1 value.2.1 value.2.2 hsuccess)
    exact Finset.mem_biUnion.mpr ⟨rank, Finset.mem_univ _,
      Finset.mem_filter.mpr ⟨Finset.mem_univ _, hrank.symm, hsuccess⟩⟩
  have hpiece (rank : Fin listBound) :
      (piece rank).card =
        (Finset.univ.filter fun pair : Subset × Alpha ↦
          success (strategy rank pair.2) pair.1 pair.2).card := by
    dsimp [piece]
    rw [Bcs.card_filter_prod_snd]
    have hrhs :
        (Finset.univ.filter fun pair : Subset × Alpha ↦
          success (strategy rank pair.2) pair.1 pair.2).card =
        ∑ pair : Subset × Alpha,
          if success (strategy rank pair.2) pair.1 pair.2 then 1 else 0 := by
      rw [← Finset.sum_filter]
      simp
    rw [hrhs]
    apply Finset.sum_congr rfl
    intro pair _
    by_cases hs : success (strategy rank pair.2) pair.1 pair.2
    · have heq : (Finset.univ.filter fun response : Response ↦
          response = strategy rank pair.2 ∧
            success response pair.1 pair.2).card = 1 := by
        rw [show (Finset.univ.filter fun response : Response ↦
            response = strategy rank pair.2 ∧
              success response pair.1 pair.2) =
            {strategy rank pair.2} by
          ext response
          constructor
          · intro hresponse
            have heq := (Finset.mem_filter.mp hresponse).2.1
            simpa using heq
          · intro hresponse
            have heq : response = strategy rank pair.2 := by
              simpa using hresponse
            subst response
            exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, rfl, hs⟩]
        simp
      rw [heq]
      rw [if_pos hs]
    · have heq : (Finset.univ.filter fun response : Response ↦
          response = strategy rank pair.2 ∧
            success response pair.1 pair.2).card = 0 := by
        rw [show (Finset.univ.filter fun response : Response ↦
            response = strategy rank pair.2 ∧
              success response pair.1 pair.2) = ∅ by
          ext response
          constructor
          · intro hresponse
            have h := (Finset.mem_filter.mp hresponse).2
            exact (hs (h.1 ▸ h.2)).elim
          · intro hresponse
            simp at hresponse]
        simp
      rw [heq]
      rw [if_neg hs]
  have hden : (0 : ℚ) < Fintype.card (Subset × Alpha) := by
    exact_mod_cast Fintype.card_pos
  change (full.card : ℚ) / Fintype.card (Subset × Alpha) ≤ _
  rw [div_le_iff₀ hden]
  have hcard : full.card ≤ ∑ rank : Fin listBound, (piece rank).card :=
    (Finset.card_le_card hcover).trans Finset.card_biUnion_le
  calc
    (full.card : ℚ) ≤ ∑ rank : Fin listBound, ((piece rank).card : ℚ) := by
      exact_mod_cast hcard
    _ = ∑ rank : Fin listBound,
        ((Finset.univ.filter fun pair : Subset × Alpha ↦
          success (strategy rank pair.2) pair.1 pair.2).card : ℚ) := by
      apply Finset.sum_congr rfl
      intro rank _
      exact_mod_cast hpiece rank
    _ ≤ ∑ _rank : Fin listBound,
        epsilon * Fintype.card (Subset × Alpha) := by
      apply Finset.sum_le_sum
      intro rank _
      exact (div_le_iff₀ hden).mp (hstrategy (strategy rank))
    _ = listBound * (epsilon * Fintype.card (Subset × Alpha)) := by simp
    _ = (listBound * epsilon) * Fintype.card (Subset × Alpha) := by ring

omit [DecidableEq Alpha] in
/-- Actual-verifier specialization of `response_list_pair_ratio_le`.
For every fixed adaptive-tape remainder and every retained response, a
profiled classifier proves the same accepting `(query, challenge)` density.
The only response dependence left is the proved finite list size. -/
theorem profiled_response_list_pair_ratio_le
    {F Equations CheckedMask DirectMask Response Data : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Fintype CheckedMask] [DecidableEq CheckedMask]
    [Fintype Response] [DecidableEq Response]
    [Nonempty Alpha] [Nonempty (QuerySet n r)]
    {logicalWidth w nw nq e g profileDenominator
      failureDenominator : ℕ}
    (C : MultiplicativeCode F r w n)
    (layout : ConstraintLayout F logicalWidth w)
    (policy : SchemeProtocolPolicy (Equations := Equations) C layout
      Alpha Response CheckedMask DirectMask nw nq 1)
    (oracle : Data → SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (statement : ConstraintSystem F nw nq logicalWidth Equations)
    (failureProfile arithmeticProfile : AgreementProfile n)
    (responses : Data → Finset Response) (listBound : ℕ)
    (hlist : ∀ data, (responses data).card ≤ listBound)
    (hmember : ∀ data response challenge query,
      policy.accepts statement challenge response query
          (openSchemeOracle (oracle data) query) →
        response ∈ responses data)
    (classifier : ∀ data response,
      PolicyDoublyProfiledSoundnessClassifier policy (oracle data) statement
        (fun _challenge ↦ response) failureProfile arithmeticProfile
          profileDenominator failureDenominator e g)
    (hprofile : 0 < profileDenominator)
    (hfailure : 0 < failureDenominator) (hquery : r ≤ n) :
    ∀ data,
      ((eventSet fun value :
          Response × (QuerySet n r × Alpha) ↦
        policy.accepts statement value.2.2 value.1 value.2.1
          (openSchemeOracle (oracle data) value.2.1)).card : ℚ) /
            Fintype.card (QuerySet n r × Alpha) ≤
        listBound *
          (failureProfile.contribution failureDenominator n n 0 r +
            arithmeticProfile.contribution profileDenominator n e g r) := by
  classical
  intro data
  let epsilon := failureProfile.contribution failureDenominator n n 0 r +
    arithmeticProfile.contribution profileDenominator n e g r
  change ((Finset.univ.filter fun value :
      Response × (QuerySet n r × Alpha) ↦
    policy.accepts statement value.2.2 value.1 value.2.1
      (openSchemeOracle (oracle data) value.2.1)).card : ℚ) /
        Fintype.card (QuerySet n r × Alpha) ≤ listBound * epsilon
  apply response_list_pair_ratio_le (responses data)
    (fun response query challenge ↦
      policy.accepts statement challenge response query
        (openSchemeOracle (oracle data) query))
    epsilon listBound
  · exact add_nonneg
      (AgreementProfile.contribution_nonnegative _ _ _ _ _ _)
      (AgreementProfile.contribution_nonnegative _ _ _ _ _ _)
  · exact hlist data
  · intro response query challenge haccept
    exact hmember data response challenge query haccept
  · intro response hresponse
    have h := PolicyDoublyProfiledSoundnessClassifier.strategyUniform_acceptingPairs_density_le
        (policy := policy) (oracle := oracle data) (statement := statement)
        (respondBy := fun response : Response => fun _challenge ↦ response)
        (classifier := classifier data) hprofile hfailure hquery response
    simpa [epsilon,
      PolicyDoublyProfiledSoundnessClassifier.strategyAcceptingPairs,
      Fintype.card_prod, Nat.cast_mul] using h

omit [DecidableEq Alpha] in
/-- Actual-verifier theorem for challenge-indexed response lists.  This is
the response-rigid Case-A semantic endpoint used by Ligero: each list rank is
a complete response strategy, and every such strategy is bounded by the
threshold-free profiled classifier. -/
theorem profiled_indexed_response_lists_pair_ratio_le
    {F Equations CheckedMask DirectMask Response Data : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Fintype CheckedMask] [DecidableEq CheckedMask]
    [Fintype Response] [DecidableEq Response] [Nonempty Response]
    [Nonempty Alpha] [Nonempty (QuerySet n r)]
    {logicalWidth w nw nq e g profileDenominator failureDenominator : ℕ}
    (C : MultiplicativeCode F r w n)
    (layout : ConstraintLayout F logicalWidth w)
    (policy : SchemeProtocolPolicy (Equations := Equations) C layout
      Alpha Response CheckedMask DirectMask nw nq 1)
    (oracle : Data → SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (statement : ConstraintSystem F nw nq logicalWidth Equations)
    (failureProfile arithmeticProfile : AgreementProfile n)
    (responses : Data → Alpha → Finset Response) (listBound : ℕ)
    (hlist : ∀ data alpha, (responses data alpha).card ≤ listBound)
    (classifier : ∀ data (strategy : Alpha → Response),
      PolicyDoublyProfiledSoundnessClassifier policy (oracle data) statement
        strategy failureProfile arithmeticProfile profileDenominator
          failureDenominator e g)
    (hprofile : 0 < profileDenominator)
    (hfailure : 0 < failureDenominator) (hquery : r ≤ n) :
    ∀ data,
      ((eventSet fun value : Response × (QuerySet n r × Alpha) ↦
        value.1 ∈ responses data value.2.2 ∧
          policy.accepts statement value.2.2 value.1 value.2.1
            (openSchemeOracle (oracle data) value.2.1)).card : ℚ) /
              Fintype.card (QuerySet n r × Alpha) ≤
        listBound *
          (failureProfile.contribution failureDenominator n n 0 r +
            arithmeticProfile.contribution profileDenominator n e g r) := by
  classical
  intro data
  let epsilon := failureProfile.contribution failureDenominator n n 0 r +
    arithmeticProfile.contribution profileDenominator n e g r
  have hevent :
      eventSet (fun value : Response × (QuerySet n r × Alpha) ↦
        value.1 ∈ responses data value.2.2 ∧
          policy.accepts statement value.2.2 value.1 value.2.1
            (openSchemeOracle (oracle data) value.2.1)) =
      Finset.univ.filter fun value : Response × (QuerySet n r × Alpha) ↦
        value.1 ∈ responses data value.2.2 ∧
          policy.accepts statement value.2.2 value.1 value.2.1
            (openSchemeOracle (oracle data) value.2.1) := by
    ext value
    simp [eventSet]
  rw [hevent]
  change ((Finset.univ.filter fun value :
      Response × (QuerySet n r × Alpha) ↦
    value.1 ∈ responses data value.2.2 ∧
      policy.accepts statement value.2.2 value.1 value.2.1
        (openSchemeOracle (oracle data) value.2.1)).card : ℚ) /
          Fintype.card (QuerySet n r × Alpha) ≤ listBound * epsilon
  apply indexed_response_lists_pair_ratio_le (responses data)
    (fun response query challenge ↦
      response ∈ responses data challenge ∧
        policy.accepts statement challenge response query
          (openSchemeOracle (oracle data) query))
    epsilon listBound (hlist data)
  · intro response query challenge hsuccess
    exact hsuccess.1
  · intro strategy
    let accepted :=
      PolicyDoublyProfiledSoundnessClassifier.strategyAcceptingPairs
        (policy := policy) (oracle := oracle data) (statement := statement)
        strategy
    have hsubset :
        (Finset.univ.filter fun pair : QuerySet n r × Alpha ↦
          strategy pair.2 ∈ responses data pair.2 ∧
            policy.accepts statement pair.2 (strategy pair.2) pair.1
              (openSchemeOracle (oracle data) pair.1)) ⊆ accepted := by
      intro pair hpair
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
        (Finset.mem_filter.mp hpair).2.2⟩
    have hcard := Finset.card_le_card hsubset
    have hbound :=
      PolicyDoublyProfiledSoundnessClassifier.strategyUniform_acceptingPairs_density_le
        (policy := policy) (oracle := oracle data) (statement := statement)
        (respondBy := fun strategy : Alpha → Response ↦ strategy)
        (classifier := classifier data) hprofile hfailure hquery strategy
    have hden : (0 : ℚ) <
        Fintype.card (QuerySet n r) * Fintype.card Alpha := by
      exact_mod_cast Nat.mul_pos Fintype.card_pos Fintype.card_pos
    calc
      ((Finset.univ.filter fun pair : QuerySet n r × Alpha ↦
          strategy pair.2 ∈ responses data pair.2 ∧
            policy.accepts statement pair.2 (strategy pair.2) pair.1
              (openSchemeOracle (oracle data) pair.1)).card : ℚ) /
          Fintype.card (QuerySet n r × Alpha)
        ≤ (accepted.card : ℚ) /
            (Fintype.card (QuerySet n r) * Fintype.card Alpha) := by
          simp only [Fintype.card_prod, Nat.cast_mul]
          exact div_le_div_of_nonneg_right (by exact_mod_cast hcard) hden.le
      _ ≤ epsilon := by simpa [accepted, epsilon] using hbound

/-- Exact Case-A lift from a response-indexed semantic incidence theorem to
the real typed lazy-oracle tape.  The final adversary response may depend on
the entire execution.  It is retained by
`lazy_response_target_tape_ratio_le`, while this theorem cancels only the
unused alpha/subset projections.  Thus the caller pays precisely the proved
response-list incidence and no `(T - 1)` slot union. -/
theorem lazy_response_semantic_ratio_le
    {Q Output Response : Type*} [DecidableEq Q]
    [Nonempty Alpha] [Nonempty (QuerySet n r)]
    [Fintype Response] [DecidableEq Response] [Nonempty Response]
    {N : ℕ}
    (adversary : Merkle.RandomOracle.Tree Q
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (fixedSlot : Fin (N + 2))
    (responseOf : Output → Response)
    (precursorOf targetOf : Response → Q)
    (success : ((Fin (N + 1) → PUnit.{1}) ×
      (Fin N → Answer Alpha (QuerySet n r))) →
        Response → QuerySet n r → Alpha → Prop)
    [∀ data response, DecidableRel (success data response)]
    (epsilon : ℚ)
    (hsemantic : ∀ data,
      ((Finset.univ.filter fun value :
          Response × (QuerySet n r × Alpha) ↦
        success data value.1 value.2.1 value.2.2).card : ℚ) /
          Fintype.card (QuerySet n r × Alpha) ≤ epsilon)
    (event : (Fin (N + 2) → Answer Alpha (QuerySet n r)) → Prop)
    [DecidablePred event]
    (hcover : ∀ tape, event tape →
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let fixedResponse := (tape fixedSlot, responseOf output)
      let rest := fun k ↦ (Equiv.punitProd.{0}
        (Answer Alpha (QuerySet n r))).symm
          (tape (fixedSlot.succAbove k))
      let selected := lazyResponseSelector adversary dflt fixedSlot
        precursorOf targetOf fixedResponse rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (selected.succAbove k)).2)
      lazyResponseLater adversary dflt fixedSlot precursorOf targetOf
          (fixedResponse, rest) ∧
        success data fixedResponse.2 (subsetAnswer (rest selected).2)
          (alphaAnswer fixedResponse.1)) :
    ((Finset.univ.filter event).card : ℚ) /
        Fintype.card
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤ epsilon := by
  classical
  let fullSuccess := fun data
      (fixedResponse : Answer Alpha (QuerySet n r) × Response)
      (later : Answer Alpha (QuerySet n r)) ↦
    success data fixedResponse.2 (subsetAnswer later)
      (alphaAnswer fixedResponse.1)
  apply lazy_response_target_tape_ratio_le adversary dflt fixedSlot
    responseOf precursorOf targetOf fullSuccess epsilon
  · intro data
    exact answer_response_reverse_incidence_ratio_le
      (success data) epsilon (hsemantic data)
  · intro tape htape
    simpa [fullSuccess] using hcover tape htape

/-- One-step listed Case A.  For every fixed remainder, the successful final
responses lie in a proved finite Johnson list, and every fixed response has a
strategy-uniform refined/integrated MCA pair density.  The response list and
the typed lazy execution are composed without any slot-count factor. -/
theorem lazy_response_list_pair_ratio_le
    {Q Output Response : Type*} [DecidableEq Q]
    [Nonempty Alpha] [Nonempty (QuerySet n r)]
    [Fintype Response] [DecidableEq Response] [Nonempty Response]
    {N : ℕ}
    (adversary : Merkle.RandomOracle.Tree Q
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (fixedSlot : Fin (N + 2))
    (responseOf : Output → Response)
    (precursorOf targetOf : Response → Q)
    (responses : ((Fin (N + 1) → PUnit.{1}) ×
      (Fin N → Answer Alpha (QuerySet n r))) → Finset Response)
    (success : ((Fin (N + 1) → PUnit.{1}) ×
      (Fin N → Answer Alpha (QuerySet n r))) →
        Response → QuerySet n r → Alpha → Prop)
    [∀ data response, DecidableRel (success data response)]
    (pairEpsilon : ℚ) (listBound : ℕ)
    (hpairEpsilon : 0 ≤ pairEpsilon)
    (hlist : ∀ data, (responses data).card ≤ listBound)
    (hmember : ∀ data response query alpha,
      success data response query alpha → response ∈ responses data)
    (hpairs : ∀ data, ∀ response ∈ responses data,
      ((Finset.univ.filter fun pair : QuerySet n r × Alpha ↦
        success data response pair.1 pair.2).card : ℚ) /
          Fintype.card (QuerySet n r × Alpha) ≤ pairEpsilon)
    (event : (Fin (N + 2) → Answer Alpha (QuerySet n r)) → Prop)
    [DecidablePred event]
    (hcover : ∀ tape, event tape →
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let fixedResponse := (tape fixedSlot, responseOf output)
      let rest := fun k ↦ (Equiv.punitProd.{0}
        (Answer Alpha (QuerySet n r))).symm
          (tape (fixedSlot.succAbove k))
      let chosen := lazyResponseSelector adversary dflt fixedSlot
        precursorOf targetOf fixedResponse rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (chosen.succAbove k)).2)
      lazyResponseLater adversary dflt fixedSlot precursorOf targetOf
          (fixedResponse, rest) ∧
        success data fixedResponse.2 (subsetAnswer (rest chosen).2)
          (alphaAnswer fixedResponse.1)) :
    ((Finset.univ.filter event).card : ℚ) /
        Fintype.card
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
      listBound * pairEpsilon := by
  classical
  apply lazy_response_semantic_ratio_le adversary dflt fixedSlot
    responseOf precursorOf targetOf success (listBound * pairEpsilon)
  · intro data
    exact response_list_pair_ratio_le (responses data) (success data)
      pairEpsilon listBound hpairEpsilon (hlist data)
      (hmember data) (hpairs data)
  · intro tape htape
    exact hcover tape htape

/-- Correct one-step listed Case A with challenge-indexed Johnson lists.
Each list rank defines a complete response strategy across all alphas, so the
strategy-uniform profiled MCA theorem is applied exactly `listBound` times. -/
theorem lazy_response_indexed_lists_pair_ratio_le
    {Q Output Response : Type*} [DecidableEq Q]
    [Nonempty Alpha] [Nonempty (QuerySet n r)]
    [Fintype Response] [DecidableEq Response] [Nonempty Response]
    {N : ℕ}
    (adversary : Merkle.RandomOracle.Tree Q
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (fixedSlot : Fin (N + 2))
    (responseOf : Output → Response)
    (precursorOf targetOf : Response → Q)
    (responses : ((Fin (N + 1) → PUnit.{1}) ×
      (Fin N → Answer Alpha (QuerySet n r))) →
        Alpha → Finset Response)
    (success : ((Fin (N + 1) → PUnit.{1}) ×
      (Fin N → Answer Alpha (QuerySet n r))) →
        Response → QuerySet n r → Alpha → Prop)
    [∀ data response, DecidableRel (success data response)]
    (pairEpsilon : ℚ) (listBound : ℕ)
    (hlist : ∀ data alpha, (responses data alpha).card ≤ listBound)
    (hmember : ∀ data response query alpha,
      success data response query alpha →
        response ∈ responses data alpha)
    (hpairs : ∀ data, ∀ strategy : Alpha → Response,
      ((Finset.univ.filter fun pair : QuerySet n r × Alpha ↦
        success data (strategy pair.2) pair.1 pair.2).card : ℚ) /
          Fintype.card (QuerySet n r × Alpha) ≤ pairEpsilon)
    (event : (Fin (N + 2) → Answer Alpha (QuerySet n r)) → Prop)
    [DecidablePred event]
    (hcover : ∀ tape, event tape →
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let fixedResponse := (tape fixedSlot, responseOf output)
      let rest := fun k ↦ (Equiv.punitProd.{0}
        (Answer Alpha (QuerySet n r))).symm
          (tape (fixedSlot.succAbove k))
      let chosen := lazyResponseSelector adversary dflt fixedSlot
        precursorOf targetOf fixedResponse rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (chosen.succAbove k)).2)
      lazyResponseLater adversary dflt fixedSlot precursorOf targetOf
          (fixedResponse, rest) ∧
        success data fixedResponse.2 (subsetAnswer (rest chosen).2)
          (alphaAnswer fixedResponse.1)) :
    ((Finset.univ.filter event).card : ℚ) /
        Fintype.card
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
      listBound * pairEpsilon := by
  classical
  apply lazy_response_semantic_ratio_le adversary dflt fixedSlot
    responseOf precursorOf targetOf success (listBound * pairEpsilon)
  · intro data
    exact indexed_response_lists_pair_ratio_le (responses data)
      (success data) pairEpsilon listBound (hlist data) (hmember data)
      (hpairs data)
  · intro tape htape
    exact hcover tape htape

/-- Exact Case-B lift.  Here the defining alpha key is determined by the
prefix at the charged subset slot, so ordinary predictable deletion applies.
The unused projections cancel and no later-slot union is introduced. -/
theorem lazy_prefix_semantic_ratio_le
    {Q Output : Type*} [DecidableEq Q]
    [Nonempty Alpha] [Nonempty (QuerySet n r)] {N : ℕ}
    (adversary : Merkle.RandomOracle.Tree Q
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (fixedSlot : Fin (N + 2))
    (targetFrom : List Q → Answer Alpha (QuerySet n r) → Q)
    (success : ((Fin (N + 1) → PUnit) ×
      (Fin N → Answer Alpha (QuerySet n r))) →
        QuerySet n r → Alpha → Prop)
    [∀ data, DecidableRel (success data)]
    (epsilon : ℚ)
    (hsemantic : ∀ data,
      ((Finset.univ.filter fun value : QuerySet n r × Alpha ↦
        success data value.1 value.2).card : ℚ) /
          Fintype.card (QuerySet n r × Alpha) ≤ epsilon)
    (event : (Fin (N + 2) → Answer Alpha (QuerySet n r)) → Prop)
    [DecidablePred event]
    (hcover : ∀ tape, event tape →
      let fixed := tape fixedSlot
      let rest := fun k ↦ (Equiv.punitProd
        (Answer Alpha (QuerySet n r))).symm
          (tape (fixedSlot.succAbove k))
      let selected := lazyPrefixSelector adversary dflt fixedSlot
        (Equiv.punitProd (Answer Alpha (QuerySet n r))).symm
          targetFrom fixed rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (selected.succAbove k)).2)
      lazyPrefixLater adversary dflt fixedSlot
          (Equiv.punitProd (Answer Alpha (QuerySet n r))).symm
            targetFrom (fixed, rest) ∧
        success data (subsetAnswer fixed)
          (alphaAnswer (rest selected).2)) :
    ((Finset.univ.filter event).card : ℚ) /
        Fintype.card
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤ epsilon := by
  classical
  let fullSuccess := fun data
      (fixed later : Answer Alpha (QuerySet n r)) ↦
    success data (subsetAnswer fixed) (alphaAnswer later)
  have hfull : ∀ data, ((Finset.univ.filter fun pair :
      Answer Alpha (QuerySet n r) × Answer Alpha (QuerySet n r) ↦
        fullSuccess data pair.1 pair.2).card : ℚ) /
          (Fintype.card (Answer Alpha (QuerySet n r)) *
            Fintype.card (Answer Alpha (QuerySet n r))) ≤ epsilon := by
    intro data
    simpa only [Fintype.card_prod, Nat.cast_mul] using
      answer_pair_incidence_ratio_le_of_pair_ratio
        (success data) epsilon (hsemantic data)
  apply predictable_raw_other_slot_tape_on_ratio_le fixedSlot
    (lazyPrefixSelector adversary dflt fixedSlot
      (Equiv.punitProd (Answer Alpha (QuerySet n r))).symm targetFrom)
    (lazyPrefixLater adversary dflt fixedSlot
      (Equiv.punitProd (Answer Alpha (QuerySet n r))).symm targetFrom)
    (lazyPrefixSelector_predictableOn adversary dflt fixedSlot
      (Equiv.punitProd (Answer Alpha (QuerySet n r))).symm targetFrom)
    fullSuccess event epsilon hfull
  intro tape htape
  simpa [fullSuccess] using hcover tape htape

/- Complete threshold-free Case-B semantic lift from an actual protocol
classifier.  After deleting the charged subset slot, the remaining tape
determines both the commitment and a full alpha-indexed response strategy.
The integrated classifier bounds exactly the accepting `(query, alpha)`
pairs for that strategy, and predictable deletion lifts the bound to the
adaptive lazy tape without a later-slot union. -/
omit [DecidableEq Alpha] in
theorem lazy_prefix_profiled_accepting_ratio_le
    {F Equations CheckedMask DirectMask Response Q Output : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Fintype CheckedMask] [DecidableEq CheckedMask]
    [DecidableEq Q] [Nonempty Alpha] [Nonempty (QuerySet n r)]
    {logicalWidth w nw nq e g profileDenominator failureDenominator N : ℕ}
    (C : MultiplicativeCode F r w n)
    (layout : ConstraintLayout F logicalWidth w)
    (policy : SchemeProtocolPolicy (Equations := Equations) C layout
      Alpha Response CheckedMask DirectMask nw nq 1)
    (statement : ConstraintSystem F nw nq logicalWidth Equations)
    (adversary : Merkle.RandomOracle.Tree Q
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (fixedSlot : Fin (N + 2))
    (targetFrom : List Q → Answer Alpha (QuerySet n r) → Q)
    (oracle : ((Fin (N + 1) → PUnit) ×
      (Fin N → Answer Alpha (QuerySet n r))) →
        SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (respond : ((Fin (N + 1) → PUnit) ×
      (Fin N → Answer Alpha (QuerySet n r))) → Alpha → Response)
    (failureProfile arithmeticProfile : AgreementProfile n)
    (classifier : ∀ data,
      PolicyDoublyProfiledSoundnessClassifier policy (oracle data) statement
        (respond data) failureProfile arithmeticProfile profileDenominator
          failureDenominator e g)
    (hprofile : 0 < profileDenominator)
    (hfailure : 0 < failureDenominator) (hquery : r ≤ n)
    (baselineAgreement : ℕ) (hbaselineAgreement : baselineAgreement ≤ n)
    (hprofileFloor : ∀ a ≤ baselineAgreement,
      profileDenominator ≤ arithmeticProfile.labelsAtLeast a)
    (event : (Fin (N + 2) → Answer Alpha (QuerySet n r)) → Prop)
    [DecidablePred event]
    (hcover : ∀ tape, event tape →
      let fixed := tape fixedSlot
      let rest := fun k ↦ (Equiv.punitProd
        (Answer Alpha (QuerySet n r))).symm
          (tape (fixedSlot.succAbove k))
      let chosen := lazyPrefixSelector adversary dflt fixedSlot
        (Equiv.punitProd (Answer Alpha (QuerySet n r))).symm
          targetFrom fixed rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (chosen.succAbove k)).2)
      lazyPrefixLater adversary dflt fixedSlot
          (Equiv.punitProd (Answer Alpha (QuerySet n r))).symm
            targetFrom (fixed, rest) ∧
        policy.accepts statement (alphaAnswer (rest chosen).2)
          (respond data (alphaAnswer (rest chosen).2)) (subsetAnswer fixed)
          (openSchemeOracle (oracle data) (subsetAnswer fixed))) :
    ((Finset.univ.filter event).card : ℚ) /
        Fintype.card
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
      failureProfile.excessContribution failureDenominator n n 0 r
          (max (n - e - 1) (min n (g + baselineAgreement))) +
        arithmeticProfile.contribution profileDenominator n e g r := by
  classical
  let success := fun data (query : QuerySet n r) (alpha : Alpha) ↦
    policy.accepts statement alpha (respond data alpha) query
      (openSchemeOracle (oracle data) query)
  apply lazy_prefix_semantic_ratio_le adversary dflt fixedSlot targetFrom
    success
    (failureProfile.excessContribution failureDenominator n n 0 r
        (max (n - e - 1) (min n (g + baselineAgreement))) +
      arithmeticProfile.contribution profileDenominator n e g r)
  · intro data
    have h :=
      PolicyDoublyProfiledSoundnessClassifier.strategyUniform_acceptingPairs_density_le_eventPartition
        (policy := policy) (oracle := oracle data) (statement := statement)
        (respondBy := fun _ : Unit ↦ respond data)
        (classifier := fun _ : Unit ↦ classifier data)
        baselineAgreement hprofile hfailure hquery hbaselineAgreement
          hprofileFloor ()
    simpa [success,
      PolicyDoublyProfiledSoundnessClassifier.strategyAcceptingPairs,
      Fintype.card_prod, Nat.cast_mul] using h
  · intro tape htape
    simpa [success] using hcover tape htape

omit [DecidableEq Alpha] in
/-- Complete canonical Case-B theorem for a prefix-bound Ligero policy.
The event is defined directly by the actual Merkle opening and policy
acceptance.  The charged H₂ prefix supplies the response strategy,
`policy_accepts_of_prefixBindingFamily` supplies the extracted oracle, and
the integrated classifier supplies the exact semantic pair density. -/
theorem canonical_caseB_prefixBound_profiled_ratio_le
    {F Equations CheckedMask DirectMask AlphaKey Response Salt D Enc Output
      PrefixOut RunOut : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Fintype CheckedMask] [DecidableEq CheckedMask]
    [Fintype Response] [DecidableEq Response] [Nonempty Response]
    [Inhabited Salt] [Inhabited D] [DecidableEq D] [DecidableEq Enc]
    [DecidableEq AlphaKey] [Nonempty Alpha] [Nonempty (QuerySet n r)]
    {logicalWidth w nw nq e g profileDenominator failureDenominator
      merkleT N prefixFuel runFuel : ℕ}
    (code : MultiplicativeCode F r w n)
    (layout : ConstraintLayout F logicalWidth w)
    (policy : SchemeProtocolPolicy (Equations := Equations) code layout
      Alpha Response CheckedMask DirectMask nw nq 1)
    (statement : ConstraintSystem F nw nq logicalWidth Equations)
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F CheckedMask DirectMask nw nq 1) D Enc)
    (family : Merkle.MH.PrefixBindingFamily
      (Out := PrefixOut) (RunOut := RunOut) codec
      (Fin (N + 2) → Answer Alpha (QuerySet n r)) n merkleT
        prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec)
    (merkleAnswers : Fin merkleT → D)
    (adversary : Merkle.RandomOracle.Tree
      (Bcs.TypedFiatShamir.Query AlphaKey (AlphaKey × Response))
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (keyOf : Output → AlphaKey) (responseOf : Output → Response)
    (fallback : AlphaKey × Response)
    (reference : Fin (N + 2) → Answer Alpha (QuerySet n r))
    (i : Fin (N + 2))
    (failureProfile arithmeticProfile : AgreementProfile n)
    (classifier : ∀ data :
      ((Fin (N + 1) → PUnit) ×
        (Fin N → Answer Alpha (QuerySet n r))),
      PolicyDoublyProfiledSoundnessClassifier policy
        (SchemeOracle.ofColumns
          ((family.game reference).boundMessage dec merkleAnswers))
        statement
        (fun _alpha ↦ Bcs.TypedFiatShamir.canonicalCaseBResponseFromData
          adversary dflt fallback i data)
        failureProfile arithmeticProfile profileDenominator
          failureDenominator e g)
    (hprofile : 0 < profileDenominator)
    (hfailure : 0 < failureDenominator) (hquery : r ≤ n)
    (baselineAgreement : ℕ) (hbaselineAgreement : baselineAgreement ≤ n)
    (hprofileFloor : ∀ a ≤ baselineAgreement,
      profileDenominator ≤ arithmeticProfile.labelsAtLeast a) :
    let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
      dflt keyOf (fun output ↦ (keyOf output, responseOf output))
    let win := fun tape : Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
      let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
      let claim := (family.game tape).claim merkleAnswers
      claim.I = query.coordinates ∧
        Merkle.MH.Accepts
          (codec.withOracle ((family.game tape).oracle merkleAnswers)) n
          ((family.game tape).root merkleAnswers)
          claim.I claim.a claim.pf ∧
        policy.accepts statement alpha (responseOf output) query
          (fun j ↦ claim.a j.1)
    let bindBreak := fun tape :
      Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
        (family.game tape).Bad dec merkleAnswers
    ((eventSet (trace.caseB win bindBreak i)).card : ℚ) /
        Fintype.card
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
      failureProfile.excessContribution failureDenominator n n 0 r
          (max (n - e - 1) (min n (g + baselineAgreement))) +
        arithmeticProfile.contribution profileDenominator n e g r := by
  classical
  dsimp only
  let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
    dflt keyOf (fun output ↦ (keyOf output, responseOf output))
  let win := fun tape : Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
    let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
    let claim := (family.game tape).claim merkleAnswers
    claim.I = query.coordinates ∧
      Merkle.MH.Accepts
        (codec.withOracle ((family.game tape).oracle merkleAnswers)) n
        ((family.game tape).root merkleAnswers)
        claim.I claim.a claim.pf ∧
      policy.accepts statement alpha (responseOf output) query
        (fun j ↦ claim.a j.1)
  let bindBreak := fun tape :
    Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
      (family.game tape).Bad dec merkleAnswers
  let oracle := SchemeOracle.ofColumns
    ((family.game reference).boundMessage dec merkleAnswers)
  let respond := fun data
      (_alpha : Alpha) ↦
    Bcs.TypedFiatShamir.canonicalCaseBResponseFromData adversary dflt
      fallback i data
  apply lazy_prefix_profiled_accepting_ratio_le code layout policy statement
    adversary dflt i
    (Bcs.TypedFiatShamir.canonicalAlphaTargetFromPrefix fallback.1)
    (fun _data ↦ oracle) respond failureProfile arithmeticProfile
    (fun data ↦ by simpa [oracle, respond] using classifier data)
    hprofile hfailure hquery baselineAgreement hbaselineAgreement hprofileFloor
      (trace.caseB win bindBreak i)
  intro tape hcase
  have hselector := Bcs.TypedFiatShamir.canonicalCaseB_selector adversary
    dflt keyOf responseOf fallback.1 win bindBreak i tape hcase
  have hresponse := Bcs.TypedFiatShamir.canonicalCaseBResponseFromData_eq
    adversary dflt keyOf responseOf fallback win bindBreak i tape hcase
  let rest := fun k ↦
    (Equiv.punitProd.{0} (Answer Alpha (QuerySet n r))).symm
      (tape (i.succAbove k))
  let chosen := Bcs.TypedFiatShamir.lazyPrefixSelector adversary dflt i
    (Equiv.punitProd.{0} (Answer Alpha (QuerySet n r))).symm
    (Bcs.TypedFiatShamir.canonicalAlphaTargetFromPrefix fallback.1)
      (tape i) rest
  let data := ((fun k ↦ (rest k).1),
    fun k ↦ (rest (chosen.succAbove k)).2)
  have hselector' :
      Bcs.TypedFiatShamir.lazyPrefixLater adversary dflt i
          (Equiv.punitProd.{0} (Answer Alpha (QuerySet n r))).symm
          (Bcs.TypedFiatShamir.canonicalAlphaTargetFromPrefix fallback.1)
          (tape i, rest) ∧
        Bcs.TypedFiatShamir.subsetAnswer (tape i) =
          Bcs.TypedFiatShamir.definingSubsetAnswer trace tape ∧
        Bcs.TypedFiatShamir.alphaAnswer (rest chosen).2 =
          Bcs.TypedFiatShamir.definingAlphaAnswer trace tape := by
    simpa only [trace, rest, chosen] using hselector
  have hresponse' :
      Bcs.TypedFiatShamir.canonicalCaseBResponseFromData adversary dflt
          fallback i data =
        responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1 := by
    simpa only [data, rest, chosen] using hresponse
  have hwin := hcase.1
  have hgood := hcase.2.1
  let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
  let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
  let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
  have haccept := policy_accepts_of_prefixBindingFamily code layout policy
    statement codec family dec reference tape merkleAnswers alpha
      (responseOf output) query hwin.1 hwin.2.1 hgood hwin.2.2
  refine ⟨hselector'.1, ?_⟩
  change policy.accepts statement
    (Bcs.TypedFiatShamir.alphaAnswer (rest chosen).2)
    (respond data (Bcs.TypedFiatShamir.alphaAnswer (rest chosen).2))
    (Bcs.TypedFiatShamir.subsetAnswer (tape i))
    (openSchemeOracle oracle (Bcs.TypedFiatShamir.subsetAnswer (tape i)))
  rw [hselector'.2.2, hselector'.2.1, show
    respond data (Bcs.TypedFiatShamir.definingAlphaAnswer trace tape) =
      Bcs.TypedFiatShamir.canonicalCaseBResponseFromData adversary dflt
        fallback i data by rfl, hresponse']
  simpa only [oracle, query, alpha, output] using haccept

omit [DecidableEq Alpha] in
/-- Complete listed Case-A theorem for a prefix-bound Ligero policy with a
fixed commitment key.  The event is a real first-occurrence event intersected
with membership in the verifier-defined, challenge-indexed response list.
The charged `H₁` answer is fresh, the later `H₂` query retains the adversary's
actual response, and prefix binding replaces the claimed opening by the one
fixed extracted oracle.  Thus the only multiplicative loss is the proved
response-list bound. -/
theorem canonical_caseA_listed_prefixBound_profiled_ratio_le
    {F Equations CheckedMask DirectMask AlphaKey Response Salt D Enc Output
      PrefixOut RunOut : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Fintype CheckedMask] [DecidableEq CheckedMask]
    [Fintype Response] [DecidableEq Response] [Nonempty Response]
    [Inhabited Salt] [Inhabited D] [DecidableEq D] [DecidableEq Enc]
    [DecidableEq AlphaKey] [Nonempty Alpha] [Nonempty (QuerySet n r)]
    {logicalWidth w nw nq e g profileDenominator failureDenominator
      merkleT N prefixFuel runFuel : ℕ}
    (code : MultiplicativeCode F r w n)
    (layout : ConstraintLayout F logicalWidth w)
    (policy : SchemeProtocolPolicy (Equations := Equations) code layout
      Alpha Response CheckedMask DirectMask nw nq 1)
    (statement : ConstraintSystem F nw nq logicalWidth Equations)
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F CheckedMask DirectMask nw nq 1) D Enc)
    (family : Merkle.MH.PrefixBindingFamily
      (Out := PrefixOut) (RunOut := RunOut) codec
      (Fin (N + 2) → Answer Alpha (QuerySet n r)) n merkleT
        prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec)
    (merkleAnswers : Fin merkleT → D)
    (adversary : Merkle.RandomOracle.Tree
      (Bcs.TypedFiatShamir.Query AlphaKey (AlphaKey × Response))
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (alphaKey : AlphaKey) (responseOf : Output → Response)
    (reference : Fin (N + 2) → Answer Alpha (QuerySet n r))
    (i : Fin (N + 2))
    (responses : Alpha → Finset Response) (listBound : ℕ)
    (hlist : ∀ alpha, (responses alpha).card ≤ listBound)
    (failureProfile arithmeticProfile : AgreementProfile n)
    (classifier : ∀ strategy : Alpha → Response,
      PolicyDoublyProfiledSoundnessClassifier policy
        (SchemeOracle.ofColumns
          ((family.game reference).boundMessage dec merkleAnswers))
        statement strategy failureProfile arithmeticProfile
          profileDenominator failureDenominator e g)
    (hprofile : 0 < profileDenominator)
    (hfailure : 0 < failureDenominator) (hquery : r ≤ n)
    (baselineAgreement : ℕ) (hbaselineAgreement : baselineAgreement ≤ n)
    (hprofileFloor : ∀ a ≤ baselineAgreement,
      profileDenominator ≤ arithmeticProfile.labelsAtLeast a) :
    let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
      dflt (fun _output ↦ alphaKey)
        (fun output ↦ (alphaKey, responseOf output))
    let listed := fun tape :
        Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
      responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1 ∈
        responses (Bcs.TypedFiatShamir.definingAlphaAnswer trace tape)
    let win := fun tape : Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
      let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
      let claim := (family.game tape).claim merkleAnswers
      claim.I = query.coordinates ∧
        Merkle.MH.Accepts
          (codec.withOracle ((family.game tape).oracle merkleAnswers)) n
          ((family.game tape).root merkleAnswers)
          claim.I claim.a claim.pf ∧
        policy.accepts statement alpha (responseOf output) query
          (fun j ↦ claim.a j.1)
    let bindBreak := fun tape :
      Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
        (family.game tape).Bad dec merkleAnswers
    ((eventSet fun tape ↦
      trace.caseA listed win bindBreak i tape ∧ listed tape).card : ℚ) /
        Fintype.card
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
      listBound *
        (failureProfile.excessContribution failureDenominator n n 0 r
            (max (n - e - 1) (min n (g + baselineAgreement))) +
          arithmeticProfile.contribution profileDenominator n e g r) := by
  classical
  dsimp only
  let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
    dflt (fun _output ↦ alphaKey)
      (fun output ↦ (alphaKey, responseOf output))
  let oracle := SchemeOracle.ofColumns
    ((family.game reference).boundMessage dec merkleAnswers)
  let listed := fun tape :
      Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
    responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1 ∈
      responses (Bcs.TypedFiatShamir.definingAlphaAnswer trace tape)
  let win := fun tape : Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
    let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
    let claim := (family.game tape).claim merkleAnswers
    claim.I = query.coordinates ∧
      Merkle.MH.Accepts
        (codec.withOracle ((family.game tape).oracle merkleAnswers)) n
        ((family.game tape).root merkleAnswers)
        claim.I claim.a claim.pf ∧
      policy.accepts statement alpha (responseOf output) query
        (fun j ↦ claim.a j.1)
  let bindBreak := fun tape :
    Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
      (family.game tape).Bad dec merkleAnswers
  let epsilon := failureProfile.excessContribution failureDenominator n n 0 r
      (max (n - e - 1) (min n (g + baselineAgreement))) +
    arithmeticProfile.contribution profileDenominator n e g r
  let success := fun (_data :
      (Fin (N + 1) → PUnit) ×
        (Fin N → Answer Alpha (QuerySet n r)))
      (response : Response) (query : QuerySet n r) (alpha : Alpha) ↦
    response ∈ responses alpha ∧
      policy.accepts statement alpha response query
        (openSchemeOracle oracle query)
  change ((eventSet (fun tape ↦
      trace.caseA listed win bindBreak i tape ∧ listed tape)).card : ℚ) /
        Fintype.card
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤ listBound * epsilon
  letI : ∀ data response, DecidableRel (success data response) := by
    intro data response query alpha
    exact Classical.propDecidable _
  letI : DecidablePred (fun tape ↦
      trace.caseA listed win bindBreak i tape ∧ listed tape) :=
    Classical.decPred _
  apply lazy_response_indexed_lists_pair_ratio_le adversary dflt i responseOf
    (fun _response ↦ Bcs.TypedFiatShamir.Query.alpha alphaKey)
    (fun response ↦ Bcs.TypedFiatShamir.Query.subset (alphaKey, response))
    (fun _data ↦ responses) success epsilon listBound
  · intro _data alpha
    exact hlist alpha
  · intro _data response query alpha hsuccess
    exact hsuccess.1
  · intro data strategy
    let accepted :=
      PolicyDoublyProfiledSoundnessClassifier.strategyAcceptingPairs
        (policy := policy) (oracle := oracle) (statement := statement)
        strategy
    have hsubset :
        (Finset.univ.filter fun pair : QuerySet n r × Alpha ↦
          success data (strategy pair.2) pair.1 pair.2) ⊆ accepted := by
      intro pair hpair
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
        (Finset.mem_filter.mp hpair).2.2⟩
    have hcard := Finset.card_le_card hsubset
    have hbound :=
      PolicyDoublyProfiledSoundnessClassifier.strategyUniform_acceptingPairs_density_le_eventPartition
        (policy := policy) (oracle := oracle) (statement := statement)
        (respondBy := fun strategy : Alpha → Response ↦ strategy)
        (classifier := classifier) baselineAgreement hprofile hfailure hquery
          hbaselineAgreement hprofileFloor strategy
    have hden : (0 : ℚ) <
        Fintype.card (QuerySet n r × Alpha) := by
      exact_mod_cast Fintype.card_pos
    calc
      ((Finset.univ.filter fun pair : QuerySet n r × Alpha ↦
          success data (strategy pair.2) pair.1 pair.2).card : ℚ) /
          Fintype.card (QuerySet n r × Alpha)
        ≤ (accepted.card : ℚ) /
            Fintype.card (QuerySet n r × Alpha) :=
          div_le_div_of_nonneg_right (by exact_mod_cast hcard) hden.le
      _ ≤ epsilon := by
        simpa [epsilon, accepted,
          PolicyDoublyProfiledSoundnessClassifier.strategyAcceptingPairs,
          Fintype.card_prod, Nat.cast_mul] using hbound
  · intro tape hevent
    have hcase := hevent.1
    have hlisted := hevent.2
    have hselector := Bcs.TypedFiatShamir.canonicalCaseA_listed_selector
      adversary dflt (fun _output ↦ alphaKey) responseOf listed win bindBreak
        i tape hcase hlisted
    let rest := fun k ↦
      (Equiv.punitProd.{0} (Answer Alpha (QuerySet n r))).symm
        (tape (i.succAbove k))
    let chosen := Bcs.TypedFiatShamir.lazyResponseSelector adversary dflt i
      (fun _response : Response ↦ Bcs.TypedFiatShamir.Query.alpha alphaKey)
      (fun response ↦ Bcs.TypedFiatShamir.Query.subset (alphaKey, response))
      (tape i,
        responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1)
      rest
    let data := ((fun k ↦ (rest k).1),
      fun k ↦ (rest (chosen.succAbove k)).2)
    let pairChosen := Bcs.TypedFiatShamir.lazyResponseSelector adversary
      dflt i (fun value : AlphaKey × Response ↦
        Bcs.TypedFiatShamir.Query.alpha value.1)
      (fun value ↦ Bcs.TypedFiatShamir.Query.subset value)
      (tape i,
        (alphaKey,
          responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1))
      rest
    have hchosenEq : pairChosen = chosen := by
      apply Fin.ext
      simp only [pairChosen, chosen,
        Bcs.TypedFiatShamir.lazyResponseSelector,
        Bcs.TypedFiatShamir.lazyResponseTargetSlot,
        Bcs.TypedFiatShamir.lazyResponseTargetTrace]
    have hselector' :
        Bcs.TypedFiatShamir.lazyResponseLater adversary dflt i
            (fun _response : Response ↦
              Bcs.TypedFiatShamir.Query.alpha alphaKey)
            (fun response ↦
              Bcs.TypedFiatShamir.Query.subset (alphaKey, response))
            ((tape i,
              responseOf
                (Merkle.RandomOracle.lazyRun tape dflt adversary []).1),
              rest) ∧
          Bcs.TypedFiatShamir.alphaAnswer (tape i) =
            Bcs.TypedFiatShamir.definingAlphaAnswer trace tape ∧
          Bcs.TypedFiatShamir.subsetAnswer (rest chosen).2 =
            Bcs.TypedFiatShamir.definingSubsetAnswer trace tape := by
      refine ⟨?_, hselector.2.1, ?_⟩
      · exact hselector.1
      · rw [← hchosenEq]
        exact hselector.2.2
    have hwin := hcase.1
    have hgood := hcase.2.1
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
    let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
    have haccept := policy_accepts_of_prefixBindingFamily code layout policy
      statement codec family dec reference tape merkleAnswers alpha
        (responseOf output) query hwin.1 hwin.2.1 hgood hwin.2.2
    refine ⟨hselector'.1, ?_⟩
    constructor
    · change responseOf output ∈
        responses (Bcs.TypedFiatShamir.alphaAnswer (tape i))
      rw [hselector'.2.1]
      simpa only [listed, output] using hlisted
    · change policy.accepts statement
        (Bcs.TypedFiatShamir.alphaAnswer (tape i)) (responseOf output)
        (Bcs.TypedFiatShamir.subsetAnswer (rest chosen).2)
        (openSchemeOracle oracle
          (Bcs.TypedFiatShamir.subsetAnswer (rest chosen).2))
      rw [hselector'.2.1, hselector'.2.2]
      simpa only [oracle, query, alpha, output] using haccept

/-- Keep an accepting-coordinate set only when its cardinality has already
been proved to lie below the Case-A floor.  This makes the allowed set a
total prefix function while preserving the actual unlisted execution. -/
noncomputable def floorBoundedCoordinates {n : ℕ} (floor : ℕ)
    (coordinates : Finset (Fin n)) : Finset (Fin n) :=
  if coordinates.card ≤ floor then coordinates else ∅

theorem floorBoundedCoordinates_card_le {n floor : ℕ}
    (coordinates : Finset (Fin n)) :
    (floorBoundedCoordinates floor coordinates).card ≤ floor := by
  classical
  unfold floorBoundedCoordinates
  split <;> simp_all

theorem floorBoundedCoordinates_eq {n floor : ℕ}
    (coordinates : Finset (Fin n)) (hcard : coordinates.card ≤ floor) :
    floorBoundedCoordinates floor coordinates = coordinates := by
  classical
  simp [floorBoundedCoordinates, hcard]

omit [DecidableEq Alpha] in
/-- Complete unlisted/floor Case-A theorem for a prefix-bound Ligero policy.
The defining response and batching challenge are reconstructed from the
answer prefix strictly before the charged `H₂` slot.  Prefix binding supplies
the fixed extracted oracle.  The verifier-specific caller proves only the
semantic facts that acceptance lies in `acceptingCoordinates` and that an
accepted response outside the canonical list has at most `floor` such
coordinates; no probability or prefix-stability premise is assumed. -/
theorem canonical_caseA_floor_prefixBound_ratio_le
    {F Equations CheckedMask DirectMask AlphaKey Response Salt D Enc Output
      PrefixOut RunOut : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Fintype CheckedMask] [DecidableEq CheckedMask]
    [Inhabited Salt] [Inhabited D] [DecidableEq D] [DecidableEq Enc]
    [DecidableEq AlphaKey] [DecidableEq Response]
    [Nonempty Alpha] [Nonempty (QuerySet n r)]
    {logicalWidth w nw nq merkleT N prefixFuel runFuel floor : ℕ}
    (code : MultiplicativeCode F r w n)
    (layout : ConstraintLayout F logicalWidth w)
    (policy : SchemeProtocolPolicy (Equations := Equations) code layout
      Alpha Response CheckedMask DirectMask nw nq 1)
    (statement : ConstraintSystem F nw nq logicalWidth Equations)
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F CheckedMask DirectMask nw nq 1) D Enc)
    (family : Merkle.MH.PrefixBindingFamily
      (Out := PrefixOut) (RunOut := RunOut) codec
      (Fin (N + 2) → Answer Alpha (QuerySet n r)) n merkleT
        prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec)
    (merkleAnswers : Fin merkleT → D)
    (adversary : Merkle.RandomOracle.Tree
      (Bcs.TypedFiatShamir.Query AlphaKey (AlphaKey × Response))
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (alphaKey : AlphaKey) (responseOf : Output → Response)
    (reference : Fin (N + 2) → Answer Alpha (QuerySet n r))
    (i : Fin (N + 2))
    (responses : Alpha → Finset Response)
    (acceptingCoordinates : Alpha → Response → Finset (Fin n))
    (hsubset : ∀ alpha response query,
      policy.accepts statement alpha response query
          (openSchemeOracle
            (SchemeOracle.ofColumns
              ((family.game reference).boundMessage dec merkleAnswers)) query) →
        query.coordinates ⊆ acceptingCoordinates alpha response)
    (hfloor : ∀ alpha response query,
      policy.accepts statement alpha response query
          (openSchemeOracle
            (SchemeOracle.ofColumns
              ((family.game reference).boundMessage dec merkleAnswers)) query) →
        response ∉ responses alpha →
        (acceptingCoordinates alpha response).card ≤ floor)
    (hquery : r ≤ n) :
    let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
      dflt (fun _output ↦ alphaKey)
        (fun output ↦ (alphaKey, responseOf output))
    let listed := fun tape :
        Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
      responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1 ∈
        responses (Bcs.TypedFiatShamir.definingAlphaAnswer trace tape)
    let win := fun tape : Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
      let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
      let claim := (family.game tape).claim merkleAnswers
      claim.I = query.coordinates ∧
        Merkle.MH.Accepts
          (codec.withOracle ((family.game tape).oracle merkleAnswers)) n
          ((family.game tape).root merkleAnswers)
          claim.I claim.a claim.pf ∧
        policy.accepts statement alpha (responseOf output) query
          (fun j ↦ claim.a j.1)
    let bindBreak := fun tape :
      Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
        (family.game tape).Bad dec merkleAnswers
    ((eventSet fun tape ↦
      trace.caseA listed win bindBreak i tape ∧ ¬listed tape).card : ℚ) /
        Fintype.card
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
      hypergeometricRatio floor n r := by
  classical
  dsimp only
  let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
    dflt (fun _output ↦ alphaKey)
      (fun output ↦ (alphaKey, responseOf output))
  let oracle := SchemeOracle.ofColumns
    ((family.game reference).boundMessage dec merkleAnswers)
  let listed := fun tape :
      Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
    responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1 ∈
      responses (Bcs.TypedFiatShamir.definingAlphaAnswer trace tape)
  let win := fun tape : Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
    let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
    let claim := (family.game tape).claim merkleAnswers
    claim.I = query.coordinates ∧
      Merkle.MH.Accepts
        (codec.withOracle ((family.game tape).oracle merkleAnswers)) n
        ((family.game tape).root merkleAnswers)
        claim.I claim.a claim.pf ∧
      policy.accepts statement alpha (responseOf output) query
        (fun j ↦ claim.a j.1)
  let bindBreak := fun tape :
    Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
      (family.game tape).Bad dec merkleAnswers
  let allowed := fun pref : Sumcheck.Prefix
      (Answer Alpha (QuerySet n r)) i.val ↦
    let alpha := Bcs.TypedFiatShamir.canonicalCaseAFloorAlpha adversary
      dflt alphaKey responseOf i pref
    let response :=
      (Bcs.TypedFiatShamir.canonicalCaseAFloorSubsetKey adversary dflt
        alphaKey responseOf i pref).2
    floorBoundedCoordinates floor (acceptingCoordinates alpha response)
  have hresult : ((Finset.univ.filter (fun tape ↦
        trace.caseA listed win bindBreak i tape ∧ ¬listed tape)).card : ℚ) /
          Fintype.card
            (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
        hypergeometricRatio floor n r := by
    apply Bcs.TypedFiatShamir.ligero_caseA_floor_tape_ratio_le
      (floor := floor) i allowed
      (fun tape ↦ trace.caseA listed win bindBreak i tape ∧ ¬listed tape)
    · intro pref
      exact floorBoundedCoordinates_card_le _
    · intro tape hevent
      have hcase := hevent.1
      have hunlisted := hevent.2
      have hwin := hcase.1
      have hgood := hcase.2.1
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
      let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
      have haccept := policy_accepts_of_prefixBindingFamily code layout policy
        statement codec family dec reference tape merkleAnswers alpha
          (responseOf output) query hwin.1 hwin.2.1 hgood hwin.2.2
      have hnot : responseOf output ∉ responses alpha := by
        simpa only [listed, output, alpha] using hunlisted
      have hcard := hfloor alpha (responseOf output) query haccept hnot
      have hquerySubset := hsubset alpha (responseOf output) query haccept
      have hresponse := Bcs.TypedFiatShamir.canonicalCaseAFloorSubsetKey_eq
        adversary dflt alphaKey responseOf listed win bindBreak i tape hcase
          hunlisted
      have halpha := Bcs.TypedFiatShamir.canonicalCaseAFloorAlpha_eq adversary
        dflt alphaKey responseOf listed win bindBreak i tape hcase hunlisted
      have hsubsetAnswer := Bcs.TypedFiatShamir.caseA_floor_definingSubsetAnswer
        trace listed win bindBreak i tape hcase hunlisted
      rw [← hsubsetAnswer]
      simp only [allowed]
      rw [halpha, hresponse, floorBoundedCoordinates_eq _ hcard]
      simpa only [alpha, output, query] using hquerySubset
    · exact hquery
  calc
    _ = ((Finset.univ.filter (fun tape ↦
          trace.caseA listed win bindBreak i tape ∧ ¬listed tape)).card : ℚ) /
          Fintype.card
            (Fin (N + 2) → Answer Alpha (QuerySet n r)) := by
      congr 2
      apply congrArg Finset.card
      ext tape
      simp [eventSet, trace, listed, win, bindBreak]
    _ ≤ hypergeometricRatio floor n r := hresult

/-- Recombine the exhaustive unlisted/listed split of one Case-A
first-occurrence cell.  This is a pure finite-probability union bound; the two
inputs are the independently checked floor and listed theorems. -/
theorem caseA_ratio_le_of_floor_listed
    {Q : Type*} [BEq Q] [LawfulBEq Q]
    [Nonempty Alpha] [Nonempty (QuerySet n r)] {T : ℕ}
    (trace : Bcs.FirstOccurrenceTrace
      (Fin T → Answer Alpha (QuerySet n r)) Q T)
    (listed win bindBreak :
      (Fin T → Answer Alpha (QuerySet n r)) → Prop)
    [DecidablePred listed] [DecidablePred win] [DecidablePred bindBreak]
    (i : Fin T) (epsilonFloor epsilonListed : ℚ)
    (hfloor : ((eventSet fun tape ↦
      trace.caseA listed win bindBreak i tape ∧ ¬listed tape).card : ℚ) /
        Fintype.card (Fin T → Answer Alpha (QuerySet n r)) ≤ epsilonFloor)
    (hlisted : ((eventSet fun tape ↦
      trace.caseA listed win bindBreak i tape ∧ listed tape).card : ℚ) /
        Fintype.card (Fin T → Answer Alpha (QuerySet n r)) ≤ epsilonListed) :
    ((eventSet (trace.caseA listed win bindBreak i)).card : ℚ) /
        Fintype.card (Fin T → Answer Alpha (QuerySet n r)) ≤
      epsilonFloor + epsilonListed := by
  classical
  let allSet := eventSet (trace.caseA listed win bindBreak i)
  let floorSet := eventSet fun tape ↦
    trace.caseA listed win bindBreak i tape ∧ ¬listed tape
  let listedSet := eventSet fun tape ↦
    trace.caseA listed win bindBreak i tape ∧ listed tape
  have hcover : allSet ⊆ floorSet ∪ listedSet := by
    intro tape htape
    have hcase : trace.caseA listed win bindBreak i tape := by
      simpa [allSet, eventSet] using htape
    by_cases h : listed tape
    · exact Finset.mem_union_right _ (by
        simp [listedSet, eventSet, hcase, h])
    · exact Finset.mem_union_left _ (by
        simp [floorSet, eventSet, hcase, h])
  have hden : (0 : ℚ) <
      Fintype.card (Fin T → Answer Alpha (QuerySet n r)) := by
    exact_mod_cast Fintype.card_pos
  rw [div_le_iff₀ hden]
  have hfloor' := (div_le_iff₀ hden).mp hfloor
  have hlisted' := (div_le_iff₀ hden).mp hlisted
  calc
    (allSet.card : ℚ) ≤ ((floorSet ∪ listedSet).card : ℚ) := by
      exact_mod_cast Finset.card_le_card hcover
    _ ≤ ((floorSet.card + listedSet.card : ℕ) : ℚ) := by
      exact_mod_cast Finset.card_union_le floorSet listedSet
    _ = (floorSet.card : ℚ) + listedSet.card := by push_cast; ring
    _ ≤ epsilonFloor *
          Fintype.card (Fin T → Answer Alpha (QuerySet n r)) +
        epsilonListed *
          Fintype.card (Fin T → Answer Alpha (QuerySet n r)) :=
      add_le_add (by simpa [floorSet] using hfloor')
        (by simpa [listedSet] using hlisted')
    _ = (epsilonFloor + epsilonListed) *
        Fintype.card (Fin T → Answer Alpha (QuerySet n r)) := by ring

/-- Policy-generic complete Case A obtained by composing the checked floor
and listed cells above.  Protocol specializations must prove the canonical
list bound and the two accepting-coordinate facts, but do not supply any
probability expression or operational transcript premise. -/
theorem canonical_caseA_prefixBound_profiled_ratio_le
    {F Equations CheckedMask DirectMask AlphaKey Response Salt D Enc Output
      PrefixOut RunOut : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Fintype CheckedMask] [DecidableEq CheckedMask]
    [Fintype Response] [DecidableEq Response] [Nonempty Response]
    [Inhabited Salt] [Inhabited D] [DecidableEq D] [DecidableEq Enc]
    [DecidableEq AlphaKey] [Nonempty Alpha] [Nonempty (QuerySet n r)]
    {logicalWidth w nw nq e g profileDenominator failureDenominator
      merkleT N prefixFuel runFuel floor : ℕ}
    (code : MultiplicativeCode F r w n)
    (layout : ConstraintLayout F logicalWidth w)
    (policy : SchemeProtocolPolicy (Equations := Equations) code layout
      Alpha Response CheckedMask DirectMask nw nq 1)
    (statement : ConstraintSystem F nw nq logicalWidth Equations)
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F CheckedMask DirectMask nw nq 1) D Enc)
    (family : Merkle.MH.PrefixBindingFamily
      (Out := PrefixOut) (RunOut := RunOut) codec
      (Fin (N + 2) → Answer Alpha (QuerySet n r)) n merkleT
        prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec)
    (merkleAnswers : Fin merkleT → D)
    (adversary : Merkle.RandomOracle.Tree
      (Bcs.TypedFiatShamir.Query AlphaKey (AlphaKey × Response))
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (alphaKey : AlphaKey) (responseOf : Output → Response)
    (reference : Fin (N + 2) → Answer Alpha (QuerySet n r))
    (i : Fin (N + 2))
    (responses : Alpha → Finset Response) (listBound : ℕ)
    (hlist : ∀ alpha, (responses alpha).card ≤ listBound)
    (acceptingCoordinates : Alpha → Response → Finset (Fin n))
    (hsubset : ∀ alpha response query,
      policy.accepts statement alpha response query
          (openSchemeOracle
            (SchemeOracle.ofColumns
              ((family.game reference).boundMessage dec merkleAnswers)) query) →
        query.coordinates ⊆ acceptingCoordinates alpha response)
    (hfloor : ∀ alpha response query,
      policy.accepts statement alpha response query
          (openSchemeOracle
            (SchemeOracle.ofColumns
              ((family.game reference).boundMessage dec merkleAnswers)) query) →
        response ∉ responses alpha →
        (acceptingCoordinates alpha response).card ≤ floor)
    (failureProfile arithmeticProfile : AgreementProfile n)
    (classifier : ∀ strategy : Alpha → Response,
      PolicyDoublyProfiledSoundnessClassifier policy
        (SchemeOracle.ofColumns
          ((family.game reference).boundMessage dec merkleAnswers))
        statement strategy failureProfile arithmeticProfile
          profileDenominator failureDenominator e g)
    (hprofile : 0 < profileDenominator)
    (hfailure : 0 < failureDenominator) (hquery : r ≤ n)
    (baselineAgreement : ℕ) (hbaselineAgreement : baselineAgreement ≤ n)
    (hprofileFloor : ∀ a ≤ baselineAgreement,
      profileDenominator ≤ arithmeticProfile.labelsAtLeast a) :
    let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
      dflt (fun _output ↦ alphaKey)
        (fun output ↦ (alphaKey, responseOf output))
    let listed := fun tape :
        Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
      responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1 ∈
        responses (Bcs.TypedFiatShamir.definingAlphaAnswer trace tape)
    let win := fun tape : Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
      let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
      let claim := (family.game tape).claim merkleAnswers
      claim.I = query.coordinates ∧
        Merkle.MH.Accepts
          (codec.withOracle ((family.game tape).oracle merkleAnswers)) n
          ((family.game tape).root merkleAnswers)
          claim.I claim.a claim.pf ∧
        policy.accepts statement alpha (responseOf output) query
          (fun j ↦ claim.a j.1)
    let bindBreak := fun tape :
      Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
        (family.game tape).Bad dec merkleAnswers
    ((eventSet (trace.caseA listed win bindBreak i)).card : ℚ) /
        Fintype.card
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
      hypergeometricRatio floor n r + listBound *
        (failureProfile.excessContribution failureDenominator n n 0 r
            (max (n - e - 1) (min n (g + baselineAgreement))) +
          arithmeticProfile.contribution profileDenominator n e g r) := by
  classical
  dsimp only
  let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
    dflt (fun _output ↦ alphaKey)
      (fun output ↦ (alphaKey, responseOf output))
  let listed := fun tape :
      Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
    responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1 ∈
      responses (Bcs.TypedFiatShamir.definingAlphaAnswer trace tape)
  let win := fun tape : Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
    let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
    let claim := (family.game tape).claim merkleAnswers
    claim.I = query.coordinates ∧
      Merkle.MH.Accepts
        (codec.withOracle ((family.game tape).oracle merkleAnswers)) n
        ((family.game tape).root merkleAnswers)
        claim.I claim.a claim.pf ∧
      policy.accepts statement alpha (responseOf output) query
        (fun j ↦ claim.a j.1)
  let bindBreak := fun tape :
    Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
      (family.game tape).Bad dec merkleAnswers
  have hfloorCell := canonical_caseA_floor_prefixBound_ratio_le code layout
    policy statement codec family dec merkleAnswers adversary dflt alphaKey
    responseOf reference i responses acceptingCoordinates hsubset hfloor hquery
  have hlistedCell := canonical_caseA_listed_prefixBound_profiled_ratio_le
    code layout policy statement codec family dec merkleAnswers adversary dflt
    alphaKey responseOf reference i responses listBound hlist failureProfile
    arithmeticProfile classifier hprofile hfailure hquery baselineAgreement
      hbaselineAgreement hprofileFloor
  have hcombined := caseA_ratio_le_of_floor_listed trace listed win bindBreak i
    (hypergeometricRatio floor n r)
    (listBound *
      (failureProfile.excessContribution failureDenominator n n 0 r
          (max (n - e - 1) (min n (g + baselineAgreement))) +
        arithmeticProfile.contribution profileDenominator n e g r))
    (by simpa only [trace, listed, win, bindBreak] using hfloorCell)
    (by simpa only [trace, listed, win, bindBreak] using hlistedCell)
  simpa only [trace, listed, win, bindBreak] using hcombined

set_option maxHeartbeats 2000000 in
omit [DecidableEq Alpha] in
/-- Threshold-free policy-generic Case A.  Every execution pays one shared
baseline at the later subset-query slot.  Only the excess outside that
baseline is charged to the earlier response/challenge slot, where the exact
pointwise response-list multiplicity is integrated against the actual
response-agreement tail. -/
theorem canonical_caseA_prefixBound_responseAgreement_ratio_le
    {F Equations CheckedMask DirectMask AlphaKey Response Salt D Enc Output
      PrefixOut RunOut : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Fintype CheckedMask] [DecidableEq CheckedMask]
    [Fintype Response] [DecidableEq Response] [Nonempty Response]
    [Inhabited Salt] [Inhabited D] [DecidableEq D] [DecidableEq Enc]
    [DecidableEq AlphaKey] [Nonempty Alpha] [Nonempty (QuerySet n r)]
    {logicalWidth w nw nq e g profileDenominator failureDenominator
      merkleT N prefixFuel runFuel floor : ℕ}
    (code : MultiplicativeCode F r w n)
    (layout : ConstraintLayout F logicalWidth w)
    (policy : SchemeProtocolPolicy (Equations := Equations) code layout
      Alpha Response CheckedMask DirectMask nw nq 1)
    (statement : ConstraintSystem F nw nq logicalWidth Equations)
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F CheckedMask DirectMask nw nq 1) D Enc)
    (family : Merkle.MH.PrefixBindingFamily
      (Out := PrefixOut) (RunOut := RunOut) codec
      (Fin (N + 2) → Answer Alpha (QuerySet n r)) n merkleT
        prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec)
    (merkleAnswers : Fin merkleT → D)
    (adversary : Merkle.RandomOracle.Tree
      (Bcs.TypedFiatShamir.Query AlphaKey (AlphaKey × Response))
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (alphaKey : AlphaKey) (responseOf : Output → Response)
    (reference : Fin (N + 2) → Answer Alpha (QuerySet n r))
    (i : Fin (N + 2))
    (failureProfile arithmeticProfile : AgreementProfile n)
    (classifier : ∀ strategy : Alpha → Response,
      PolicyDoublyProfiledSoundnessClassifier policy
        (SchemeOracle.ofColumns
          ((family.game reference).boundMessage dec merkleAnswers))
        statement strategy failureProfile arithmeticProfile
          profileDenominator failureDenominator e g)
    (multiplicity : ℕ → ℕ)
    (hprofile : 0 < profileDenominator)
    (hfailure : 0 < failureDenominator) (hquery : r ≤ n)
    (hfloor : floor < n) (hfarFloor : n - e - 1 ≤ floor)
    (hlist : ∀ a, floor < a → a ≤ n → ∀ alpha,
      (policyResponseAgreementList policy
        (SchemeOracle.ofColumns
          ((family.game reference).boundMessage dec merkleAnswers))
        statement alpha a).card ≤ multiplicity a) :
    let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
      dflt (fun _output ↦ alphaKey)
        (fun output ↦ (alphaKey, responseOf output))
    let oracle := SchemeOracle.ofColumns
      ((family.game reference).boundMessage dec merkleAnswers)
    let baseline := fun alpha response ↦
      ResponseAgreement.baselineCoordinates floor
        (policyAcceptingCoordinates policy oracle statement alpha response)
    let listed := fun tape :
        Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
      let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
      ¬query.coordinates ⊆ baseline alpha (responseOf output)
    let win := fun tape : Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
      let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
      let claim := (family.game tape).claim merkleAnswers
      claim.I = query.coordinates ∧
        Merkle.MH.Accepts
          (codec.withOracle ((family.game tape).oracle merkleAnswers)) n
          ((family.game tape).root merkleAnswers)
          claim.I claim.a claim.pf ∧
        policy.accepts statement alpha (responseOf output) query
          (fun j ↦ claim.a j.1)
    let bindBreak := fun tape :
      Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
        (family.game tape).Bad dec merkleAnswers
    ((eventSet (trace.caseA listed win bindBreak i)).card : ℚ) /
        Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
      min 1 (hypergeometricRatio floor n r +
        (ResponseAgreement.multipliedProfile multiplicity
          (ResponseAgreement.combinedProfile failureDenominator
            profileDenominator g failureProfile arithmeticProfile)).rawExcessContribution
              (ResponseAgreement.combinedDenominator failureDenominator
                profileDenominator) n n 0 r floor) := by
  classical
  dsimp only
  let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
    dflt (fun _output ↦ alphaKey)
      (fun output ↦ (alphaKey, responseOf output))
  let oracle := SchemeOracle.ofColumns
    ((family.game reference).boundMessage dec merkleAnswers)
  let baseline := fun alpha response ↦
    ResponseAgreement.baselineCoordinates floor
      (policyAcceptingCoordinates policy oracle statement alpha response)
  let listed := fun tape : Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
    let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
    ¬query.coordinates ⊆ baseline alpha (responseOf output)
  let win := fun tape : Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
    let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
    let claim := (family.game tape).claim merkleAnswers
    claim.I = query.coordinates ∧
      Merkle.MH.Accepts
        (codec.withOracle ((family.game tape).oracle merkleAnswers)) n
        ((family.game tape).root merkleAnswers)
        claim.I claim.a claim.pf ∧
      policy.accepts statement alpha (responseOf output) query
        (fun j ↦ claim.a j.1)
  let bindBreak := fun tape : Fin (N + 2) → Answer Alpha (QuerySet n r) ↦
    (family.game tape).Bad dec merkleAnswers
  let epsilon :=
    (ResponseAgreement.multipliedProfile multiplicity
      (ResponseAgreement.combinedProfile failureDenominator
        profileDenominator g failureProfile arithmeticProfile)).rawExcessContribution
          (ResponseAgreement.combinedDenominator failureDenominator
            profileDenominator) n n 0 r floor
  have hfloorCell : ((eventSet fun tape ↦
      trace.caseA listed win bindBreak i tape ∧ ¬listed tape).card : ℚ) /
        Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
      hypergeometricRatio floor n r := by
    let allowed := fun pref : Sumcheck.Prefix
        (Answer Alpha (QuerySet n r)) i.val ↦
      let alpha := Bcs.TypedFiatShamir.canonicalCaseAFloorAlpha adversary
        dflt alphaKey responseOf i pref
      let response :=
        (Bcs.TypedFiatShamir.canonicalCaseAFloorSubsetKey adversary dflt
          alphaKey responseOf i pref).2
      baseline alpha response
    have hraw : ((Finset.univ.filter (fun tape ↦
        trace.caseA listed win bindBreak i tape ∧ ¬listed tape)).card : ℚ) /
          Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
        hypergeometricRatio floor n r := by
      apply Bcs.TypedFiatShamir.ligero_caseA_floor_tape_ratio_le
        (floor := floor) i allowed
          (fun tape ↦ trace.caseA listed win bindBreak i tape ∧ ¬listed tape)
      · intro pref
        simp only [allowed, baseline,
          ResponseAgreement.baselineCoordinates_card]
        exact Nat.min_le_left _ _
      · intro tape hevent
        have hcase := hevent.1
        have hunlisted := hevent.2
        have hresponse := Bcs.TypedFiatShamir.canonicalCaseAFloorSubsetKey_eq
          adversary dflt alphaKey responseOf listed win bindBreak i tape hcase
            hunlisted
        have halpha := Bcs.TypedFiatShamir.canonicalCaseAFloorAlpha_eq adversary
          dflt alphaKey responseOf listed win bindBreak i tape hcase hunlisted
        have hsubsetAnswer := Bcs.TypedFiatShamir.caseA_floor_definingSubsetAnswer
          trace listed win bindBreak i tape hcase hunlisted
        rw [← hsubsetAnswer]
        simp only [allowed]
        rw [halpha, hresponse]
        exact not_not.mp (by simpa [listed] using hunlisted)
      · exact hquery
    calc
      ((eventSet fun tape ↦
          trace.caseA listed win bindBreak i tape ∧ ¬listed tape).card : ℚ) /
          Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) =
        ((Finset.univ.filter fun tape ↦
          trace.caseA listed win bindBreak i tape ∧ ¬listed tape).card : ℚ) /
          Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) := by
            congr 2
            apply congrArg Finset.card
            ext tape
            simp [eventSet]
      _ ≤ hypergeometricRatio floor n r := hraw
  have hsemantic : ∀ _data :
      (Fin (N + 1) → PUnit) × (Fin N → Answer Alpha (QuerySet n r)),
      ((Finset.univ.filter fun value : Response × (QuerySet n r × Alpha) ↦
        policy.accepts statement value.2.2 value.1 value.2.1
            (openSchemeOracle oracle value.2.1) ∧
          ¬value.2.1.coordinates ⊆ baseline value.2.2 value.1).card : ℚ) /
        Fintype.card (QuerySet n r × Alpha) ≤ epsilon := by
    intro _data
    have hpair := ResponseAgreement.profiled_policyResponseExcess_ratio_le
      policy oracle statement failureProfile arithmeticProfile classifier
      floor multiplicity (fun pair ↦ baseline pair.2 pair.1)
      hprofile hfailure hquery hfloor hfarFloor hlist
      (fun pair ↦ by
        exact ResponseAgreement.baselineCoordinates_subset _)
      (fun pair ↦ by
        exact ResponseAgreement.baselineCoordinates_card _)
    let semanticSuccess := fun response (query : QuerySet n r) alpha ↦
      policy.accepts statement alpha response query
          (openSchemeOracle oracle query) ∧
        ¬query.coordinates ⊆ baseline alpha response
    have hset :
        (ResponseAgreement.finiteEventSet fun value :
            (Response × Alpha) × QuerySet n r ↦
          semanticSuccess value.1.1 value.2 value.1.2) =
        (ResponseAgreement.responseExcessSet fun value :
            (Response × Alpha) × QuerySet n r ↦
          semanticSuccess value.1.1 value.2 value.1.2) := by
      ext value
      simp [ResponseAgreement.finiteEventSet,
        ResponseAgreement.responseExcessSet]
    have hpair' :
        ((ResponseAgreement.finiteEventSet fun value :
            (Response × Alpha) × QuerySet n r ↦
          semanticSuccess value.1.1 value.2 value.1.2).card : ℚ) /
            (Fintype.card (QuerySet n r) * Fintype.card Alpha) ≤ epsilon := by
      rw [hset]
      simpa [semanticSuccess, epsilon, baseline] using hpair
    have hreordered := ResponseAgreement.responseFirst_ratio_le_of_pairFirst
      semanticSuccess epsilon hpair'
    simpa [ResponseAgreement.finiteEventSet, semanticSuccess] using hreordered
  have hlistedCell : ((eventSet fun tape ↦
      trace.caseA listed win bindBreak i tape ∧ listed tape).card : ℚ) /
        Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
      epsilon := by
    let success := fun (_data :
        (Fin (N + 1) → PUnit) × (Fin N → Answer Alpha (QuerySet n r)))
        (response : Response) (query : QuerySet n r) (alpha : Alpha) ↦
      policy.accepts statement alpha response query
          (openSchemeOracle oracle query) ∧
        ¬query.coordinates ⊆ baseline alpha response
    letI : ∀ data response, DecidableRel (success data response) := by
      intro _ _ _ _
      exact Classical.propDecidable _
    letI : DecidablePred (fun tape ↦
        trace.caseA listed win bindBreak i tape ∧ listed tape) :=
      Classical.decPred _
    apply lazy_response_semantic_ratio_le adversary dflt i responseOf
      (fun _response ↦ Bcs.TypedFiatShamir.Query.alpha alphaKey)
      (fun response ↦ Bcs.TypedFiatShamir.Query.subset (alphaKey, response))
      success epsilon hsemantic
    intro tape hevent
    have hcase := hevent.1
    have hlisted := hevent.2
    have hselector := Bcs.TypedFiatShamir.canonicalCaseA_listed_selector
      adversary dflt (fun _output ↦ alphaKey) responseOf listed win bindBreak
        i tape hcase hlisted
    let rest := fun k ↦
      (Equiv.punitProd.{0} (Answer Alpha (QuerySet n r))).symm
        (tape (i.succAbove k))
    let chosen := Bcs.TypedFiatShamir.lazyResponseSelector adversary dflt i
      (fun _response : Response ↦ Bcs.TypedFiatShamir.Query.alpha alphaKey)
      (fun response ↦ Bcs.TypedFiatShamir.Query.subset (alphaKey, response))
      (tape i, responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1)
      rest
    let data := ((fun k ↦ (rest k).1),
      fun k ↦ (rest (chosen.succAbove k)).2)
    let pairChosen := Bcs.TypedFiatShamir.lazyResponseSelector adversary
      dflt i (fun value : AlphaKey × Response ↦
        Bcs.TypedFiatShamir.Query.alpha value.1)
      (fun value ↦ Bcs.TypedFiatShamir.Query.subset value)
      (tape i, (alphaKey,
        responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1))
      rest
    have hchosenEq : pairChosen = chosen := by
      apply Fin.ext
      simp only [pairChosen, chosen,
        Bcs.TypedFiatShamir.lazyResponseSelector,
        Bcs.TypedFiatShamir.lazyResponseTargetSlot,
        Bcs.TypedFiatShamir.lazyResponseTargetTrace]
    have hselector' :
        Bcs.TypedFiatShamir.lazyResponseLater adversary dflt i
            (fun _response : Response ↦ Bcs.TypedFiatShamir.Query.alpha alphaKey)
            (fun response ↦ Bcs.TypedFiatShamir.Query.subset (alphaKey, response))
            ((tape i, responseOf
              (Merkle.RandomOracle.lazyRun tape dflt adversary []).1), rest) ∧
          Bcs.TypedFiatShamir.alphaAnswer (tape i) =
            Bcs.TypedFiatShamir.definingAlphaAnswer trace tape ∧
          Bcs.TypedFiatShamir.subsetAnswer (rest chosen).2 =
            Bcs.TypedFiatShamir.definingSubsetAnswer trace tape := by
      refine ⟨?_, hselector.2.1, ?_⟩
      · exact hselector.1
      · rw [← hchosenEq]
        exact hselector.2.2
    have hwin := hcase.1
    have hgood := hcase.2.1
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
    let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
    have haccept := policy_accepts_of_prefixBindingFamily code layout policy
      statement codec family dec reference tape merkleAnswers alpha
        (responseOf output) query hwin.1 hwin.2.1 hgood hwin.2.2
    refine ⟨hselector'.1, ?_⟩
    constructor
    · rw [hselector'.2.1, hselector'.2.2]
      simpa only [oracle, query, alpha, output] using haccept
    · rw [hselector'.2.1, hselector'.2.2]
      simpa only [listed, baseline, query, alpha, output] using hlisted
  have hcombined := caseA_ratio_le_of_floor_listed trace listed win bindBreak i
    (hypergeometricRatio floor n r) epsilon hfloorCell hlistedCell
  have hone : ((eventSet (trace.caseA listed win bindBreak i)).card : ℚ) /
      Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤ 1 := by
    rw [div_le_one (by positivity)]
    exact_mod_cast Finset.card_le_card (Finset.subset_univ _)
  apply le_min hone
  simpa only [trace, listed, win, bindBreak, epsilon] using hcombined






theorem canonical_scheme_caseA_prefixBound_profiled_ratio_le
    {F Equations CheckedMask DirectMask AlphaKey Salt D Enc Output
      PrefixOut RunOut : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Fintype CheckedMask] [DecidableEq CheckedMask]
    [Inhabited Salt] [Inhabited D] [DecidableEq D] [DecidableEq Enc]
    [DecidableEq AlphaKey]
    {r w n nw nq e g profileDenominator failureDenominator merkleT N
      prefixFuel runFuel floor responseDistance : ℕ}
    (code : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F CheckedMask DirectMask nw nq 1) D Enc)
    (family : Merkle.MH.PrefixBindingFamily
      (Out := PrefixOut) (RunOut := RunOut) codec
      (Fin (N + 2) →
        Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
          (QuerySet n r)) n merkleT prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec)
    (merkleAnswers : Fin merkleT → D)
    (adversary : Merkle.RandomOracle.Tree
      (Bcs.TypedFiatShamir.Query AlphaKey
        (AlphaKey × Response F r w n 1))
      (Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
        (QuerySet n r)) Output N)
    (dflt : Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
      (QuerySet n r))
    (alphaKey : AlphaKey) (responseOf : Output → Response F r w n 1)
    (reference : Fin (N + 2) →
      Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
        (QuerySet n r))
    (i : Fin (N + 2))
    (failureProfile arithmeticProfile : AgreementProfile n)
    (classifier : ∀ strategy :
        SchemeChallenge F CheckedMask nw nq 1 Equations →
          Response F r w n 1,
      PolicyDoublyProfiledSoundnessClassifier
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) code scheme)
        (SchemeOracle.ofColumns
          ((family.game reference).boundMessage dec merkleAnswers))
        statement strategy failureProfile arithmeticProfile
          profileDenominator failureDenominator e g)
    (hprofile : 0 < profileDenominator)
    (hfailure : 0 < failureDenominator)
    (hquery : r ≤ n) (h2k : 2 * code.k ≤ n)
    (baselineAgreement : ℕ) (hbaselineAgreement : baselineAgreement ≤ n)
    (hprofileFloor : ∀ a ≤ baselineAgreement,
      profileDenominator ≤ arithmeticProfile.labelsAtLeast a)
    (hresponse : CodingTheory.HasMinimumDistanceAtLeast
      code.responseCode responseDistance)
    (hresponseRadius : n - (floor + 1) < responseDistance)
    (hresponseDen : 0 < CodingTheory.InterleavedJohnson.denominator
      n responseDistance (n - (floor + 1))) :
    let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
      dflt (fun _output ↦ alphaKey)
        (fun output ↦ (alphaKey, responseOf output))
    let oracle := SchemeOracle.ofColumns
      ((family.game reference).boundMessage dec merkleAnswers)
    let responses := fun alpha ↦
      RigidResponseList.schemeListedResponses code scheme statement oracle
        alpha (floor + 1)
    let listed := fun tape : Fin (N + 2) →
        Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
          (QuerySet n r) ↦
      responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1 ∈
        responses (Bcs.TypedFiatShamir.definingAlphaAnswer trace tape)
    let win := fun tape : Fin (N + 2) →
        Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
          (QuerySet n r) ↦
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
      let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
      let claim := (family.game tape).claim merkleAnswers
      claim.I = query.coordinates ∧
        Merkle.MH.Accepts
          (codec.withOracle ((family.game tape).oracle merkleAnswers)) n
          ((family.game tape).root merkleAnswers)
          claim.I claim.a claim.pf ∧
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) code scheme).accepts statement alpha
            (responseOf output) query (fun j ↦ claim.a j.1)
    let bindBreak := fun tape : Fin (N + 2) →
        Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
          (QuerySet n r) ↦
      (family.game tape).Bad dec merkleAnswers
    ((eventSet (trace.caseA listed win bindBreak i)).card : ℚ) /
        Fintype.card (Fin (N + 2) →
          Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
            (QuerySet n r)) ≤
      hypergeometricRatio floor n r +
        CodingTheory.InterleavedJohnson.listBound n responseDistance
          (n - (floor + 1)) *
          (failureProfile.excessContribution failureDenominator n n 0 r
              (max (n - e - 1) (min n (g + baselineAgreement))) +
            arithmeticProfile.contribution profileDenominator n e g r) := by
  classical
  letI : Nonempty (QuerySet n r) := QuerySet.nonempty hquery
  letI : Nonempty (Response F r w n 1) := ⟨⟨0, 0, 0⟩⟩
  dsimp only
  let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
    dflt (fun _output ↦ alphaKey)
      (fun output ↦ (alphaKey, responseOf output))
  let oracle := SchemeOracle.ofColumns
    ((family.game reference).boundMessage dec merkleAnswers)
  let responses := fun alpha ↦
    RigidResponseList.schemeListedResponses code scheme statement oracle
      alpha (floor + 1)
  let listed := fun tape : Fin (N + 2) →
      Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
        (QuerySet n r) ↦
    responseOf (Merkle.RandomOracle.lazyRun tape dflt adversary []).1 ∈
      responses (Bcs.TypedFiatShamir.definingAlphaAnswer trace tape)
  let win := fun tape : Fin (N + 2) →
      Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
        (QuerySet n r) ↦
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
    let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
    let claim := (family.game tape).claim merkleAnswers
    claim.I = query.coordinates ∧
      Merkle.MH.Accepts
        (codec.withOracle ((family.game tape).oracle merkleAnswers)) n
        ((family.game tape).root merkleAnswers)
        claim.I claim.a claim.pf ∧
      (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
        (repetitions := 1) code scheme).accepts statement alpha
          (responseOf output) query (fun j ↦ claim.a j.1)
  let bindBreak := fun tape : Fin (N + 2) →
      Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
        (QuerySet n r) ↦
    (family.game tape).Bad dec merkleAnswers
  let listBound :=
    CodingTheory.InterleavedJohnson.listBound n responseDistance
      (n - (floor + 1))
  have hlist : ∀ alpha, (responses alpha).card ≤ listBound := by
    intro alpha
    exact RigidResponseList.schemeListedResponses_card_le_interleaved code h2k
      scheme statement oracle alpha (floor + 1) hresponse hresponseRadius
        hresponseDen
  have hfloorCell := canonical_caseA_floor_prefixBound_ratio_le
    code (ConstraintLayout.identity w)
    (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
      (repetitions := 1) code scheme)
    statement codec family dec merkleAnswers adversary dflt alphaKey responseOf
    reference i responses
    (fun alpha response ↦ RigidResponseList.schemeAcceptingCoordinates code
      scheme statement oracle alpha response)
    (by
      intro alpha response query haccept
      exact RigidResponseList.scheme_query_subset_acceptingCoordinates_of_accepts
        code scheme statement oracle alpha response query haccept)
    (by
      intro alpha response query haccept hnot
      exact RigidResponseList.scheme_acceptingCoordinates_card_le_of_not_mem_listed
        code scheme statement oracle alpha response query floor haccept hnot)
    hquery
  have hlistedCell := canonical_caseA_listed_prefixBound_profiled_ratio_le
    code (ConstraintLayout.identity w)
    (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
      (repetitions := 1) code scheme)
    statement codec family dec merkleAnswers adversary dflt alphaKey responseOf
    reference i responses listBound hlist failureProfile arithmeticProfile
    classifier hprofile hfailure hquery baselineAgreement hbaselineAgreement
      hprofileFloor
  have hcombined := caseA_ratio_le_of_floor_listed trace listed win bindBreak i
    (hypergeometricRatio floor n r)
    (listBound *
      (failureProfile.excessContribution failureDenominator n n 0 r
          (max (n - e - 1) (min n (g + baselineAgreement))) +
        arithmeticProfile.contribution profileDenominator n e g r))
    (by simpa only [trace, listed, win, bindBreak, responses, oracle]
      using hfloorCell)
    (by simpa only [trace, listed, win, bindBreak, responses, oracle, listBound]
      using hlistedCell)
  simpa only [trace, listed, win, bindBreak, responses, oracle, listBound,
    Nat.cast_mul]
    using hcombined



theorem canonical_scheme_caseA_prefixBound_responseAgreement_ratio_le
    {F Equations CheckedMask DirectMask AlphaKey Salt D Enc Output
      PrefixOut RunOut : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Fintype CheckedMask] [DecidableEq CheckedMask]
    [Inhabited Salt] [Inhabited D] [DecidableEq D] [DecidableEq Enc]
    [DecidableEq AlphaKey]
    {r w n nw nq e g profileDenominator failureDenominator merkleT N
      prefixFuel runFuel floor responseDistance : ℕ}
    (code : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F CheckedMask DirectMask nw nq 1) D Enc)
    (family : Merkle.MH.PrefixBindingFamily
      (Out := PrefixOut) (RunOut := RunOut) codec
      (Fin (N + 2) →
        Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
          (QuerySet n r)) n merkleT prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec)
    (merkleAnswers : Fin merkleT → D)
    (adversary : Merkle.RandomOracle.Tree
      (Bcs.TypedFiatShamir.Query AlphaKey
        (AlphaKey × Response F r w n 1))
      (Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
        (QuerySet n r)) Output N)
    (dflt : Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
      (QuerySet n r))
    (alphaKey : AlphaKey) (responseOf : Output → Response F r w n 1)
    (reference : Fin (N + 2) →
      Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
        (QuerySet n r))
    (i : Fin (N + 2))
    (failureProfile arithmeticProfile : AgreementProfile n)
    (classifier : ∀ strategy :
        SchemeChallenge F CheckedMask nw nq 1 Equations → Response F r w n 1,
      PolicyDoublyProfiledSoundnessClassifier
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) code scheme)
        (SchemeOracle.ofColumns
          ((family.game reference).boundMessage dec merkleAnswers))
        statement strategy failureProfile arithmeticProfile
          profileDenominator failureDenominator e g)
    (hprofile : 0 < profileDenominator)
    (hfailure : 0 < failureDenominator)
    (hquery : r ≤ n) (h2k : 2 * code.k ≤ n)
    (hfloor : floor < n) (hfarFloor : n - e - 1 ≤ floor)
    (hresponse : CodingTheory.HasMinimumDistanceAtLeast
      code.responseCode responseDistance)
    (hresponseRadius : n - (floor + 1) < responseDistance)
    (hresponseDen : 0 < CodingTheory.InterleavedJohnson.denominator
      n responseDistance (n - (floor + 1))) :
    let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
      dflt (fun _output ↦ alphaKey)
        (fun output ↦ (alphaKey, responseOf output))
    let oracle := SchemeOracle.ofColumns
      ((family.game reference).boundMessage dec merkleAnswers)
    let baseline := fun alpha response ↦
      ResponseAgreement.baselineCoordinates floor
        (policyAcceptingCoordinates
          (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
            (repetitions := 1) code scheme)
          oracle statement alpha response)
    let listed := fun tape : Fin (N + 2) →
        Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
          (QuerySet n r) ↦
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
      let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
      ¬query.coordinates ⊆ baseline alpha (responseOf output)
    let win := fun tape : Fin (N + 2) →
        Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
          (QuerySet n r) ↦
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
      let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
      let claim := (family.game tape).claim merkleAnswers
      claim.I = query.coordinates ∧
        Merkle.MH.Accepts
          (codec.withOracle ((family.game tape).oracle merkleAnswers)) n
          ((family.game tape).root merkleAnswers)
          claim.I claim.a claim.pf ∧
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) code scheme).accepts statement alpha
            (responseOf output) query (fun j ↦ claim.a j.1)
    let bindBreak := fun tape : Fin (N + 2) →
        Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
          (QuerySet n r) ↦
      (family.game tape).Bad dec merkleAnswers
    ((eventSet (trace.caseA listed win bindBreak i)).card : ℚ) /
        Fintype.card (Fin (N + 2) →
          Answer (SchemeChallenge F CheckedMask nw nq 1 Equations)
            (QuerySet n r)) ≤
      min 1 (hypergeometricRatio floor n r +
        (ResponseAgreement.multipliedProfile
          (fun a ↦ CodingTheory.InterleavedJohnson.listBound
            n responseDistance (n - a))
          (ResponseAgreement.combinedProfile failureDenominator
            profileDenominator g failureProfile arithmeticProfile)).rawExcessContribution
              (ResponseAgreement.combinedDenominator failureDenominator
                profileDenominator) n n 0 r floor) := by
  classical
  letI : Nonempty (QuerySet n r) := QuerySet.nonempty hquery
  letI : Nonempty (Response F r w n 1) := ⟨⟨0, 0, 0⟩⟩
  dsimp only
  let oracle := SchemeOracle.ofColumns
    ((family.game reference).boundMessage dec merkleAnswers)
  let multiplicity := fun a ↦ CodingTheory.InterleavedJohnson.listBound
    n responseDistance (n - a)
  apply canonical_caseA_prefixBound_responseAgreement_ratio_le
    code (ConstraintLayout.identity w)
    (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
      (repetitions := 1) code scheme)
    statement codec family dec merkleAnswers adversary dflt alphaKey responseOf
      reference i failureProfile arithmeticProfile classifier multiplicity
      hprofile hfailure hquery hfloor hfarFloor
  · intro a hfa han alpha
    have herrors : n - a ≤ n - (floor + 1) := by
      exact Nat.sub_le_sub_left (by omega) n
    have hradius : n - a < responseDistance :=
      herrors.trans_lt hresponseRadius
    have hden : 0 < CodingTheory.InterleavedJohnson.denominator
        n responseDistance (n - a) :=
      CodingTheory.InterleavedJohnson.denominator_pos_of_le herrors
        (Nat.sub_le n (floor + 1)) hresponseDen
    rw [← RigidResponseList.schemeResponseAgreementList_eq_policy
      code scheme statement oracle alpha a]
    exact RigidResponseList.schemeResponseAgreementList_card_le_interleaved
      code h2k scheme statement oracle alpha a hresponse hradius hden




/-- Threshold-free Case B in one step: every fixed remainder of the adaptive
tape supplies its own selected alpha set and allowed-coordinate function;
the proved tail profile is integrated exactly and then lifted by predictable
deletion. -/
theorem lazy_prefix_profiled_incidence_ratio_le
    {Q Output : Type*} [DecidableEq Q]
    [Nonempty Alpha] [Nonempty (QuerySet n r)] {N : ℕ}
    (adversary : Merkle.RandomOracle.Tree Q
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (fixedSlot : Fin (N + 2))
    (targetFrom : List Q → Answer Alpha (QuerySet n r) → Q)
    (selected : ((Fin (N + 1) → PUnit) ×
      (Fin N → Answer Alpha (QuerySet n r))) → Finset Alpha)
    (allowed : ((Fin (N + 1) → PUnit) ×
      (Fin N → Answer Alpha (QuerySet n r))) →
        Alpha → Finset (Fin n))
    (profile : AgreementProfile n) (q : ℕ) (hq : 0 < q)
    (hdensity : ∀ data, ∀ a ≤ n,
      q * (AgreementProfile.restrictedTailSet (selected data)
        (fun alpha ↦ (allowed data alpha).card) a).card ≤
          profile.labelsAtLeast a * Fintype.card Alpha)
    (event : (Fin (N + 2) → Answer Alpha (QuerySet n r)) → Prop)
    [DecidablePred event]
    (hcover : ∀ tape, event tape →
      let fixed := tape fixedSlot
      let rest := fun k ↦ (Equiv.punitProd
        (Answer Alpha (QuerySet n r))).symm
          (tape (fixedSlot.succAbove k))
      let chosen := lazyPrefixSelector adversary dflt fixedSlot
        (Equiv.punitProd (Answer Alpha (QuerySet n r))).symm
          targetFrom fixed rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (chosen.succAbove k)).2)
      lazyPrefixLater adversary dflt fixedSlot
          (Equiv.punitProd (Answer Alpha (QuerySet n r))).symm
            targetFrom (fixed, rest) ∧
        alphaAnswer (rest chosen).2 ∈ selected data ∧
        (subsetAnswer fixed).coordinates ⊆
          allowed data (alphaAnswer (rest chosen).2)) :
    ((Finset.univ.filter event).card : ℚ) /
        Fintype.card
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
      profile.contribution q n n 0 r := by
  classical
  let success := fun data (query : QuerySet n r) (alpha : Alpha) ↦
    alpha ∈ selected data ∧ query.coordinates ⊆ allowed data alpha
  apply lazy_prefix_semantic_ratio_le adversary dflt fixedSlot targetFrom
    success (profile.contribution q n n 0 r)
  · intro data
    exact profiled_incidence_ratio_le (selected data) (allowed data)
      profile q hq (hdensity data)
  · intro tape htape
    simpa [success] using hcover tape htape

/-- Correct outer compiler for the actual asymmetric branches: response-
indexed Case A and prefix-derived Case B are first proved separately, then
united at each charged slot.  This theorem makes no claim that Case A's final
response is prefix-measurable. -/
theorem firstOccurrence_response_prefix_ratio_le
    {Q : Type*} [BEq Q] [LawfulBEq Q]
    [Nonempty Alpha] [Nonempty (QuerySet n r)]
    {N : ℕ}
    (trace : Bcs.FirstOccurrenceTrace
      (Fin (N + 2) → Answer Alpha (QuerySet n r)) Q (N + 2))
    (listed win bindBreak :
      (Fin (N + 2) → Answer Alpha (QuerySet n r)) → Prop)
    [DecidablePred listed] [DecidablePred win] [DecidablePred bindBreak]
    (bindEpsilon epsilonA epsilonB : ℚ)
    (hbind : ((eventSet bindBreak).card : ℚ) /
      Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
        bindEpsilon)
    (hcaseA : ∀ i, ((eventSet
      (trace.caseA listed win bindBreak i)).card : ℚ) /
        Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤ epsilonA)
    (hcaseB : ∀ i, ((eventSet
      (trace.caseB win bindBreak i)).card : ℚ) /
        Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤ epsilonB) :
    ((eventSet win).card : ℚ) /
        Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
      bindEpsilon + (N + 2) * (epsilonA + epsilonB) := by
  classical
  let queryEvent := fun i tape ↦
    trace.caseA listed win bindBreak i tape ∨
      trace.caseB win bindBreak i tape
  let querySet := fun i ↦ eventSet (queryEvent i)
  have htotal : (0 : ℚ) <
      Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) := by
    exact_mod_cast Fintype.card_pos
  have hquery : ∀ i, ((querySet i).card : ℚ) /
      Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
        epsilonA + epsilonB := by
    intro i
    let setA := eventSet (trace.caseA listed win bindBreak i)
    let setB := eventSet (trace.caseB win bindBreak i)
    have hsubset : querySet i ⊆ setA ∪ setB := by
      intro tape htape
      have hor : queryEvent i tape := by
        simpa [querySet, eventSet] using htape
      rcases hor with hA | hB
      · exact Finset.mem_union_left _
          (by simpa [setA, eventSet] using hA)
      · exact Finset.mem_union_right _
          (by simpa [setB, eventSet] using hB)
    have hcard : (querySet i).card ≤ setA.card + setB.card :=
      (Finset.card_le_card hsubset).trans (Finset.card_union_le _ _)
    rw [div_le_iff₀ htotal]
    have hA := (div_le_iff₀ htotal).mp (hcaseA i)
    have hB := (div_le_iff₀ htotal).mp (hcaseB i)
    calc
      ((querySet i).card : ℚ) ≤ (setA.card : ℚ) + setB.card := by
        exact_mod_cast hcard
      _ ≤ epsilonA *
            Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) +
          epsilonB *
            Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) :=
        add_le_add (by simpa [setA] using hA) (by simpa [setB] using hB)
      _ = (epsilonA + epsilonB) *
          Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) := by ring
  let attribution := trace.toUnifiedRigidRatioAttribution
    listed win bindBreak queryEvent (eventSet win) (eventSet bindBreak)
      querySet
      (fun tape ↦ by simp [eventSet])
      (fun tape ↦ by simp [eventSet])
      (fun i tape ↦ by simp [querySet, eventSet])
      (fun i tape ↦ by rfl)
      bindEpsilon (epsilonA + epsilonB) hbind hquery
  simpa [attribution, Bcs.FirstOccurrenceTrace.toUnifiedRigidRatioAttribution]
    using attribution.rom_compiler_ratio_le

/-- Canonical outer response-rigid compiler with prefix binding charged by
the theorem, not by a caller-supplied error formula.  The first-occurrence
trace is the actual domain-separated `Q + 2` lazy execution.  Thus the only
remaining obligations are the independently proved semantic Case-A and
Case-B cell bounds. -/
theorem canonical_prefixBinding_response_compiler_ratio_le
    {F CheckedMask DirectMask Salt Enc AlphaKey Response Output
      PrefixOut RunOut : Type*}
    [Field F] [Inhabited Salt]
    [DecidableEq Enc] [DecidableEq AlphaKey] [DecidableEq Response]
    [Nonempty Alpha] [Nonempty (QuerySet n r)]
    [Inhabited (Answer Alpha (QuerySet n r))]
    {nw nq repetitions N prefixFuel runFuel : ℕ}
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F CheckedMask DirectMask nw nq repetitions)
      (Answer Alpha (QuerySet n r)) Enc)
    (game : Merkle.MH.PrefixBindingGame
      (Out := PrefixOut) (RunOut := RunOut) codec n (N + 2)
        prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec)
    (hprefix : prefixFuel ≤ N + 2)
    (adversary : Merkle.RandomOracle.Tree
      (Bcs.TypedFiatShamir.Query AlphaKey (AlphaKey × Response))
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (keyOf : Output → AlphaKey) (responseOf : Output → Response)
    (listed win :
      (Fin (N + 2) → Answer Alpha (QuerySet n r)) → Prop)
    [DecidablePred listed] [DecidablePred win]
    [DecidablePred (game.Bad dec)]
    (epsilonA epsilonB : ℚ)
    (hcaseA : ∀ i, ((eventSet
      ((Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary dflt
        keyOf (fun output ↦ (keyOf output, responseOf output))).caseA
          listed win (game.Bad dec) i)).card : ℚ) /
        Fintype.card
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤ epsilonA)
    (hcaseB : ∀ i, ((eventSet
      ((Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary dflt
        keyOf (fun output ↦ (keyOf output, responseOf output))).caseB
          win (game.Bad dec) i)).card : ℚ) /
        Fintype.card
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤ epsilonB) :
    ((eventSet win).card : ℚ) /
        Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
      ((((prefixFuel * (prefixFuel - 1) / 2 +
            (N + 2) * (2 * prefixFuel + 1)) *
          Fintype.card (Answer Alpha (QuerySet n r)) ^ (N + 1) : ℕ) : ℚ) /
        Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r))) +
      (N + 2) * (epsilonA + epsilonB) := by
  apply firstOccurrence_response_prefix_ratio_le
    (Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary dflt keyOf
      (fun output ↦ (keyOf output, responseOf output)))
    listed win (game.Bad dec)
    ((((prefixFuel * (prefixFuel - 1) / 2 +
          (N + 2) * (2 * prefixFuel + 1)) *
        Fintype.card (Answer Alpha (QuerySet n r)) ^ (N + 1) : ℕ) : ℚ) /
      Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)))
    epsilonA epsilonB
  · let badSet : Finset
        (Fin (N + 2) → Answer Alpha (QuerySet n r)) :=
      Finset.univ.filter (game.Bad dec)
    have hset : eventSet (game.Bad dec) = badSet := by
      classical
      ext tape
      simp [eventSet, badSet]
    rw [hset]
    simpa only [badSet, show N + 2 - 1 = N + 1 by omega] using
      game.bad_ratio_le dec hprefix
  · exact hcaseA
  · exact hcaseB

/-- The correct domain-separated outer compiler: Merkle hashing and the two
Fiat--Shamir hashes use independent random-oracle domains, represented by a
product of a digest tape and the paired `(H₁,H₂)` answer tape.

For every fixed Merkle tape, the actual `Q + 2` first-occurrence theorem
charges the proved Case-A and Case-B densities.  Prefix binding is then
charged once on the independent digest tape by `bad_ratio_le`.  No shared-
tape correlation or binding-error formula is assumed. -/
theorem independent_prefixBinding_response_compiler_ratio_le
    {F CheckedMask DirectMask Salt D Enc AlphaKey Response Output
      PrefixOut RunOut : Type*}
    [Field F] [Inhabited Salt] [Inhabited D]
    [Fintype D] [DecidableEq D] [DecidableEq Enc]
    [DecidableEq AlphaKey] [DecidableEq Response]
    [Nonempty Alpha] [Nonempty (QuerySet n r)]
    {nw nq repetitions merkleT N prefixFuel runFuel : ℕ}
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F CheckedMask DirectMask nw nq repetitions) D Enc)
    (game : Merkle.MH.PrefixBindingGame
      (Out := PrefixOut) (RunOut := RunOut) codec n merkleT
        prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec)
    (hprefix : prefixFuel ≤ merkleT)
    (adversary : Merkle.RandomOracle.Tree
      (Bcs.TypedFiatShamir.Query AlphaKey (AlphaKey × Response))
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (keyOf : Output → AlphaKey) (responseOf : Output → Response)
    (listed win : (Fin merkleT → D) →
      (Fin (N + 2) → Answer Alpha (QuerySet n r)) → Prop)
    [DecidablePred (game.Bad dec)]
    (epsilonA epsilonB : ℚ) (hepsilonA : 0 ≤ epsilonA)
    (hepsilonB : 0 ≤ epsilonB)
    (hcaseA : ∀ merkleAnswers i,
      ((eventSet
        ((Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary dflt
          keyOf (fun output ↦ (keyOf output, responseOf output))).caseA
            (listed merkleAnswers) (win merkleAnswers)
            (fun _ ↦ game.Bad dec merkleAnswers) i)).card : ℚ) /
          Fintype.card
            (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤ epsilonA)
    (hcaseB : ∀ merkleAnswers i,
      ((eventSet
        ((Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary dflt
          keyOf (fun output ↦ (keyOf output, responseOf output))).caseB
            (win merkleAnswers)
            (fun _ ↦ game.Bad dec merkleAnswers) i)).card : ℚ) /
          Fintype.card
            (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤ epsilonB) :
    ((eventSet fun value :
        (Fin merkleT → D) ×
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ↦
        win value.1 value.2).card : ℚ) /
        Fintype.card
          ((Fin merkleT → D) ×
            (Fin (N + 2) → Answer Alpha (QuerySet n r))) ≤
      ((((prefixFuel * (prefixFuel - 1) / 2 +
            merkleT * (2 * prefixFuel + 1)) *
          Fintype.card D ^ (merkleT - 1) : ℕ) : ℚ) /
        Fintype.card (Fin merkleT → D)) +
      (N + 2) * (epsilonA + epsilonB) := by
  classical
  let MerkleTape := Fin merkleT → D
  let FsTape := Fin (N + 2) → Answer Alpha (QuerySet n r)
  let bindEvent : MerkleTape × FsTape → Prop := fun value ↦
    game.Bad dec value.1
  let goodWin : MerkleTape × FsTape → Prop := fun value ↦
    ¬game.Bad dec value.1 ∧ win value.1 value.2
  let beta : ℚ := (N + 2) * (epsilonA + epsilonB)
  have hbeta : 0 ≤ beta := by
    dsimp [beta]
    positivity
  have hgoodFiber : ∀ merkleAnswers : MerkleTape,
      ((Finset.univ.filter fun tape : FsTape ↦
        ¬game.Bad dec merkleAnswers ∧ win merkleAnswers tape).card : ℚ) /
          Fintype.card FsTape ≤ beta := by
    intro merkleAnswers
    by_cases hbad : game.Bad dec merkleAnswers
    · simp [hbad, hbeta]
    · have hcompiler := firstOccurrence_response_prefix_ratio_le
        (Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary dflt keyOf
          (fun output ↦ (keyOf output, responseOf output)))
        (listed merkleAnswers) (win merkleAnswers)
        (fun _ ↦ game.Bad dec merkleAnswers)
        0 epsilonA epsilonB
        (by simp [eventSet, hbad])
        (hcaseA merkleAnswers) (hcaseB merkleAnswers)
      have hevent :
          (Finset.univ.filter fun tape : FsTape ↦
            ¬game.Bad dec merkleAnswers ∧ win merkleAnswers tape) =
            eventSet (win merkleAnswers) := by
        ext tape
        simp [eventSet, hbad]
      rw [hevent]
      dsimp only [FsTape, beta]
      simpa only [zero_add] using hcompiler
  have hgood : ((Finset.univ.filter goodWin).card : ℚ) /
      Fintype.card (MerkleTape × FsTape) ≤ beta := by
    apply product_event_ratio_le_of_fiber
      (fun merkleAnswers tape ↦
        ¬game.Bad dec merkleAnswers ∧ win merkleAnswers tape)
      beta hgoodFiber
  have hbind : ((Finset.univ.filter bindEvent).card : ℚ) /
      Fintype.card (MerkleTape × FsTape) ≤
        ((((prefixFuel * (prefixFuel - 1) / 2 +
              merkleT * (2 * prefixFuel + 1)) *
            Fintype.card D ^ (merkleT - 1) : ℕ) : ℚ) /
          Fintype.card MerkleTape) := by
    rw [first_projection_event_ratio_eq]
    exact game.bad_ratio_le dec hprefix
  let winSet : Finset (MerkleTape × FsTape) :=
    Finset.univ.filter fun value ↦ win value.1 value.2
  let bindSet : Finset (MerkleTape × FsTape) :=
    Finset.univ.filter bindEvent
  let goodSet : Finset (MerkleTape × FsTape) :=
    Finset.univ.filter goodWin
  have hcover : winSet ⊆ bindSet ∪ goodSet := by
    intro value hvalue
    have hwin := (Finset.mem_filter.mp hvalue).2
    by_cases hbad : game.Bad dec value.1
    · exact Finset.mem_union_left _
        (Finset.mem_filter.mpr ⟨Finset.mem_univ _, hbad⟩)
    · exact Finset.mem_union_right _
        (Finset.mem_filter.mpr ⟨Finset.mem_univ _, hbad, hwin⟩)
  have hden : (0 : ℚ) < Fintype.card (MerkleTape × FsTape) := by
    exact_mod_cast Fintype.card_pos
  calc
    ((eventSet fun value : MerkleTape × FsTape ↦
        win value.1 value.2).card : ℚ) /
          Fintype.card (MerkleTape × FsTape) =
        (winSet.card : ℚ) / Fintype.card (MerkleTape × FsTape) := by
          rfl
    _ ≤ ((bindSet ∪ goodSet).card : ℚ) /
          Fintype.card (MerkleTape × FsTape) :=
      div_le_div_of_nonneg_right
        (by exact_mod_cast Finset.card_le_card hcover) hden.le
    _ ≤ ((bindSet.card + goodSet.card : ℕ) : ℚ) /
          Fintype.card (MerkleTape × FsTape) :=
      div_le_div_of_nonneg_right
        (by exact_mod_cast Finset.card_union_le bindSet goodSet) hden.le
    _ = (bindSet.card : ℚ) / Fintype.card (MerkleTape × FsTape) +
          (goodSet.card : ℚ) / Fintype.card (MerkleTape × FsTape) := by
      push_cast
      ring
    _ ≤ ((((prefixFuel * (prefixFuel - 1) / 2 +
              merkleT * (2 * prefixFuel + 1)) *
            Fintype.card D ^ (merkleT - 1) : ℕ) : ℚ) /
          Fintype.card MerkleTape) + beta := by
      exact add_le_add (by simpa [bindSet, bindEvent] using hbind)
        (by simpa [goodSet] using hgood)
    _ = _ := by rfl

/-- Fully general independent-domain compiler.  The later Merkle opening may
depend on the entire typed Fiat--Shamir tape, so each FS tape selects its own
`PrefixBindingGame`; the binding theorem is averaged in the Merkle-tape
direction.  Conversely, Case A/B is averaged in the FS-tape direction for
every fixed Merkle tape.  This is the product-space shape of an actual
domain-separated Fiat--Shamir execution. -/
theorem independent_prefixBinding_family_compiler_ratio_le
    {F CheckedMask DirectMask Salt D Enc AlphaKey Response Output
      PrefixOut RunOut : Type*}
    [Field F] [Inhabited Salt] [Inhabited D]
    [Fintype D] [DecidableEq D] [DecidableEq Enc]
    [DecidableEq AlphaKey] [DecidableEq Response]
    [Nonempty Alpha] [Nonempty (QuerySet n r)]
    {nw nq repetitions merkleT N prefixFuel runFuel : ℕ}
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F CheckedMask DirectMask nw nq repetitions) D Enc)
    (game : (Fin (N + 2) → Answer Alpha (QuerySet n r)) →
      Merkle.MH.PrefixBindingGame
        (Out := PrefixOut) (RunOut := RunOut) codec n merkleT
          prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec)
    (hprefix : prefixFuel ≤ merkleT)
    (adversary : Merkle.RandomOracle.Tree
      (Bcs.TypedFiatShamir.Query AlphaKey (AlphaKey × Response))
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (keyOf : Output → AlphaKey) (responseOf : Output → Response)
    (listed win : (Fin merkleT → D) →
      (Fin (N + 2) → Answer Alpha (QuerySet n r)) → Prop)
    [∀ fsAnswers, DecidablePred ((game fsAnswers).Bad dec)]
    (epsilonA epsilonB : ℚ)
    (hcaseA : ∀ merkleAnswers i,
      ((eventSet
        ((Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary dflt
          keyOf (fun output ↦ (keyOf output, responseOf output))).caseA
            (listed merkleAnswers) (win merkleAnswers)
            (fun fsAnswers ↦ (game fsAnswers).Bad dec merkleAnswers) i)).card : ℚ) /
          Fintype.card
            (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤ epsilonA)
    (hcaseB : ∀ merkleAnswers i,
      ((eventSet
        ((Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary dflt
          keyOf (fun output ↦ (keyOf output, responseOf output))).caseB
            (win merkleAnswers)
            (fun fsAnswers ↦ (game fsAnswers).Bad dec merkleAnswers) i)).card : ℚ) /
          Fintype.card
            (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤ epsilonB) :
    ((eventSet fun value :
        (Fin merkleT → D) ×
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ↦
        win value.1 value.2).card : ℚ) /
        Fintype.card
          ((Fin merkleT → D) ×
            (Fin (N + 2) → Answer Alpha (QuerySet n r))) ≤
      ((((prefixFuel * (prefixFuel - 1) / 2 +
            merkleT * (2 * prefixFuel + 1)) *
          Fintype.card D ^ (merkleT - 1) : ℕ) : ℚ) /
        Fintype.card (Fin merkleT → D)) +
      (N + 2) * (epsilonA + epsilonB) := by
  classical
  let MerkleTape := Fin merkleT → D
  let FsTape := Fin (N + 2) → Answer Alpha (QuerySet n r)
  let Omega := MerkleTape × FsTape
  let fsTrace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
    dflt keyOf (fun output ↦ (keyOf output, responseOf output))
  let fullTrace : Bcs.FirstOccurrenceTrace Omega
      (Bcs.TypedFiatShamir.Query AlphaKey (AlphaKey × Response)) (N + 2) :=
    fsTrace.comap Prod.snd
  let listedFull : Omega → Prop := fun value ↦ listed value.1 value.2
  let winFull : Omega → Prop := fun value ↦ win value.1 value.2
  let bindFull : Omega → Prop := fun value ↦
    (game value.2).Bad dec value.1
  let queryCase : Fin (N + 2) → Omega → Prop := fun i value ↦
    fullTrace.caseA listedFull winFull bindFull i value ∨
      fullTrace.caseB winFull bindFull i value
  let bindEpsilon : ℚ :=
    ((((prefixFuel * (prefixFuel - 1) / 2 +
          merkleT * (2 * prefixFuel + 1)) *
        Fintype.card D ^ (merkleT - 1) : ℕ) : ℚ) /
      Fintype.card MerkleTape)
  have hbind : ((eventSet bindFull).card : ℚ) /
      Fintype.card Omega ≤ bindEpsilon := by
    have hproduct := product_event_ratio_le_of_second_fiber
      (fun merkleAnswers : MerkleTape ↦ fun fsAnswers : FsTape ↦
        (game fsAnswers).Bad dec merkleAnswers)
      bindEpsilon (fun fsAnswers ↦ by
        simpa only [bindEpsilon, MerkleTape] using
          (game fsAnswers).bad_ratio_le dec hprefix)
    simpa only [eventSet, bindFull, Omega] using hproduct
  have hqueryFiber : ∀ merkleAnswers : MerkleTape, ∀ i,
      ((eventSet fun fsAnswers : FsTape ↦
        (fsTrace.caseA (listed merkleAnswers) (win merkleAnswers)
          (fun tape ↦ (game tape).Bad dec merkleAnswers) i fsAnswers) ∨
        (fsTrace.caseB (win merkleAnswers)
          (fun tape ↦ (game tape).Bad dec merkleAnswers) i fsAnswers)).card : ℚ) /
          Fintype.card FsTape ≤ epsilonA + epsilonB := by
    intro merkleAnswers i
    let setA := eventSet
      (fsTrace.caseA (listed merkleAnswers) (win merkleAnswers)
        (fun tape ↦ (game tape).Bad dec merkleAnswers) i)
    let setB := eventSet
      (fsTrace.caseB (win merkleAnswers)
        (fun tape ↦ (game tape).Bad dec merkleAnswers) i)
    let unionEvent := eventSet fun fsAnswers : FsTape ↦
      fsTrace.caseA (listed merkleAnswers) (win merkleAnswers)
          (fun tape ↦ (game tape).Bad dec merkleAnswers) i fsAnswers ∨
        fsTrace.caseB (win merkleAnswers)
          (fun tape ↦ (game tape).Bad dec merkleAnswers) i fsAnswers
    have hsubset : unionEvent ⊆ setA ∪ setB := by
      intro tape htape
      have hor :
          fsTrace.caseA (listed merkleAnswers) (win merkleAnswers)
              (fun fs ↦ (game fs).Bad dec merkleAnswers) i tape ∨
            fsTrace.caseB (win merkleAnswers)
              (fun fs ↦ (game fs).Bad dec merkleAnswers) i tape := by
        simpa [unionEvent, eventSet] using htape
      rcases hor with hA | hB
      · exact Finset.mem_union_left _
          (Finset.mem_filter.mpr ⟨Finset.mem_univ _, hA⟩)
      · exact Finset.mem_union_right _
          (Finset.mem_filter.mpr ⟨Finset.mem_univ _, hB⟩)
    have hden : (0 : ℚ) < Fintype.card FsTape := by
      exact_mod_cast Fintype.card_pos
    calc
      (unionEvent.card : ℚ) / Fintype.card FsTape
          ≤ ((setA ∪ setB).card : ℚ) / Fintype.card FsTape :=
        div_le_div_of_nonneg_right
          (by exact_mod_cast Finset.card_le_card hsubset) hden.le
      _ ≤ ((setA.card + setB.card : ℕ) : ℚ) / Fintype.card FsTape :=
        div_le_div_of_nonneg_right
          (by exact_mod_cast Finset.card_union_le setA setB) hden.le
      _ = (setA.card : ℚ) / Fintype.card FsTape +
          (setB.card : ℚ) / Fintype.card FsTape := by
        push_cast
        ring
      _ ≤ epsilonA + epsilonB := by
        exact add_le_add
          (by simpa only [setA, fsTrace, FsTape] using hcaseA merkleAnswers i)
          (by simpa only [setB, fsTrace, FsTape] using hcaseB merkleAnswers i)
  have hquery : ∀ i, ((eventSet (queryCase i)).card : ℚ) /
      Fintype.card Omega ≤ epsilonA + epsilonB := by
    intro i
    have hfiberRaw : ∀ merkleAnswers : MerkleTape,
        ((Finset.univ.filter fun fsAnswers : FsTape ↦
          (fsTrace.caseA (listed merkleAnswers) (win merkleAnswers)
            (fun tape ↦ (game tape).Bad dec merkleAnswers) i fsAnswers) ∨
          (fsTrace.caseB (win merkleAnswers)
            (fun tape ↦ (game tape).Bad dec merkleAnswers) i fsAnswers)).card : ℚ) /
            Fintype.card FsTape ≤ epsilonA + epsilonB := by
      intro merkleAnswers
      let raw := Finset.univ.filter fun fsAnswers : FsTape ↦
        (fsTrace.caseA (listed merkleAnswers) (win merkleAnswers)
          (fun tape ↦ (game tape).Bad dec merkleAnswers) i fsAnswers) ∨
        (fsTrace.caseB (win merkleAnswers)
          (fun tape ↦ (game tape).Bad dec merkleAnswers) i fsAnswers)
      have heq : raw = eventSet (fun fsAnswers : FsTape ↦
          (fsTrace.caseA (listed merkleAnswers) (win merkleAnswers)
            (fun tape ↦ (game tape).Bad dec merkleAnswers) i fsAnswers) ∨
          (fsTrace.caseB (win merkleAnswers)
            (fun tape ↦ (game tape).Bad dec merkleAnswers) i fsAnswers)) := by
        ext fsAnswers
        simp [raw, eventSet]
      rw [show (Finset.univ.filter fun fsAnswers : FsTape ↦
          (fsTrace.caseA (listed merkleAnswers) (win merkleAnswers)
            (fun tape ↦ (game tape).Bad dec merkleAnswers) i fsAnswers) ∨
          (fsTrace.caseB (win merkleAnswers)
            (fun tape ↦ (game tape).Bad dec merkleAnswers) i fsAnswers)) = raw by rfl,
        heq]
      exact hqueryFiber merkleAnswers i
    have hproduct := product_event_ratio_le_of_fiber
      (fun merkleAnswers : MerkleTape ↦ fun fsAnswers : FsTape ↦
        (fsTrace.caseA (listed merkleAnswers) (win merkleAnswers)
          (fun tape ↦ (game tape).Bad dec merkleAnswers) i fsAnswers) ∨
        (fsTrace.caseB (win merkleAnswers)
          (fun tape ↦ (game tape).Bad dec merkleAnswers) i fsAnswers))
      (epsilonA + epsilonB) hfiberRaw
    simpa only [eventSet, queryCase, fullTrace, listedFull, winFull,
      bindFull, fsTrace, Omega, Bcs.FirstOccurrenceTrace.comap,
      Bcs.FirstOccurrenceTrace.caseA, Bcs.FirstOccurrenceTrace.caseB] using hproduct
  let winSet : Finset Omega := eventSet winFull
  let bindSet : Finset Omega := eventSet bindFull
  let querySet : Fin (N + 2) → Finset Omega := fun i ↦ eventSet (queryCase i)
  let attribution := fullTrace.toUnifiedRigidRatioAttribution
    listedFull winFull bindFull queryCase winSet bindSet querySet
    (fun tape ↦ by simp [winSet, eventSet])
    (fun tape ↦ by simp [bindSet, eventSet])
    (fun i tape ↦ by simp [querySet, eventSet])
    (fun i tape ↦ by rfl)
    bindEpsilon (epsilonA + epsilonB)
    (by simpa [bindSet] using hbind)
    (by intro i; simpa [querySet] using hquery i)
  have hfinal := attribution.rom_compiler_ratio_le
  simp only [attribution,
    Bcs.FirstOccurrenceTrace.toUnifiedRigidRatioAttribution] at hfinal
  rw [Nat.cast_add, Nat.cast_ofNat] at hfinal
  change (winSet.card : ℚ) / Fintype.card Omega ≤
    bindEpsilon + (N + 2) * (epsilonA + epsilonB) at hfinal
  change ((eventSet winFull).card : ℚ) / Fintype.card Omega ≤
    bindEpsilon + (N + 2) * (epsilonA + epsilonB)
  rw [show eventSet winFull = winSet by rfl]
  exact hfinal

/-- Exact two-order A/B lifting theorem for the actual paired typed-answer
tape.  The alpha-first branch uses `(later subset, fixed alpha)`; the
subset-first branch uses `(fixed subset, later alpha)`.  Once each semantic
pair relation has a proved strategy-uniform density, the prefix-measurable
order split costs their `max`, never their sum. -/
theorem lazy_two_semantic_branches_ratio_le
    {Q Output : Type*} [DecidableEq Q] [Nonempty Alpha]
    [Nonempty (QuerySet n r)] {N : ℕ}
    (adversary : Merkle.RandomOracle.Tree Q
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (fixedSlot : Fin (N + 2))
    (targetFrom : List Q → Answer Alpha (QuerySet n r) → Q)
    (branchA : ((Fin (N + 1) → PUnit) ×
      (Fin N → Answer Alpha (QuerySet n r))) → Bool)
    (successA successB :
      ((Fin (N + 1) → PUnit) ×
        (Fin N → Answer Alpha (QuerySet n r))) →
          QuerySet n r → Alpha → Prop)
    [∀ data, DecidableRel (successA data)]
    [∀ data, DecidableRel (successB data)]
    (epsilonA epsilonB : ℚ)
    (hpairsA : ∀ data, ((Finset.univ.filter fun pair : QuerySet n r × Alpha ↦
      successA data pair.1 pair.2).card : ℚ) /
        Fintype.card (QuerySet n r × Alpha) ≤ epsilonA)
    (hpairsB : ∀ data, ((Finset.univ.filter fun pair : QuerySet n r × Alpha ↦
      successB data pair.1 pair.2).card : ℚ) /
        Fintype.card (QuerySet n r × Alpha) ≤ epsilonB)
    (event : (Fin (N + 2) → Answer Alpha (QuerySet n r)) → Prop)
    [DecidablePred event]
    (hcover : ∀ tape, event tape →
      let fixed := tape fixedSlot
      let rest := fun k ↦ (Equiv.punitProd
        (Answer Alpha (QuerySet n r))).symm (tape (fixedSlot.succAbove k))
      let selected := lazyPrefixSelector adversary dflt fixedSlot
        (Equiv.punitProd (Answer Alpha (QuerySet n r))).symm
          targetFrom fixed rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (selected.succAbove k)).2)
      lazyPrefixLater adversary dflt fixedSlot
          (Equiv.punitProd (Answer Alpha (QuerySet n r))).symm
            targetFrom (fixed, rest) ∧
        if branchA data then
          successA data (subsetAnswer (rest selected).2) (alphaAnswer fixed)
        else
          successB data (subsetAnswer fixed) (alphaAnswer (rest selected).2)) :
    ((Finset.univ.filter event).card : ℚ) /
        Fintype.card
          (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
      max epsilonA epsilonB := by
  classical
  let fullA := fun data
      (fixed later : Answer Alpha (QuerySet n r)) ↦
    successA data (subsetAnswer later) (alphaAnswer fixed)
  let fullB := fun data
      (fixed later : Answer Alpha (QuerySet n r)) ↦
    successB data (subsetAnswer fixed) (alphaAnswer later)
  have hfullA : ∀ data, ((Finset.univ.filter fun pair :
      Answer Alpha (QuerySet n r) × Answer Alpha (QuerySet n r) ↦
        fullA data pair.1 pair.2).card : ℚ) /
          (Fintype.card (Answer Alpha (QuerySet n r)) *
            Fintype.card (Answer Alpha (QuerySet n r))) ≤
        epsilonA := by
    intro data
    simpa only [Fintype.card_prod, Nat.cast_mul] using
      answer_pair_reverse_incidence_ratio_le_of_pair_ratio
        (successA data) epsilonA (hpairsA data)
  have hfullB : ∀ data, ((Finset.univ.filter fun pair :
      Answer Alpha (QuerySet n r) × Answer Alpha (QuerySet n r) ↦
        fullB data pair.1 pair.2).card : ℚ) /
          (Fintype.card (Answer Alpha (QuerySet n r)) *
            Fintype.card (Answer Alpha (QuerySet n r))) ≤
        epsilonB := by
    intro data
    simpa only [Fintype.card_prod, Nat.cast_mul] using
      answer_pair_incidence_ratio_le_of_pair_ratio
        (successB data) epsilonB (hpairsB data)
  apply lazy_prefix_two_branch_tape_ratio_le adversary dflt fixedSlot
    targetFrom branchA fullA fullB epsilonA epsilonB hfullA hfullB event
  intro tape htape
  simpa [fullA, fullB] using hcover tape htape

/-- End-to-end generic response-rigid compiler from an actual bounded lazy
execution, its canonical first-occurrence partition, and proved semantic A/B
pair densities.  The theorem performs both unions: A/B is combined by `max`
inside each prefix-measurable slot, then the possible first slots contribute
the single outer factor `N + 2`. -/
theorem firstOccurrence_lazy_semantic_compiler_ratio_le
    {Q Output : Type*} [DecidableEq Q] [BEq Q] [LawfulBEq Q]
    [Nonempty Alpha] [Nonempty (QuerySet n r)] {N : ℕ}
    (adversary : Merkle.RandomOracle.Tree Q
      (Answer Alpha (QuerySet n r)) Output N)
    (dflt : Answer Alpha (QuerySet n r))
    (trace : Bcs.FirstOccurrenceTrace
      (Fin (N + 2) → Answer Alpha (QuerySet n r)) Q (N + 2))
    (listed win bindBreak :
      (Fin (N + 2) → Answer Alpha (QuerySet n r)) → Prop)
    (queryCase : Fin (N + 2) →
      (Fin (N + 2) → Answer Alpha (QuerySet n r)) → Prop)
    (winSet bindSet :
      Finset (Fin (N + 2) → Answer Alpha (QuerySet n r)))
    (querySet : Fin (N + 2) →
      Finset (Fin (N + 2) → Answer Alpha (QuerySet n r)))
    (hwinSet : ∀ tape, tape ∈ winSet ↔ win tape)
    (hbindSet : ∀ tape, tape ∈ bindSet ↔ bindBreak tape)
    (hquerySet : ∀ i tape, tape ∈ querySet i ↔ queryCase i tape)
    (hcase : ∀ i tape, queryCase i tape ↔
      trace.caseA listed win bindBreak i tape ∨
        trace.caseB win bindBreak i tape)
    (bindEpsilon epsilonA epsilonB : ℚ)
    (hbind : (bindSet.card : ℚ) /
      Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
        bindEpsilon)
    (targetFrom : Fin (N + 2) →
      List Q → Answer Alpha (QuerySet n r) → Q)
    (branchA : Fin (N + 2) →
      ((Fin (N + 1) → PUnit) ×
        (Fin N → Answer Alpha (QuerySet n r))) → Bool)
    (successA successB : Fin (N + 2) →
      ((Fin (N + 1) → PUnit) ×
        (Fin N → Answer Alpha (QuerySet n r))) →
          QuerySet n r → Alpha → Prop)
    [∀ i data, DecidableRel (successA i data)]
    [∀ i data, DecidableRel (successB i data)]
    (hpairsA : ∀ i data,
      ((Finset.univ.filter fun pair : QuerySet n r × Alpha ↦
        successA i data pair.1 pair.2).card : ℚ) /
          Fintype.card (QuerySet n r × Alpha) ≤ epsilonA)
    (hpairsB : ∀ i data,
      ((Finset.univ.filter fun pair : QuerySet n r × Alpha ↦
        successB i data pair.1 pair.2).card : ℚ) /
          Fintype.card (QuerySet n r × Alpha) ≤ epsilonB)
    (hqueryCover : ∀ i tape, queryCase i tape →
      let fixed := tape i
      let rest := fun k ↦ (Equiv.punitProd
        (Answer Alpha (QuerySet n r))).symm (tape (i.succAbove k))
      let selected := lazyPrefixSelector adversary dflt i
        (Equiv.punitProd (Answer Alpha (QuerySet n r))).symm
          (targetFrom i) fixed rest
      let data := ((fun k ↦ (rest k).1),
        fun k ↦ (rest (selected.succAbove k)).2)
      lazyPrefixLater adversary dflt i
          (Equiv.punitProd (Answer Alpha (QuerySet n r))).symm
            (targetFrom i) (fixed, rest) ∧
        if branchA i data then
          successA i data (subsetAnswer (rest selected).2) (alphaAnswer fixed)
        else
          successB i data (subsetAnswer fixed) (alphaAnswer (rest selected).2)) :
    (winSet.card : ℚ) /
        Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
      bindEpsilon + (N + 2) * max epsilonA epsilonB := by
  classical
  have hquery : ∀ i, ((querySet i).card : ℚ) /
      Fintype.card (Fin (N + 2) → Answer Alpha (QuerySet n r)) ≤
        max epsilonA epsilonB := by
    intro i
    have hlazy := lazy_two_semantic_branches_ratio_le adversary dflt i
      (targetFrom i) (branchA i) (successA i) (successB i)
      epsilonA epsilonB (hpairsA i) (hpairsB i) (queryCase i)
      (hqueryCover i)
    have heq : querySet i = Finset.univ.filter (queryCase i) := by
      ext tape
      simp [hquerySet]
    rw [heq]
    exact hlazy
  let attribution := trace.toUnifiedRigidRatioAttribution
    listed win bindBreak queryCase winSet bindSet querySet
      hwinSet hbindSet hquerySet hcase bindEpsilon (max epsilonA epsilonB)
        hbind hquery
  simpa [attribution, Bcs.FirstOccurrenceTrace.toUnifiedRigidRatioAttribution]
    using attribution.rom_compiler_ratio_le

/-- Case B no longer enters the ledger as an assumed cardinality.  Actual
semantic incidence in the defining answers, the first-occurrence identities,
and `alpha_last_pair_card_le` derive the full tape count. -/
theorem semanticCaseB_card_le_of_incidence
    (trace : Bcs.FirstOccurrenceTrace
      (Fin T → Answer Alpha (QuerySet n r)) Query T)
    (partition : ThreeEventPartition
      (Fin T → Answer Alpha (QuerySet n r)))
    (bindBreak : (Fin T → Answer Alpha (QuerySet n r)) → Prop)
    (kind : SemanticEventKind) (i : Fin T)
    {goodCap absoluteCap badCount : ℕ}
    (bad : Finset Alpha) (allowed : Alpha → Finset (Fin n))
    (hbad : bad.card ≤ badCount)
    (hgood : ∀ alpha ∉ bad, (allowed alpha).card ≤ goodCap)
    (habsolute : ∀ alpha, (allowed alpha).card ≤ absoluteCap)
    (hincidence : ∀ tape, partition.event kind tape →
      (definingSubsetAnswer trace tape).coordinates ⊆
        allowed (definingAlphaAnswer trace tape)) :
    (eventSet (semanticCaseB trace partition bindBreak kind i)).card ≤
      (T - 1) *
        (Fintype.card Alpha * goodCap.choose r +
          badCount * absoluteCap.choose r) *
        Fintype.card (Answer Alpha (QuerySet n r)) ^ (T - 1) := by
  classical
  let event := semanticCaseB trace partition bindBreak kind i
  have hcount := ligero_caseB_tape_card_le i bad allowed event
    hbad hgood habsolute (by
      intro tape hevent
      have hkind := hevent.1
      have hcase := hevent.2
      obtain ⟨hsubset, alphaSlot, hne, halpha⟩ :=
        caseB_defining_answers trace partition.win bindBreak i tape hcase
      refine ⟨alphaSlot, hne, ?_⟩
      rw [← hsubset, ← halpha]
      exact hincidence tape hkind)
  simpa [eventSet, event] using hcount

/-- Case A's floor cell is derived from the actual defining subset answer at
the charged `H₂` slot. -/
theorem semanticCaseA_floor_card_le
    (trace : Bcs.FirstOccurrenceTrace
      (Fin T → Answer Alpha (QuerySet n r)) Query T)
    (partition : ThreeEventPartition
      (Fin T → Answer Alpha (QuerySet n r)))
    (listed : SemanticEventKind →
      (Fin T → Answer Alpha (QuerySet n r)) → Prop)
    (bindBreak : (Fin T → Answer Alpha (QuerySet n r)) → Prop)
    (kind : SemanticEventKind) (i : Fin T) {floor : ℕ}
    (allowed : Sumcheck.Prefix (Answer Alpha (QuerySet n r)) i.val →
      Finset (Fin n))
    (hallowed : ∀ pref, (allowed pref).card ≤ floor)
    (hincidence : ∀ tape,
      semanticCaseA trace partition listed bindBreak kind i tape →
      ¬listed kind tape →
      (definingSubsetAnswer trace tape).coordinates ⊆
        allowed (Sumcheck.extract_prefix tape i)) :
    (eventSet (fun tape =>
      semanticCaseA trace partition listed bindBreak kind i tape ∧
        ¬listed kind tape)).card ≤
      (Fintype.card Alpha * floor.choose r) *
        Fintype.card (Answer Alpha (QuerySet n r)) ^ (T - 1) := by
  classical
  let event := fun tape =>
    semanticCaseA trace partition listed bindBreak kind i tape ∧
      ¬listed kind tape
  have hcount := ligero_caseA_floor_tape_card_le i allowed event hallowed (by
    intro tape hevent
    have hsemantic := hevent.1
    have hunlisted := hevent.2
    have hanswer := caseA_floor_definingSubsetAnswer trace (listed kind)
      partition.win bindBreak i tape hsemantic.2 hunlisted
    rw [← hanswer]
    exact hincidence tape hsemantic hunlisted)
  convert hcount using 1
  all_goals first | rfl | (congr 1; ext; simp [eventSet, event])

/-- Case A's listed cell is derived from a strategy-uniform independent-pair
bound after all remaining tape data is fixed.  No response-list or selected-
MCA formula is assumed here: the caller supplies the proved per-data pair
theorem, and this result performs only the operational first-occurrence lift.
-/
theorem semanticCaseA_listed_card_le
    (trace : Bcs.FirstOccurrenceTrace
      (Fin T → Answer Alpha (QuerySet n r)) Query T)
    (partition : ThreeEventPartition
      (Fin T → Answer Alpha (QuerySet n r)))
    (listed : SemanticEventKind →
      (Fin T → Answer Alpha (QuerySet n r)) → Prop)
    (bindBreak : (Fin T → Answer Alpha (QuerySet n r)) → Prop)
    (kind : SemanticEventKind) (i : Fin T)
    (success : ∀ subsetSlot : Fin T,
      TwoSlotData Alpha (QuerySet n r) T subsetSlot i →
        QuerySet n r → Alpha → Prop)
    [∀ subsetSlot data, DecidableRel (success subsetSlot data)]
    (pairBudget : ℕ)
    (hpairs : ∀ subsetSlot (_hne : subsetSlot ≠ i) data,
      (Finset.univ.filter fun pair : QuerySet n r × Alpha =>
        success subsetSlot data pair.1 pair.2).card ≤ pairBudget)
    (hincidence : ∀ tape,
      semanticCaseA trace partition listed bindBreak kind i tape →
      listed kind tape →
      success (trace.subsetSlot tape)
        (twoSlotData (trace.subsetSlot tape) i tape)
        (definingSubsetAnswer trace tape) (definingAlphaAnswer trace tape)) :
    (eventSet (fun tape =>
      semanticCaseA trace partition listed bindBreak kind i tape ∧
        listed kind tape)).card ≤
      (T - 1) * pairBudget *
        Fintype.card (Answer Alpha (QuerySet n r)) ^ (T - 1) := by
  classical
  let event := fun tape =>
    semanticCaseA trace partition listed bindBreak kind i tape ∧
      listed kind tape
  have hcount := later_subset_slot_dependent_tape_card_le i success event
    pairBudget hpairs (by
      intro tape hevent
      have hsemantic := hevent.1
      have hlisted := hevent.2
      have halpha := trace.alphaSlot_eq_of_caseA_listed (listed kind)
        partition.win bindBreak i tape hsemantic.2 hlisted
      refine ⟨trace.subsetSlot tape, ?_, ?_⟩
      · intro heq
        exact trace.alphaSlot_ne_subsetSlot tape (halpha.trans heq.symm)
      · simpa [definingSubsetAnswer, definingAlphaAnswer, halpha] using
          hincidence tape hsemantic hlisted)
  convert hcount using 1
  all_goals first | rfl | (congr 1; ext; simp [eventSet, event])

/-- The complete Case-A cell is the union of its proved floor and listed
subcells. -/
theorem semanticCaseA_card_le_of_counts
    (trace : Bcs.FirstOccurrenceTrace
      (Fin T → Answer Alpha (QuerySet n r)) Query T)
    (partition : ThreeEventPartition
      (Fin T → Answer Alpha (QuerySet n r)))
    (listed : SemanticEventKind →
      (Fin T → Answer Alpha (QuerySet n r)) → Prop)
    (bindBreak : (Fin T → Answer Alpha (QuerySet n r)) → Prop)
    (kind : SemanticEventKind) (i : Fin T)
    (floorBudget listedBudget : ℕ)
    (hfloor : (eventSet (fun tape =>
      semanticCaseA trace partition listed bindBreak kind i tape ∧
        ¬listed kind tape)).card ≤ floorBudget)
    (hlisted : (eventSet (fun tape =>
      semanticCaseA trace partition listed bindBreak kind i tape ∧
        listed kind tape)).card ≤ listedBudget) :
    (eventSet (semanticCaseA trace partition listed bindBreak kind i)).card ≤
      floorBudget + listedBudget := by
  classical
  let floorSet := eventSet (fun tape =>
    semanticCaseA trace partition listed bindBreak kind i tape ∧
      ¬listed kind tape)
  let listedSet := eventSet (fun tape =>
    semanticCaseA trace partition listed bindBreak kind i tape ∧
      listed kind tape)
  calc
    (eventSet (semanticCaseA trace partition listed bindBreak kind i)).card
      ≤ (floorSet ∪ listedSet).card := by
        apply Finset.card_le_card
        intro tape htape
        have hsemantic := (Finset.mem_filter.mp htape).2
        by_cases h : listed kind tape
        · apply Finset.mem_union_right
          simp [listedSet, eventSet, hsemantic, h]
        · apply Finset.mem_union_left
          simp [floorSet, eventSet, hsemantic, h]
    _ ≤ floorSet.card + listedSet.card := Finset.card_union_le _ _
    _ ≤ floorBudget + listedBudget := Nat.add_le_add
      (by simpa [floorSet] using hfloor) (by simpa [listedSet] using hlisted)

end FirstOccurrenceEventLedger.TypedCounts

end LigeroFamily
