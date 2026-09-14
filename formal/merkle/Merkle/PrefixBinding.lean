import Merkle.ExtractionROM
import Mathlib.Data.Rat.Cast.Order

/-!
# Prefix-fixed Merkle binding

This file packages the generic half of `ExtractionROM` in the form needed by
Fiat--Shamir: extraction is performed from a distinguished execution prefix,
while the accepted opening may be produced anywhere later in a larger lazy-ROM
execution.

The important point is definitional.  `boundMessage` reads only
`prefixRun`; it does not inspect the suffix, the final opening, or any
challenge-oracle answer issued after the prefix.  `boundMessage_eq_of_prefixRun_eq`
makes that non-correlation property explicit.  The counted theorem then says
that an accepted later opening disagrees with this prefix-fixed total message
only on the standard commitment-collision/fresh-hit event.

`PrefixBindingGame` is deliberately an adapter, rather than another adversary
language.  A caller supplies a bounded whole execution `run`, a bounded phase
`prefix`, and the two structural facts produced by a real split execution:

* the phase's lazy slots are a prefix of the whole run's slots; and
* the whole run contains the verifier's materialized Merkle check.

This also applies to a phase in the middle of a multi-root execution; it need
not be the first syntactic `bind` of `run`.
-/

open Finset

set_option autoImplicit false
set_option relaxedAutoImplicit false

namespace Merkle
namespace MH

open RandomOracle

universe uSalt uMsg uDigest uEnc uOut uRun uIndex

variable {Salt : Type uSalt} {M : Type uMsg} {D : Type uDigest}
variable {Enc : Type uEnc} {Out : Type uOut} {RunOut : Type uRun}

/-- A root-exposure prefix embedded in an arbitrary bounded lazy-ROM run. -/
structure PrefixBindingGame [Inhabited D] [DecidableEq Enc]
    (C : Codec Salt M D Enc) (n T prefixFuel runFuel : ℕ) where
  /-- The Merkle-query phase ending immediately before this root is exposed to
  a challenge oracle. -/
  phase : Tree Enc D Out prefixFuel
  /-- The complete execution, including the later opening and its check. -/
  run : Tree Enc D RunOut runFuel
  /-- The root exposed by the prefix. -/
  rootOf : Out → D
  /-- The later opening selected by the complete execution. -/
  claim : (Fin T → D) → OpeningClaim n Salt M D
  /-- The complete execution fits in the fixed lazy answer tape. -/
  run_fits : runFuel ≤ T
  /-- The phase occupies an initial segment of the complete run's lazy slots. -/
  prefix_slots : ∀ answers,
    (lazyRun answers default phase []).2.1 <+: runSlots T run answers
  /-- The materialized check of the selected opening occurs in the complete
  execution. -/
  check_in_run : ∀ answers qa,
    qa ∈ ((checkPass C n (claim answers).I (claim answers).a
          (claim answers).pf (2 * n) fun _ ↦ default).run
        (runOracle T run answers)).2 →
      qa ∈ (run.run (runOracle T run answers)).2

namespace PrefixBindingGame

variable [Inhabited D] [Inhabited Salt] [Inhabited M]
variable [DecidableEq D] [DecidableEq Enc]
variable {C : Codec Salt M D Enc} {n T prefixFuel runFuel : ℕ}

/-- The complete execution's lazy-sampling oracle. -/
def oracle (G : PrefixBindingGame (Out := Out) (RunOut := RunOut) C n T prefixFuel runFuel)
    (answers : Fin T → D) : Enc → D :=
  runOracle T G.run answers

/-- The prefix query/answer trace, evaluated in the complete execution's
oracle. -/
def prefixTrace (G : PrefixBindingGame (Out := Out) (RunOut := RunOut) C n T prefixFuel runFuel)
    (answers : Fin T → D) : List (Enc × D) :=
  (G.phase.run (G.oracle answers)).2

/-- The root fixed by the prefix. -/
def root (G : PrefixBindingGame (Out := Out) (RunOut := RunOut) C n T prefixFuel runFuel)
    (answers : Fin T → D) : D :=
  G.rootOf (lazyRun answers default G.phase []).1

/-- Run the partial-tree extractor on an already materialized prefix run.
Missing leaves are filled with the extractor's defaults, so the result is a
total committed message even when extraction is partial. -/
noncomputable def messageOfPrefixRun
    (G : PrefixBindingGame (Out := Out) (RunOut := RunOut) C n T prefixFuel runFuel)
    (dec : RoleDecoders C) (prefixRun : Out × List Enc × List (Enc × D)) : Fin n → M :=
  match extract dec n (G.rootOf prefixRun.1) prefixRun.2.2 with
  | some out => out.message
  | none => fun _ => default

/-- The prefix-fixed total message.  Notice that the only tape-dependent
argument passed to `messageOfPrefixRun` is the lazy execution of `G.prefix`.
-/
noncomputable def boundMessage
    (G : PrefixBindingGame (Out := Out) (RunOut := RunOut) C n T prefixFuel runFuel)
    (dec : RoleDecoders C) (answers : Fin T → D) : Fin n → M :=
  G.messageOfPrefixRun dec (lazyRun answers default G.phase [])

/-- Prefix locality, in its strongest and most useful form: equal prefix runs
give literally equal bound messages, regardless of the suffixes of the two
answer tapes. -/
theorem boundMessage_eq_of_prefixRun_eq
    (G : PrefixBindingGame (Out := Out) (RunOut := RunOut) C n T prefixFuel runFuel)
    (dec : RoleDecoders C)
    {answers answers' : Fin T → D}
    (h : lazyRun answers default G.phase [] =
      lazyRun answers' default G.phase []) :
    G.boundMessage dec answers = G.boundMessage dec answers' := by
  simp only [boundMessage, h]

omit [Inhabited Salt] [Inhabited M] [DecidableEq D] in
/-- The prefix trace evaluated in the whole run's oracle is exactly the trace
of the standalone lazy prefix execution. -/
theorem prefixTrace_eq_lazy
    (G : PrefixBindingGame (Out := Out) (RunOut := RunOut) C n T prefixFuel runFuel)
    (answers : Fin T → D) :
    G.prefixTrace answers = (lazyRun answers default G.phase []).2.2 := by
  exact congrArg Prod.snd
    (lazyRun_run_eq_of_prefix answers default G.phase [] (G.oracle answers) _
      (fun _ ↦ rfl) (G.prefix_slots answers))

/-- If extraction from the prefix explains the later claim, the total
prefix-fixed message agrees with every opened coordinate. -/
theorem boundMessage_agrees_of_explains
    (G : PrefixBindingGame (Out := Out) (RunOut := RunOut) C n T prefixFuel runFuel)
    (dec : RoleDecoders C)
    (answers : Fin T → D)
    (h : ∃ out : Extracted n Salt M D,
      extract dec n (G.root answers) (G.prefixTrace answers) = some out ∧
        (∀ i ∈ (G.claim answers).I, out.message i = (G.claim answers).a i) ∧
        openFromTrapdoor out.trapdoor (G.claim answers).I = (G.claim answers).pf) :
    ∀ i ∈ (G.claim answers).I,
      G.boundMessage dec answers i = (G.claim answers).a i := by
  obtain ⟨out, hout, hagree, -⟩ := h
  intro i hi
  rw [root, prefixTrace_eq_lazy] at hout
  simp only [boundMessage, messageOfPrefixRun]
  rw [hout]
  exact hagree i hi

/-- An accepted later opening disagrees with the message extracted before
root exposure. -/
def Bad (G : PrefixBindingGame (Out := Out) (RunOut := RunOut) C n T prefixFuel runFuel)
    (dec : RoleDecoders C) (answers : Fin T → D) : Prop :=
  Accepts (C.withOracle (G.oracle answers)) n (G.root answers)
      (G.claim answers).I (G.claim answers).a (G.claim answers).pf ∧
    ∃ i ∈ (G.claim answers).I,
      G.boundMessage dec answers i ≠ (G.claim answers).a i

/-- The deterministic prefix-binding reduction.  Any disagreement with the
prefix-fixed message is covered by either a collision in the prefix trace or
a fresh slot hitting one of the prefix-determined candidate labels. -/
theorem bad_cover
    (G : PrefixBindingGame (Out := Out) (RunOut := RunOut) C n T prefixFuel runFuel)
    (dec : RoleDecoders C)
    (answers : Fin T → D) (hbad : G.Bad dec answers) :
    ¬ CollisionFree (G.prefixTrace answers) ∨
      HitFamily T (extractionHits runFuel prefixFuel)
        (fun p => (⟨p.1.val, lt_of_lt_of_le p.1.isLt G.run_fits⟩ : Fin T))
        (fun p ↦ hitTargetOf C dec prefixFuel T G.phase G.rootOf
          ⟨p.1.val, lt_of_lt_of_le p.1.isLt G.run_fits⟩ p.2) answers := by
  apply cover_of_failure_generic_eligible C n prefixFuel T G.phase G.run answers dec
    G.rootOf (G.root answers) (G.claim answers) G.run_fits
    (G.prefix_slots answers) rfl (G.check_in_run answers) hbad.1
  intro hexplains
  obtain ⟨i, hi, hne⟩ := hbad.2
  exact hne (G.boundMessage_agrees_of_explains dec answers hexplains i hi)

/-- **Prefix binding, counted.**  Over uniform lazy answer tapes, an accepted
opening can disagree with the total message extracted before root exposure on
at most

`(t(t-1)/2 + runFuel(2t+1)) * |D|^(T-1)`

tapes, where `t = prefixFuel`.  This is the same collision/fresh-hit cost as
two-stage extraction, but the opening may occur in an arbitrary larger run.
-/
theorem bad_card_le [Fintype D]
    (G : PrefixBindingGame (Out := Out) (RunOut := RunOut) C n T prefixFuel runFuel)
    (dec : RoleDecoders C)
    (hprefix : prefixFuel ≤ T) [DecidablePred (G.Bad dec)] :
    (Finset.filter (G.Bad dec) Finset.univ).card ≤
      (prefixFuel * (prefixFuel - 1) / 2 + runFuel * (2 * prefixFuel + 1)) *
        (Fintype.card D) ^ (T - 1) := by
  classical
  calc
    (Finset.filter (G.Bad dec) Finset.univ).card
        ≤ ((Finset.filter (fun answers : Fin T → D ↦
              ¬ CollisionFree (G.prefixTrace answers)) Finset.univ) ∪
            (Finset.filter (HitFamily (D := D) T (extractionHits runFuel prefixFuel)
              (fun p => (⟨p.1.val, lt_of_lt_of_le p.1.isLt G.run_fits⟩ : Fin T))
              (fun p ↦ hitTargetOf C dec prefixFuel T G.phase G.rootOf
                ⟨p.1.val, lt_of_lt_of_le p.1.isLt G.run_fits⟩ p.2))
              Finset.univ)).card := by
          apply Finset.card_le_card
          intro answers ha
          simp only [Finset.mem_filter, Finset.mem_univ, true_and] at ha ⊢
          rcases G.bad_cover dec answers ha with hcollision | hhit
          · exact Finset.mem_union_left _
              (Finset.mem_filter.mpr ⟨Finset.mem_univ _, hcollision⟩)
          · exact Finset.mem_union_right _
              (Finset.mem_filter.mpr ⟨Finset.mem_univ _, hhit⟩)
    _ ≤ (Finset.filter (fun answers : Fin T → D ↦
              ¬ CollisionFree (G.prefixTrace answers)) Finset.univ).card +
            (Finset.filter (HitFamily (D := D) T (extractionHits runFuel prefixFuel)
              (fun p => (⟨p.1.val, lt_of_lt_of_le p.1.isLt G.run_fits⟩ : Fin T))
              (fun p ↦ hitTargetOf C dec prefixFuel T G.phase G.rootOf
                ⟨p.1.val, lt_of_lt_of_le p.1.isLt G.run_fits⟩ p.2))
              Finset.univ).card := Finset.card_union_le _ _
    _ ≤ prefixFuel * (prefixFuel - 1) / 2 * (Fintype.card D) ^ (T - 1) +
          runFuel * (2 * prefixFuel + 1) * (Fintype.card D) ^ (T - 1) := by
        apply Nat.add_le_add
        · calc
            (Finset.filter (fun answers : Fin T → D ↦
                ¬ CollisionFree (G.prefixTrace answers)) Finset.univ).card
                ≤ (Finset.filter
                    (PairCollision (D := D) T (slotPairs T prefixFuel))
                    Finset.univ).card := by
                  apply Finset.card_le_card
                  intro answers ha
                  simp only [Finset.mem_filter, Finset.mem_univ, true_and] at ha ⊢
                  exact pairCollision_of_not_collisionFree_generic
                    (commit := G.phase) (R := G.run) (answers := answers)
                    (ht₁ := hprefix) (hpref := G.prefix_slots answers) (h := ha)
            _ ≤ (slotPairs T prefixFuel).card * (Fintype.card D) ^ (T - 1) :=
                answerTape_pairCollision_card_le T (slotPairs T prefixFuel)
                  slotPairs_distinct
            _ ≤ prefixFuel * (prefixFuel - 1) / 2 *
                  (Fintype.card D) ^ (T - 1) :=
                Nat.mul_le_mul_right _ (slotPairs_card_le T prefixFuel)
        · have h := answerTape_hitFamily_card_le (D := D) T
              (extractionHits runFuel prefixFuel)
              (fun p => (⟨p.1.val, lt_of_lt_of_le p.1.isLt G.run_fits⟩ : Fin T))
              (fun p ↦ hitTargetOf C dec prefixFuel T G.phase G.rootOf
                ⟨p.1.val, lt_of_lt_of_le p.1.isLt G.run_fits⟩ p.2)
              (fun p _ ↦ hitTarget_hitTargetOf C dec prefixFuel T G.phase G.rootOf
                ⟨p.1.val, lt_of_lt_of_le p.1.isLt G.run_fits⟩ p.2)
          simpa [extractionHits_card] using h
    _ = (prefixFuel * (prefixFuel - 1) / 2 + runFuel * (2 * prefixFuel + 1)) *
          (Fintype.card D) ^ (T - 1) := by ring

/-- Probability form of `bad_card_le`, with the exact finite answer-tape
denominator retained.  Downstream Fiat--Shamir compilers can therefore charge
prefix binding by invoking this theorem, rather than assuming a binding-error
formula. -/
theorem bad_ratio_le [Fintype D]
    (G : PrefixBindingGame (Out := Out) (RunOut := RunOut) C n T prefixFuel runFuel)
    (dec : RoleDecoders C)
    (hprefix : prefixFuel ≤ T) [DecidablePred (G.Bad dec)] :
    ((Finset.filter (G.Bad dec) Finset.univ).card : ℚ) /
        Fintype.card (Fin T → D) ≤
      (((prefixFuel * (prefixFuel - 1) / 2 + T * (2 * prefixFuel + 1)) *
          (Fintype.card D) ^ (T - 1) : ℕ) : ℚ) /
        Fintype.card (Fin T → D) := by
  apply div_le_div_of_nonneg_right
  · have hcard := G.bad_card_le dec hprefix
    have hbudget := Nat.mul_le_mul_right ((Fintype.card D) ^ (T - 1))
      (Nat.add_le_add_left (Nat.mul_le_mul_right (2 * prefixFuel + 1) G.run_fits)
        (prefixFuel * (prefixFuel - 1) / 2))
    exact_mod_cast hcard.trans hbudget
  · exact_mod_cast Nat.zero_le (Fintype.card (Fin T → D))

end PrefixBindingGame

/-! ## Query-dependent openings with one shared commitment prefix -/

/-- A family of later Merkle runs and opening claims sharing one
root-exposure phase.  The index is typically the typed Fiat--Shamir answer
tape: challenges may select different openings, but they cannot retroactively
change the phase from which the committed message is extracted. -/
structure PrefixBindingFamily [Inhabited D] [DecidableEq Enc]
    (C : Codec Salt M D Enc) (Index : Type uIndex)
    (n T prefixFuel runFuel : ℕ) where
  phase : Tree Enc D Out prefixFuel
  run : Index → Tree Enc D RunOut runFuel
  rootOf : Out → D
  claim : Index → (Fin T → D) → OpeningClaim n Salt M D
  run_fits : runFuel ≤ T
  prefix_slots : ∀ index answers,
    (lazyRun answers default phase []).2.1 <+:
      runSlots T (run index) answers
  check_in_run : ∀ index answers qa,
    qa ∈ ((checkPass C n (claim index answers).I (claim index answers).a
          (claim index answers).pf (2 * n) fun _ ↦ default).run
        (runOracle T (run index) answers)).2 →
      qa ∈ ((run index).run (runOracle T (run index) answers)).2

namespace PrefixBindingFamily

variable [Inhabited D] [Inhabited Salt] [Inhabited M]
variable [DecidableEq D] [DecidableEq Enc]
variable {C : Codec Salt M D Enc} {Index : Type uIndex}
variable {n T prefixFuel runFuel : ℕ}

/-- Every index gives a valid ordinary prefix-binding game. -/
def game
    (G : PrefixBindingFamily (Out := Out) (RunOut := RunOut)
      C Index n T prefixFuel runFuel)
    (index : Index) :
    PrefixBindingGame (Out := Out) (RunOut := RunOut)
      C n T prefixFuel runFuel where
  phase := G.phase
  run := G.run index
  rootOf := G.rootOf
  claim := G.claim index
  run_fits := G.run_fits
  prefix_slots := G.prefix_slots index
  check_in_run := G.check_in_run index

/-- The extracted total message is independent of which later opening run is
selected.  This is definitional because `boundMessage` reads only the shared
phase and shared `rootOf`. -/
theorem boundMessage_game_eq
    (G : PrefixBindingFamily (Out := Out) (RunOut := RunOut)
      C Index n T prefixFuel runFuel)
    (dec : RoleDecoders C) (first second : Index) (answers : Fin T → D) :
    (G.game first).boundMessage dec answers =
      (G.game second).boundMessage dec answers := rfl

end PrefixBindingFamily
end MH
end Merkle
