import Merkle.RandomOracle
import Mathlib.Algebra.BigOperators.Ring.Finset

/-!
# Fresh slots hitting predetermined values

`answerTape_pairCollision_card_le` counts events of the form "two slots agree".  The extraction
argument needs the other shape: **a fresh slot lands on a value the earlier slots already
determined** — an opening-stage query receiving one of the labels the commitment stage's extraction
already produced.  The target is not itself a slot: an extracted label is decoded out of a queried
*input*, not read off the tape.

What makes it countable is that the target does not depend on the slot being tested.  `HitTarget`
records exactly that, `answerTape_hit_card_le` is the `1/|D|` kernel, and
`answerTape_hitFamily_card_le` is the union bound over a fixed family of (slot, target) pairs — the
shape the three-event failure cover instantiates.
-/

open Finset

set_option autoImplicit false
set_option relaxedAutoImplicit false

namespace Merkle

namespace RandomOracle

universe uQ uD

variable {Q : Type uQ} {D : Type uD}

/-- `g` does not read coordinate `q₁`: its value is determined by the other answers.  This is the
independence the counting needs, and it is what "the target was fixed before the query" means. -/
def HitTarget [DecidableEq Q] (q₁ : Q) (g : (Q → D) → D) : Prop :=
  ∀ (H : Q → D) (d : D), g (Function.update H q₁ d) = g H

/-- Erasing a coordinate whose answer is pinned to a value the other coordinates determine stays
injective: the erased answer can be read back off `g`. -/
theorem eraseCoord_injective_on_hit [DecidableEq Q]
    (q₁ : Q) (g : (Q → D) → D) (hg : HitTarget q₁ g) :
    Function.Injective (fun H : {H : Q → D // H q₁ = g H} => eraseCoord q₁ H.val) := by
  intro H G heq
  have hoff : ∀ r : Q, r ≠ q₁ → H.val r = G.val r := fun r hr => congrFun heq ⟨r, hr⟩
  have hGupd : G.val = Function.update H.val q₁ (G.val q₁) := by
    funext r
    rw [Function.update_apply]
    split_ifs with hr
    · rw [hr]
    · exact (hoff r hr).symm
  have hg' : g G.val = g H.val := by
    rw [hGupd, hg]
  apply Subtype.ext
  funext q
  by_cases hq : q = q₁
  · rw [hq, H.property, G.property, hg']
  · exact hoff q hq

/-- **The fresh-hit kernel.**  A coordinate pinned to a value the other coordinates determine agrees
on at most a `1/|D|` fraction of oracles. -/
theorem hit_card_le [Fintype Q] [DecidableEq Q] [Fintype D] [DecidableEq D]
    (q₁ : Q) (g : (Q → D) → D) (hg : HitTarget q₁ g) :
    (Finset.filter (fun H : Q → D => H q₁ = g H) Finset.univ).card ≤
      (Fintype.card D) ^ (Fintype.card Q - 1) := by
  classical
  rw [← Fintype.card_subtype]
  calc
    Fintype.card {H : Q → D // H q₁ = g H}
        ≤ Fintype.card ({q : Q // q ≠ q₁} → D) :=
      Fintype.card_le_of_injective _ (eraseCoord_injective_on_hit q₁ g hg)
    _ = (Fintype.card D) ^ Fintype.card {q : Q // q ≠ q₁} := by
      rw [Fintype.card_fun]
    _ = (Fintype.card D) ^ (Fintype.card Q - 1) := by
      congr 1
      simp

/-- The answer-tape form of the fresh-hit kernel. -/
theorem answerTape_hit_card_le [Fintype D] [DecidableEq D]
    (T : ℕ) (j : Fin T) (g : (Fin T → D) → D) (hg : HitTarget j g) :
    (Finset.filter (fun answers : Fin T → D => answers j = g answers) Finset.univ).card ≤
      (Fintype.card D) ^ (T - 1) := by
  simpa using hit_card_le (D := D) j g hg

/-- **Neutralizing the tested slot makes any value a legitimate target.**  Whatever the target is
computed from, reading it off the tape with slot `q₁` overwritten cannot depend on slot `q₁`.

This is how the extraction cover gets its targets.  The label a fresh query has to hit is produced
by the *commitment* stage, which never reads the fresh slot — but "never reads it" is a statement
about the particular tape, whereas `HitTarget` demands invariance on every tape.  Evaluating the
target on the neutralized tape is invariant by construction, and agrees with the real label exactly
on the tapes where the commitment stage stopped short of that slot. -/
theorem hitTarget_of_neutralize [DecidableEq Q] (q₁ : Q) (v : D) (g : (Q → D) → D) :
    HitTarget q₁ (fun H => g (Function.update H q₁ v)) := by
  intro H d
  show g (Function.update (Function.update H q₁ d) q₁ v) = g (Function.update H q₁ v)
  rw [Function.update_idem]

/-- The event that some slot of a fixed family lands on its target. -/
def HitFamily {ι : Type*} (T : ℕ) (hits : Finset ι) (slot : ι → Fin T)
    (target : ι → (Fin T → D) → D) (answers : Fin T → D) : Prop :=
  ∃ k ∈ hits, answers (slot k) = target k answers

instance hitFamilyDecidable {ι : Type*} [DecidableEq D] (T : ℕ) (hits : Finset ι)
    (slot : ι → Fin T) (target : ι → (Fin T → D) → D) :
    DecidablePred (HitFamily (D := D) T hits slot target) := by
  intro answers
  unfold HitFamily
  infer_instance

/-- **Union bound over a fixed family of fresh hits.**  The family — which slots, and which target
each is tested against — is fixed in advance; only the *values* are adaptive, exactly as in
`answerTape_pairCollision_card_le`. -/
theorem answerTape_hitFamily_card_le {ι : Type*} [Fintype D] [DecidableEq D]
    (T : ℕ) (hits : Finset ι) (slot : ι → Fin T) (target : ι → (Fin T → D) → D)
    (hg : ∀ k ∈ hits, HitTarget (slot k) (target k)) :
    (Finset.filter (HitFamily (D := D) T hits slot target) Finset.univ).card ≤
      hits.card * (Fintype.card D) ^ (T - 1) := by
  classical
  calc
    (Finset.filter (HitFamily (D := D) T hits slot target) Finset.univ).card
        ≤ ∑ k ∈ hits,
            (Finset.filter (fun answers : Fin T → D =>
              answers (slot k) = target k answers) Finset.univ).card := by
      let pieces : ι → Finset (Fin T → D) :=
        fun k => Finset.filter (fun answers => answers (slot k) = target k answers)
          Finset.univ
      have heq : Finset.filter (HitFamily (D := D) T hits slot target) Finset.univ =
          hits.biUnion pieces := by
        ext answers
        simp [HitFamily, pieces]
      rw [heq]
      exact Finset.card_biUnion_le
    _ ≤ ∑ _k ∈ hits, (Fintype.card D) ^ (T - 1) :=
      Finset.sum_le_sum fun k hk => answerTape_hit_card_le T (slot k) (target k) (hg k hk)
    _ = hits.card * (Fintype.card D) ^ (T - 1) := by simp

/-! ## Conditions that determine a slot

`HitTarget` covers the shape "slot `j` equals a value the other slots determine".  The
digest-guessing event of the hiding argument has a weaker shape: a condition that *pins slot `j` down*
without naming its value — `nodeEnc (answers j, answers j') = x`, with `x` determined by the other
slots and `nodeEnc` injective, so the value at `j` is recoverable but only through a partial inverse
no one has to supply.  The count is the same `1/|D|`, and the only hypothesis that matters is the
pinning itself. -/

/-- **A condition that determines one slot from the others holds on at most a `1/|D|` fraction of
tapes.**  Strictly more general than `answerTape_hit_card_le`, whose predicate `answers j = g answers`
determines slot `j` outright; here it is enough that the predicate cannot hold at two different values
of slot `j` with the rest of the tape fixed. -/
theorem answerTape_slot_determined_card_le [Fintype D] [DecidableEq D] (T : ℕ) (j : Fin T)
    (P : (Fin T → D) → Prop) [DecidablePred P]
    (hdet : ∀ a b : Fin T → D, (∀ i : Fin T, i ≠ j → a i = b i) → P a → P b → a j = b j) :
    (Finset.filter P Finset.univ).card ≤ (Fintype.card D) ^ (T - 1) := by
  classical
  have hcard : Fintype.card {i : Fin T // i ≠ j} = T - 1 := by
    rw [Fintype.card_subtype_compl]; simp
  refine le_trans (Finset.card_le_card_of_injOn
    (fun a : Fin T → D => fun i : {i : Fin T // i ≠ j} => a i.val)
    (fun _ _ => Finset.mem_univ _) ?_) ?_
  · intro a ha b hb hab
    have hoff : ∀ i : Fin T, i ≠ j → a i = b i := fun i hi => congrFun hab ⟨i, hi⟩
    funext i
    by_cases hi : i = j
    · rw [hi]
      exact hdet a b hoff (Finset.mem_filter.mp ha).2 (Finset.mem_filter.mp hb).2
    · exact hoff i hi
  · rw [Finset.card_univ, Fintype.card_fun, hcard]

/--
**A fresh slot is uniform.**

The tapes on which slot `j` takes a given value number exactly `|D|^(T-1)` — the same count for every
value.  `answerTape_slot_determined_card_le` gives only `≤`, which is all a bad-event bound needs;
*uniformity* needs the equality, and it is what makes a freshly queried oracle answer a uniform coin
the simulator may sample instead.
-/
theorem answerTape_slot_eq_card [Fintype D] [DecidableEq D] (T : ℕ) (j : Fin T) (y : D) :
    (Finset.filter (fun a : Fin T → D => a j = y) Finset.univ).card
      = (Fintype.card D) ^ (T - 1) := by
  classical
  have hcard : Fintype.card {i : Fin T // i ≠ j} = T - 1 := by
    rw [Fintype.card_subtype_compl]; simp
  have e : {a : Fin T → D // a j = y} ≃ ({i : Fin T // i ≠ j} → D) :=
    { toFun := fun a i => a.1 i.val
      invFun := fun b => ⟨fun i => if h : i = j then y else b ⟨i, h⟩, by simp⟩
      left_inv := by
        intro a
        refine Subtype.ext ?_
        funext i
        by_cases h : i = j
        · subst h; simp [a.2]
        · simp [h]
      right_inv := by
        intro b
        funext i
        simp [i.property] }
  rw [← Fintype.card_subtype (p := fun a : Fin T → D => a j = y), Fintype.card_congr e,
    Fintype.card_fun, hcard]

/-- Union bound over a fixed family of slot-determining conditions.  As always the *family* is fixed
in advance and only the values are adaptive. -/
theorem answerTape_determinedFamily_card_le {ι : Type*} [Fintype D] [DecidableEq D]
    (T : ℕ) (fam : Finset ι) (slot : ι → Fin T) (P : ι → (Fin T → D) → Prop)
    [∀ k, DecidablePred (P k)]
    (hdet : ∀ k ∈ fam, ∀ a b : Fin T → D, (∀ i : Fin T, i ≠ slot k → a i = b i) →
      P k a → P k b → a (slot k) = b (slot k)) :
    (Finset.filter (fun answers => ∃ k ∈ fam, P k answers) Finset.univ).card ≤
      fam.card * (Fintype.card D) ^ (T - 1) := by
  classical
  calc (Finset.filter (fun answers : Fin T → D => ∃ k ∈ fam, P k answers) Finset.univ).card
      ≤ ∑ k ∈ fam, (Finset.filter (P k) Finset.univ).card := by
        have heq : Finset.filter (fun answers : Fin T → D => ∃ k ∈ fam, P k answers) Finset.univ =
            fam.biUnion fun k => Finset.filter (P k) Finset.univ := by
          ext answers; simp
        rw [heq]
        exact Finset.card_biUnion_le
    _ ≤ ∑ _k ∈ fam, (Fintype.card D) ^ (T - 1) :=
        Finset.sum_le_sum fun k hk =>
          answerTape_slot_determined_card_le T (slot k) (P k) (hdet k hk)
    _ = fam.card * (Fintype.card D) ^ (T - 1) := by simp

/-- **Two pinned slots.**  If the rest of the tape determines both slot `j₁` and slot `j₂` on the
event, the event holds on at most `|D|^(T-2)` tapes: the restriction to the other `T-2` slots is
injective on it. -/
theorem answerTape_two_slots_determined_card_le [Fintype D] [DecidableEq D] (T : ℕ)
    (j₁ j₂ : Fin T) (hne : j₁ ≠ j₂) (P : (Fin T → D) → Prop) [DecidablePred P]
    (hdet : ∀ a b : Fin T → D, (∀ i : Fin T, i ≠ j₁ → i ≠ j₂ → a i = b i) → P a → P b →
      a j₁ = b j₁ ∧ a j₂ = b j₂) :
    (Finset.filter P Finset.univ).card ≤ (Fintype.card D) ^ (T - 2) := by
  classical
  have hcard : Fintype.card {i : Fin T // i ≠ j₁ ∧ i ≠ j₂} = T - 2 := by
    rw [Fintype.card_subtype]
    have hset : (Finset.univ.filter fun i : Fin T => i ≠ j₁ ∧ i ≠ j₂) =
        Finset.univ \ {j₁, j₂} := by
      ext i; simp
    rw [hset, Finset.card_sdiff_of_subset (Finset.subset_univ _), Finset.card_univ,
      Fintype.card_fin, Finset.card_pair hne]
  refine le_trans (Finset.card_le_card_of_injOn
    (fun a : Fin T → D => fun i : {i : Fin T // i ≠ j₁ ∧ i ≠ j₂} => a i.val)
    (fun _ _ => Finset.mem_univ _) ?_) ?_
  · intro a ha b hb hab
    have hoff : ∀ i : Fin T, i ≠ j₁ → i ≠ j₂ → a i = b i :=
      fun i h₁ h₂ => congrFun hab ⟨i, h₁, h₂⟩
    have hd := hdet a b hoff (Finset.mem_filter.mp ha).2 (Finset.mem_filter.mp hb).2
    funext i
    by_cases h₁ : i = j₁
    · rw [h₁]; exact hd.1
    by_cases h₂ : i = j₂
    · rw [h₂]; exact hd.2
    exact hoff i h₁ h₂
  · rw [Finset.card_univ, Fintype.card_fun, hcard]

/-- The union bound over a fixed family of events, each pinning two distinct slots:
`|fam| · |D|^(T-2)`. -/
theorem answerTape_determinedFamily₂_card_le {ι : Type*} [Fintype D] [DecidableEq D]
    (T : ℕ) (fam : Finset ι) (slot₁ slot₂ : ι → Fin T) (hne : ∀ k ∈ fam, slot₁ k ≠ slot₂ k)
    (P : ι → (Fin T → D) → Prop) [∀ k, DecidablePred (P k)]
    (hdet : ∀ k ∈ fam, ∀ a b : Fin T → D,
      (∀ i : Fin T, i ≠ slot₁ k → i ≠ slot₂ k → a i = b i) →
      P k a → P k b → a (slot₁ k) = b (slot₁ k) ∧ a (slot₂ k) = b (slot₂ k)) :
    (Finset.filter (fun answers => ∃ k ∈ fam, P k answers) Finset.univ).card ≤
      fam.card * (Fintype.card D) ^ (T - 2) := by
  classical
  calc (Finset.filter (fun answers : Fin T → D => ∃ k ∈ fam, P k answers) Finset.univ).card
      ≤ ∑ k ∈ fam, (Finset.filter (P k) Finset.univ).card := by
        have heq : Finset.filter (fun answers : Fin T → D => ∃ k ∈ fam, P k answers) Finset.univ =
            fam.biUnion fun k => Finset.filter (P k) Finset.univ := by
          ext answers; simp
        rw [heq]
        exact Finset.card_biUnion_le
    _ ≤ ∑ _k ∈ fam, (Fintype.card D) ^ (T - 2) :=
        Finset.sum_le_sum fun k hk =>
          answerTape_two_slots_determined_card_le T (slot₁ k) (slot₂ k) (hne k hk) (P k)
            (hdet k hk)
    _ = fam.card * (Fintype.card D) ^ (T - 2) := by simp

/-! ## Fresh hits at a tape-dependent slot

`answerTape_hitFamily_card_le` names each tested slot in advance, so covering "the first fresh query
after the commitment stage" costs one name per slot the whole run could occupy.  The slot of that
query is `base answers + m`, where `base` — the commitment stage's slot count — is read off the slots
*below* it.  For a fixed offset `m` the events "the tested slot is `j`" are disjoint in `j` and do not
read slot `j`, so the family costs `1/|D|` per offset, not per slot. -/

/-- Name `k` tests slot `base answers + off k` against a target that may depend on that slot. -/
def ShiftedHitFamily {ι : Type*} (T : ℕ) (hits : Finset ι) (base : (Fin T → D) → ℕ)
    (off : ι → ℕ) (target : ι → Fin T → (Fin T → D) → D) (answers : Fin T → D) : Prop :=
  ∃ k ∈ hits, ∃ j : Fin T, j.val = base answers + off k ∧ answers j = target k j answers

instance shiftedHitFamilyDecidable {ι : Type*} [DecidableEq D] (T : ℕ) (hits : Finset ι)
    (base : (Fin T → D) → ℕ) (off : ι → ℕ) (target : ι → Fin T → (Fin T → D) → D) :
    DecidablePred (ShiftedHitFamily (D := D) T hits base off target) := by
  intro answers
  unfold ShiftedHitFamily
  infer_instance

/-- **The stopping-time kernel.**  If `base` is determined by the slots below it, then for a fixed
offset the slot `base + off` lands on a target not reading it on at most `|D|^(T-1)` tapes. -/
theorem answerTape_shifted_hit_card_le [Fintype D] [DecidableEq D] (T : ℕ)
    (base : (Fin T → D) → ℕ)
    (hbase : ∀ (a : Fin T → D) (j : Fin T) (d : D), base a ≤ j.val →
      base (Function.update a j d) = base a)
    (off : ℕ) (g : Fin T → (Fin T → D) → D) (hg : ∀ j, HitTarget j (g j)) :
    (Finset.univ.filter fun a : Fin T → D =>
        ∃ j : Fin T, j.val = base a + off ∧ a j = g j a).card ≤
      (Fintype.card D) ^ (T - 1) := by
  classical
  set N := Fintype.card D with hN
  let A : Fin T → Finset (Fin T → D) := fun j =>
    Finset.univ.filter fun a => j.val = base a + off ∧ a j = g j a
  let L : Fin T → Finset (Fin T → D) := fun j =>
    Finset.univ.filter fun a => j.val = base a + off
  -- each hit tape, with slot `j` rewritten arbitrarily, is still in `L j`, injectively
  have hA : ∀ j, (A j).card * N ≤ (L j).card := by
    intro j
    have h := Finset.card_le_card_of_injOn
      (fun p : (Fin T → D) × D => Function.update p.1 j p.2)
      (s := A j ×ˢ (Finset.univ : Finset D)) (t := L j) ?_ ?_
    · rwa [Finset.card_product, Finset.card_univ] at h
    · intro p hp
      have hpA := (Finset.mem_filter.mp (Finset.mem_product.mp hp).1).2
      refine Finset.mem_filter.mpr ⟨Finset.mem_univ _, ?_⟩
      rw [hbase p.1 j p.2 (by omega)]
      exact hpA.1
    · intro p hp p' hp' heq
      have hpA := (Finset.mem_filter.mp (Finset.mem_product.mp hp).1).2
      have hpA' := (Finset.mem_filter.mp (Finset.mem_product.mp hp').1).2
      simp only at heq
      have hd : p.2 = p'.2 := by
        have := congrFun heq j
        simpa using this
      have hoff : ∀ i, i ≠ j → p.1 i = p'.1 i := by
        intro i hi
        have := congrFun heq i
        simpa [Function.update_of_ne hi] using this
      have hj : p.1 j = p'.1 j := by
        rw [hpA.2, hpA'.2, ← hg j p.1 p.2, ← hg j p'.1 p'.2, heq]
      have h1 : p.1 = p'.1 := by
        funext i
        by_cases hi : i = j
        · rw [hi]; exact hj
        · exact hoff i hi
      exact Prod.ext h1 hd
  have hdisj : (↑(Finset.univ : Finset (Fin T)) : Set (Fin T)).PairwiseDisjoint L := by
    intro j _ j' _ hne
    rw [Function.onFun, Finset.disjoint_left]
    intro a ha ha'
    exact hne (Fin.ext (by
      have h1 := (Finset.mem_filter.mp ha).2
      have h2 := (Finset.mem_filter.mp ha').2
      omega))
  have hL : ∑ j, (L j).card ≤ N ^ T := by
    rw [← Finset.card_biUnion hdisj]
    calc _ ≤ (Finset.univ : Finset (Fin T → D)).card := Finset.card_le_card (Finset.subset_univ _)
      _ = N ^ T := by simp [hN]
  have hsub : (Finset.univ.filter fun a : Fin T → D =>
      ∃ j : Fin T, j.val = base a + off ∧ a j = g j a) ⊆ Finset.univ.biUnion A := by
    intro a ha
    obtain ⟨j, hj⟩ := (Finset.mem_filter.mp ha).2
    exact Finset.mem_biUnion.mpr ⟨j, Finset.mem_univ _, Finset.mem_filter.mpr ⟨Finset.mem_univ _, hj⟩⟩
  have key : (Finset.univ.filter fun a : Fin T → D =>
      ∃ j : Fin T, j.val = base a + off ∧ a j = g j a).card * N ≤ N ^ T := by
    calc _ ≤ (∑ j, (A j).card) * N :=
          Nat.mul_le_mul_right _ (le_trans (Finset.card_le_card hsub) Finset.card_biUnion_le)
      _ = ∑ j, (A j).card * N := Finset.sum_mul _ _ _
      _ ≤ ∑ j, (L j).card := Finset.sum_le_sum fun j _ => hA j
      _ ≤ N ^ T := hL
  rcases Nat.eq_zero_or_pos T with hT | hT
  · subst hT
    simp
  rcases Nat.eq_zero_or_pos N with hN0 | hNpos
  · calc _ ≤ Fintype.card (Fin T → D) := Finset.card_le_univ _
      _ = 0 := by
        rw [Fintype.card_fun, Fintype.card_fin, ← hN, hN0, zero_pow (Nat.pos_iff_ne_zero.mp hT)]
      _ ≤ _ := Nat.zero_le _
  · have hpow : N ^ T = N * N ^ (T - 1) := by
      rw [← pow_succ', Nat.sub_add_cancel hT]
    rw [hpow, Nat.mul_comm] at key
    exact Nat.le_of_mul_le_mul_left key hNpos

/-- The union bound over a family of tape-dependent slots: `|hits| · |D|^(T-1)`. -/
theorem answerTape_shiftedHitFamily_card_le {ι : Type*} [Fintype D] [DecidableEq D]
    (T : ℕ) (hits : Finset ι) (base : (Fin T → D) → ℕ)
    (hbase : ∀ (a : Fin T → D) (j : Fin T) (d : D), base a ≤ j.val →
      base (Function.update a j d) = base a)
    (off : ι → ℕ) (target : ι → Fin T → (Fin T → D) → D)
    (hg : ∀ k ∈ hits, ∀ j, HitTarget j (target k j)) :
    (Finset.univ.filter (ShiftedHitFamily (D := D) T hits base off target)).card ≤
      hits.card * (Fintype.card D) ^ (T - 1) := by
  classical
  calc (Finset.univ.filter (ShiftedHitFamily (D := D) T hits base off target)).card
      ≤ ∑ k ∈ hits, (Finset.univ.filter fun a : Fin T → D =>
          ∃ j : Fin T, j.val = base a + off k ∧ a j = target k j a).card := by
        have heq : Finset.univ.filter (ShiftedHitFamily (D := D) T hits base off target) =
            hits.biUnion fun k => Finset.univ.filter fun a : Fin T → D =>
              ∃ j : Fin T, j.val = base a + off k ∧ a j = target k j a := by
          ext a; simp [ShiftedHitFamily]
        rw [heq]
        exact Finset.card_biUnion_le
    _ ≤ ∑ _k ∈ hits, (Fintype.card D) ^ (T - 1) :=
        Finset.sum_le_sum fun k hk =>
          answerTape_shifted_hit_card_le T base hbase (off k) (target k) (hg k hk)
    _ = hits.card * (Fintype.card D) ^ (T - 1) := by simp

end RandomOracle

end Merkle
