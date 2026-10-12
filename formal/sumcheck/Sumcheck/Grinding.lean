import Sumcheck.Counting
import Mathlib.Algebra.BigOperators.Ring.Finset

/-!
# Grinding on a tape of challenges

How often an adversary that may **retry** can hit a rare event, when each retry draws a fresh
challenge from a tape and the event at slot `i` is decided by the slots before it together with
slot `i` itself.

This is the counting layer of Fiat--Shamir, and it is stated here with no protocol in it at all.
`Sumcheck.FiatShamir` is one instance: there the tape is the challenge sequence of a sumcheck run,
`n` is the round count, and the per-slot bad set is the root set of a degree-`deg` difference, so
`beta = deg`.  A Fiat--Shamir compiler is the other: the tape is the random oracle's answer tape,
`n` is the adversary's query budget, and the per-slot bad set is the set of answers that escape
doom from a doomed partial transcript.

## Prefix-measurability is in the typing, not in a hypothesis

The event at slot `i` is *given* as a predicate `P i : Prefix C i.val → C → Prop` — a function of
the prefix and of the slot value.  So "slot `i`'s bad set does not depend on slots after `i`" is
not something a caller has to promise and a reviewer has to check; a bad event that read a later
slot could not be written in this type.  That is the whole reason the bound holds, and it is worth
having it be unfalsifiable rather than hypothesised.

## The bounds

* `card_filter_prefix_r` — the exact fiber decomposition: filtering a tape by a
  prefix-and-slot predicate counts the good `(prefix, slot)` pairs times `|C|^(n-1-i)`;
* `slot_bad_card_le` — one slot, `beta * |C|^(n-1)`;
* `tape_bad_card_le` — every slot, with a **per-slot** budget: `(∑ i, beta i) * |C|^(n-1)`.
  Per-slot rather than uniform because the rounds of a real protocol have genuinely different
  densities (a sumcheck round pays `2/|C|`, a Ligero query round pays a cover ratio);
* `tape_bad_card_le_const` — the uniform-`beta` corollary, `n * beta * |C|^(n-1)`.

Everything here is a count over `ℕ`, deliberately: `Sumcheck` carries no rationals, and the
count-to-probability step belongs where the probabilities already live.  `bcs/Bcs/Soundness.lean`
does exactly that cast for the interactive bound (`compiled_card_le` to `compiled_ratio_le`), and
the Fiat--Shamir compiler will do the same with these.

`Prefix`, `extract_prefix` and the fiber machinery live here rather than in
`Sumcheck.FiatShamir` because none of them ever needed the field: every one of those lemmas
carried an `omit [Field F]`.  Generalising the carrier from `F` to an arbitrary `C` leaves their
statements unchanged, so `Sumcheck.FiatShamir` keeps its names by importing this file.
-/

set_option autoImplicit true
set_option relaxedAutoImplicit true

open Classical

namespace Sumcheck

/-! ## The tape and its prefixes -/

/-- The first `i` slots of a tape. -/
abbrev Prefix (C : Type*) (i : ℕ) := Fin i → C

/-- The prefix of `cs` strictly before slot `i`. -/
def extract_prefix {n : ℕ} {C : Type*} (cs : Fin n → C) (i : Fin n) : Prefix C i.val :=
  fun j => cs ⟨j.val, by omega⟩

section Fiber

variable {C : Type*} [Fintype C] [DecidableEq C]

/-- Slot `i + 1 + j`: the `j`-th slot strictly after `i`. -/
def right_index {n : ℕ} {i : Fin n} (j : Fin (n - 1 - i.val)) : Fin n :=
  ⟨i.val + 1 + j.val, by omega⟩

/-- Rebuild a whole tape from a prefix, a value at slot `i`, and the slots after `i`. -/
def reconstruct {n : ℕ} (i : Fin n) (pr : Prefix C i.val × C) (g : Fin (n - 1 - i.val) → C)
    (m : Fin n) : C :=
  if h1 : m.val < i.val then
    pr.1 ⟨m.val, h1⟩
  else if h2 : m.val = i.val then
    pr.2
  else
    g ⟨m.val - (i.val + 1), by omega⟩

omit [Fintype C] [DecidableEq C] in
lemma reconstruct_prefix {n : ℕ} (i : Fin n) (pr : Prefix C i.val × C)
    (g : Fin (n - 1 - i.val) → C) :
    extract_prefix (reconstruct i pr g) i = pr.1 := by
  ext j
  dsimp [extract_prefix, reconstruct]
  have h_lt : j.val < i.val := j.isLt
  simp [h_lt]

omit [Fintype C] [DecidableEq C] in
lemma reconstruct_at_i {n : ℕ} (i : Fin n) (pr : Prefix C i.val × C)
    (g : Fin (n - 1 - i.val) → C) :
    reconstruct i pr g i = pr.2 := by
  dsimp [reconstruct]
  have h_not_lt : ¬(i.val < i.val) := by omega
  simp

/-- Fixing the prefix and slot `i` leaves exactly the slots after `i` free. -/
def fiber_equiv {n : ℕ} (i : Fin n) (pr : Prefix C i.val × C) :
  { cs : Fin n → C // extract_prefix cs i = pr.1 ∧ cs i = pr.2 } ≃ (Fin (n - 1 - i.val) → C) where
  toFun cs j := cs.val (right_index j)
  invFun g := ⟨reconstruct i pr g, ⟨reconstruct_prefix i pr g, reconstruct_at_i i pr g⟩⟩
  left_inv cs := by
    ext m
    dsimp [reconstruct, right_index, extract_prefix]
    split_ifs with h1 h2
    · have h_eq := congr_fun cs.prop.1 ⟨m.val, h1⟩
      exact h_eq.symm
    · have h_eq : m = i := Fin.ext h2
      rw [h_eq]
      exact cs.prop.2.symm
    · apply congr_arg cs.val
      apply Fin.ext
      dsimp [right_index]
      omega
  right_inv g := by
    ext j
    dsimp [reconstruct, right_index]
    have h1 : ¬(i.val + 1 + j.val < i.val) := by omega
    have h2 : ¬(i.val + 1 + j.val = i.val) := by omega
    simp [h1, h2]

lemma card_fiber_eq (n : ℕ) (i : Fin n) (pr : Prefix C i.val × C) :
    (Finset.filter (fun cs : Fin n → C => extract_prefix cs i = pr.1 ∧ cs i = pr.2)
      Finset.univ).card = (Fintype.card C)^(n - 1 - i.val) := by
  have h_equiv := Fintype.card_congr (fiber_equiv i pr)
  have h_sub : (Finset.filter (fun cs : Fin n → C => extract_prefix cs i = pr.1 ∧ cs i = pr.2)
      Finset.univ).card
      = Fintype.card { cs : Fin n → C // extract_prefix cs i = pr.1 ∧ cs i = pr.2 } := by
    rw [Fintype.card_subtype]
  rw [h_sub, h_equiv]
  simp

/-- **The fiber decomposition.**  A tape event that reads only the prefix and slot `i` is counted
by the good `(prefix, slot)` pairs, each with `|C|^(n-1-i)` tapes above it. -/
lemma card_filter_prefix_r (n : ℕ) (i : Fin n) (P : Prefix C i.val → C → Prop) :
    (Finset.filter (fun cs : Fin n → C => P (extract_prefix cs i) (cs i)) Finset.univ).card =
    (Finset.filter (fun (pr : Prefix C i.val × C) => P pr.1 pr.2) Finset.univ).card *
      (Fintype.card C)^(n - 1 - i.val) := by
  have h_comp := card_filter_comp (fun cs : Fin n → C => (extract_prefix cs i, cs i))
    (fun (pr : Prefix C i.val × C) => P pr.1 pr.2)
  rw [h_comp]
  calc ∑ y ∈ Finset.filter (fun (pr : Prefix C i.val × C) => P pr.1 pr.2) Finset.univ,
        (Finset.filter (fun x : Fin n → C => (extract_prefix x i, x i) = y) Finset.univ).card
    _ = ∑ _y ∈ Finset.filter (fun (pr : Prefix C i.val × C) => P pr.1 pr.2) Finset.univ,
        (Fintype.card C)^(n - 1 - i.val) := by
      apply Finset.sum_congr rfl
      intro (pr : Prefix C i.val × C) _
      have h_eq : (Finset.filter (fun x : Fin n → C => (extract_prefix x i, x i) = pr)
            Finset.univ) =
          (Finset.filter (fun x : Fin n → C => extract_prefix x i = pr.1 ∧ x i = pr.2)
            Finset.univ) := by
        ext x
        simp [Prod.ext_iff]
      rw [h_eq]
      exact card_fiber_eq n i pr
    _ = (Finset.filter (fun (pr : Prefix C i.val × C) => P pr.1 pr.2) Finset.univ).card *
        (Fintype.card C)^(n - 1 - i.val) := by
      simp [Finset.sum_const]

end Fiber

/-! ## The grinding bounds -/

section Grinding

variable {C : Type*} [Fintype C] [DecidableEq C]

/--
**One slot.**  If, from every prefix, at most `beta` values of slot `i` are bad, then at most
`beta * |C|^(n-1)` of the `|C|^n` tapes are bad at slot `i`.

The `|C|^(n-1)` is exact bookkeeping and not slack: `|C|^i` prefixes times `beta` bad values
times `|C|^(n-1-i)` free tails.
-/
theorem slot_bad_card_le {n : ℕ} (i : Fin n) (beta : ℕ) (P : Prefix C i.val → C → Prop)
    (hlocal : ∀ pref : Prefix C i.val,
      (Finset.filter (fun c => P pref c) Finset.univ).card ≤ beta) :
    (Finset.filter (fun cs : Fin n → C => P (extract_prefix cs i) (cs i)) Finset.univ).card
      ≤ beta * (Fintype.card C) ^ (n - 1) := by
  rw [card_filter_prefix_r n i P]
  have hpairs : (Finset.filter (fun (pr : Prefix C i.val × C) => P pr.1 pr.2) Finset.univ).card
      ≤ (Fintype.card C) ^ i.val * beta := by
    have hfiber := card_prod_filter (fun (pref : Prefix C i.val) (c : C) => P pref c)
    calc (Finset.filter (fun (pr : Prefix C i.val × C) => P pr.1 pr.2) Finset.univ).card
        = ∑ pref : Prefix C i.val, (Finset.filter (fun c => P pref c) Finset.univ).card := hfiber
      _ ≤ ∑ _pref : Prefix C i.val, beta := Finset.sum_le_sum (fun pref _ => hlocal pref)
      _ = Fintype.card (Prefix C i.val) * beta := by simp [Finset.sum_const]
      _ = (Fintype.card C) ^ i.val * beta := by simp [Prefix]
  calc (Finset.filter (fun (pr : Prefix C i.val × C) => P pr.1 pr.2) Finset.univ).card *
        (Fintype.card C) ^ (n - 1 - i.val)
      ≤ ((Fintype.card C) ^ i.val * beta) * (Fintype.card C) ^ (n - 1 - i.val) := by gcongr
    _ = beta * ((Fintype.card C) ^ i.val * (Fintype.card C) ^ (n - 1 - i.val)) := by ring
    _ = beta * (Fintype.card C) ^ (i.val + (n - 1 - i.val)) := by rw [← pow_add]
    _ = beta * (Fintype.card C) ^ (n - 1) := by
        congr 2
        omega

/--
**Every slot, with a per-slot budget.**  `(∑ i, beta i) * |C|^(n-1)` tapes are bad somewhere.

Per-slot rather than uniform because the rounds of a real protocol have different densities: a
degree-2 sumcheck round costs `2`, a claim-combining challenge costs `1`, a Ligero query round
costs a hypergeometric cover count.  Taking the sum keeps each at its own value; the uniform
version below takes the max instead.
-/
theorem tape_bad_card_le {n : ℕ} (beta : Fin n → ℕ)
    (P : ∀ i : Fin n, Prefix C i.val → C → Prop)
    (hlocal : ∀ (i : Fin n) (pref : Prefix C i.val),
      (Finset.filter (fun c => P i pref c) Finset.univ).card ≤ beta i) :
    (Finset.filter (fun cs : Fin n → C =>
        ∃ i : Fin n, P i (extract_prefix cs i) (cs i)) Finset.univ).card
      ≤ (∑ i, beta i) * (Fintype.card C) ^ (n - 1) := by
  have h_union : Finset.filter (fun cs : Fin n → C =>
        ∃ i : Fin n, P i (extract_prefix cs i) (cs i)) Finset.univ
      = Finset.biUnion Finset.univ (fun i : Fin n =>
          Finset.filter (fun cs : Fin n → C => P i (extract_prefix cs i) (cs i)) Finset.univ) := by
    ext cs
    simp
  rw [h_union]
  calc (Finset.biUnion Finset.univ (fun i : Fin n =>
        Finset.filter (fun cs : Fin n → C => P i (extract_prefix cs i) (cs i))
          Finset.univ)).card
      ≤ ∑ i : Fin n, (Finset.filter (fun cs : Fin n → C =>
          P i (extract_prefix cs i) (cs i)) Finset.univ).card := Finset.card_biUnion_le
    _ ≤ ∑ i : Fin n, beta i * (Fintype.card C) ^ (n - 1) :=
        Finset.sum_le_sum (fun i _ => slot_bad_card_le i (beta i) (P i) (hlocal i))
    _ = (∑ i, beta i) * (Fintype.card C) ^ (n - 1) := by
        rw [Finset.sum_mul]

/-- **The uniform-budget corollary**: `n * beta * |C|^(n-1)`.  This is the shape a
round-by-round error takes, where `beta` is the maximum over rounds. -/
theorem tape_bad_card_le_const {n : ℕ} (beta : ℕ)
    (P : ∀ i : Fin n, Prefix C i.val → C → Prop)
    (hlocal : ∀ (i : Fin n) (pref : Prefix C i.val),
      (Finset.filter (fun c => P i pref c) Finset.univ).card ≤ beta) :
    (Finset.filter (fun cs : Fin n → C =>
        ∃ i : Fin n, P i (extract_prefix cs i) (cs i)) Finset.univ).card
      ≤ n * beta * (Fintype.card C) ^ (n - 1) := by
  have h := tape_bad_card_le (fun _ => beta) P (fun i pref => hlocal i pref)
  simpa [Finset.sum_const, mul_assoc] using h

end Grinding

end Sumcheck
