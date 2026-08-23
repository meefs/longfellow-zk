import Merkle.Commit

/-!
# The stored-label trapdoor

`openCore` produces an opening by *recomputing* the whole tree from a message and its nonces.  An
extractor cannot use it: it recovers only a partial tree from the commitment trace, and recomputing
would silently assume exactly the random-oracle preimages that extraction is supposed to establish.

A `Trapdoor` therefore stores the labels rather than deriving them, and `openFromTrapdoor` reads
the proof off storage.  `openFromTrapdoor_honest` says the two agree on honest input, so nothing
about completeness changes.

This is item 1 of `README.md`'s implementation order — the prerequisite for `Extraction.lean`, not
extraction itself.  The extractor still has to be written; see the status note at the end of this
file.
-/

open Finset Nat Heap

set_option autoImplicit false
set_option relaxedAutoImplicit false

namespace Merkle

namespace MH

universe uSalt uMsg uDigest uEnc

variable {Salt : Type uSalt} {M : Type uMsg} {D : Type uDigest} {Enc : Type uEnc}

/-- Everything needed to open any subset without consulting the oracle: the leaf nonces and every
heap label.  Note that `label` is total on `Heap.nodes n` — a partial extractor produces one of
these only after filling its gaps with explicit defaults. -/
structure Trapdoor (n : ℕ) (Salt : Type uSalt) (D : Type uDigest) where
  /-- Leaf nonces. -/
  nonce : Fin n → Salt
  /-- The stored label at each heap vertex. -/
  label : (v : ℕ) → v ∈ Heap.nodes n → D

/-- Read an opening off stored labels.  No hashing, so no oracle preimages are assumed. -/
def openFromTrapdoor {n : ℕ} (td : Trapdoor n Salt D) (I : Finset (Fin n)) :
    Opening n I Salt D where
  nonce i := td.nonce i.val
  frontierValue v := td.label v.val (Heap.mem_frontier_iff.mp v.property).2.1

/-- The honest trapdoor: the real nonces together with the real commitment labels. -/
def honestTrapdoor (S : Scheme Salt M D Enc) [Inhabited D] (n : ℕ)
    (nonce : Fin n → Salt) (m : Fin n → M) : Trapdoor n Salt D where
  nonce := nonce
  label v _ := commitLabels S n nonce m v

/-- **The trapdoor API agrees with the recomputing one on honest input.**

Definitional, which is the point: `openFromTrapdoor` is a strictly more general way of producing
the *same* openings, so replacing `openCore` by it costs nothing and buys the ability to open a
tree whose labels were extracted rather than computed. -/
@[simp] theorem openFromTrapdoor_honest (S : Scheme Salt M D Enc) [Inhabited D] (n : ℕ)
    (I : Finset (Fin n)) (nonce : Fin n → Salt) (m : Fin n → M) :
    openFromTrapdoor (honestTrapdoor S n nonce m) I = openCore S n I nonce m := rfl

/-- Honest openings produced through the trapdoor verify, since they *are* the honest openings. -/
theorem mh_trapdoor_completeness (S : Scheme Salt M D Enc) [Inhabited D] (n : ℕ)
    (I : Finset (Fin n)) (hI : I.Nonempty) (nonce : Fin n → Salt) (m : Fin n → M) :
    Accepts S n (root S n nonce m) I m
      (openFromTrapdoor (honestTrapdoor S n nonce m) I) := by
  rw [openFromTrapdoor_honest]
  exact mh_core_completeness S n I hI nonce m

/-- A trapdoor determines its openings: two trapdoors agreeing on the opened nonces and on the
frontier labels open identically.  This is the uniqueness half that
`mh_extract_explains_of_trace_subset` will need in order to conclude *literal* proof equality
rather than "some other accepting proof". -/
theorem openFromTrapdoor_congr {n : ℕ} (td td' : Trapdoor n Salt D) (I : Finset (Fin n))
    (hnonce : ∀ i ∈ I, td.nonce i = td'.nonce i)
    (hlabel : ∀ v, ∀ hv : v ∈ Heap.frontier n I,
      td.label v (Heap.mem_frontier_iff.mp hv).2.1
        = td'.label v (Heap.mem_frontier_iff.mp hv).2.1) :
    openFromTrapdoor td I = openFromTrapdoor td' I := by
  have hext : ∀ a b : Opening n I Salt D,
      a.nonce = b.nonce → a.frontierValue = b.frontierValue → a = b := by
    intro a b h1 h2
    cases a; cases b; simp_all
  refine hext _ _ ?_ ?_
  · funext i
    exact hnonce i.val i.property
  · funext v
    exact hlabel v.val v.property

/-! ## Status

What is here: the storage layer (item 1 of the README's implementation order).

What is not, and what `ExtractionROM.lean` still needs (the deterministic extraction theorems
`mh_extract_complete` and `mh_extract_explains_of_trace_subset` are done in `Extraction.lean`):

* trace-extension stability, for which `RandomOracle.Tree.run_congr_on_trace` is the primitive;
* the three-event failure cover, for which `RandomOracle.lazy_traceCollision_card_le` now supplies
  the commitment-collision term with the sharp `t(t-1)/2` constant;
* the multi-commitment version, which BCS needs and which nothing here addresses.
-/

end MH

end Merkle
