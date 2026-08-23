import Merkle.Collision
import Merkle.TreeCompose

/-!
# The verifier's reconstruction as a bounded adaptive execution

`checkValues` is a top-down recursion on the heap; the ROM binding game needs it as a
`RandomOracle.Tree`, so that the inputs it hashes occupy answer-tape slots exactly like the
adversary's own queries.  `checkPass` is that execution: it processes vertices `k, k-1, …, 1` in
descending order — children before parents, so one pass saturates — writing each vertex's value and
querying the oracle exactly where `checkValues` hashes.

`checkPass_run` is the simulation theorem, and it proves the two things the reduction needs at
once, from one induction:

* the pass computes `checkValues` at every vertex (`vals` correctness), and
* every input `checkValues` presents (`vertexQuery`) is recorded in the pass's trace.

The second is the point: `Collision.lean` extracts a collision consisting of two inputs the two
accepting checks *query*, and only a queried input has a slot.
-/

open Finset

set_option autoImplicit false
set_option relaxedAutoImplicit false

namespace Merkle

namespace MH

open RandomOracle

universe uSalt uMsg uDigest uEnc

variable {Salt : Type uSalt} {M : Type uMsg} {D : Type uDigest} {Enc : Type uEnc}

/-! ## Where the reconstruction does not hash -/

/-- The value the reconstruction assigns at a vertex it does not hash: a frontier digest comes
from the proof, everything off the tree is `default`. -/
def staticValue [Inhabited D] {n : ℕ} {I : Finset (Fin n)} (pf : Opening n I Salt D)
    (w : ℕ) : D :=
  if hfront : w ∈ Heap.frontier n I then pf.frontierValue ⟨w, hfront⟩ else default

variable (S : Scheme Salt M D Enc) [Inhabited D]

/-- The reconstruction hashes the leaf encoding at an opened leaf, stated at the vertex rather than
at `n + i`. -/
theorem checkValues_leaf_range (n : ℕ) (I : Finset (Fin n))
    (a : Fin n → M) (pf : Opening n I Salt D) (w : ℕ) (hleaf : n ≤ w ∧ w < 2 * n)
    (hi : (⟨w - n, by omega⟩ : Fin n) ∈ I) :
    checkValues S n I a pf w =
      S.H (S.leafEnc (pf.nonce ⟨_, hi⟩, a ⟨w - n, by omega⟩)) := by
  rw [checkValues]
  simp [hleaf, hi]

theorem checkValues_eq_staticValue_of_leaf_not_mem (n : ℕ) (I : Finset (Fin n))
    (a : Fin n → M) (pf : Opening n I Salt D) (w : ℕ) (hleaf : n ≤ w ∧ w < 2 * n)
    (hi : (⟨w - n, by omega⟩ : Fin n) ∉ I) :
    checkValues S n I a pf w = staticValue pf w := by
  rw [checkValues, staticValue]
  simp [hleaf, hi]

theorem checkValues_eq_staticValue_of_not_path (n : ℕ) (I : Finset (Fin n))
    (a : Fin n → M) (pf : Opening n I Salt D) (w : ℕ)
    (hnleaf : ¬(n ≤ w ∧ w < 2 * n))
    (hnpath : ¬(0 < w ∧ w < n ∧ w ∈ Heap.pathSet n I)) :
    checkValues S n I a pf w = staticValue pf w := by
  rw [checkValues, staticValue]
  simp [hnleaf, hnpath]

/-- Outside the heap the reconstruction is `default`, which is what makes the constant initial
state of `checkPass` a correct starting point. -/
theorem checkValues_of_ge (n : ℕ) (I : Finset (Fin n)) (a : Fin n → M)
    (pf : Opening n I Salt D) (w : ℕ) (hw : 2 * n ≤ w) :
    checkValues S n I a pf w = default := by
  have hnf : w ∉ Heap.frontier n I := by
    intro hmem
    have hnodes := (Heap.mem_frontier_iff.mp hmem).2.1
    rw [Heap.mem_nodes] at hnodes
    omega
  rw [checkValues_eq_staticValue_of_not_path S n I a pf w (by omega) (by omega), staticValue]
  simp [hnf]

/-! ## The inputs the reconstruction presents -/

/-- The oracle input the reconstruction hashes at vertex `w`, if any: the leaf encoding at an
opened leaf, the node encoding at an internal path vertex, nothing elsewhere. The branch structure
is `checkValues`'s own. -/
def vertexQuery (n : ℕ) (I : Finset (Fin n)) (a : Fin n → M)
    (pf : Opening n I Salt D) (w : ℕ) : Option Enc :=
  if hleaf : n ≤ w ∧ w < 2 * n then
    if hi : (⟨w - n, by omega⟩ : Fin n) ∈ I then
      some (S.leafEnc (pf.nonce ⟨_, hi⟩, a ⟨w - n, by omega⟩))
    else none
  else if 0 < w ∧ w < n ∧ w ∈ Heap.pathSet n I then
    some (S.nodeEnc
      (checkValues S n I a pf (2 * w), checkValues S n I a pf (2 * w + 1)))
  else none

theorem vertexQuery_eq_none_of_leaf_not_mem (n : ℕ) (I : Finset (Fin n))
    (a : Fin n → M) (pf : Opening n I Salt D) (w : ℕ) (hleaf : n ≤ w ∧ w < 2 * n)
    (hi : (⟨w - n, by omega⟩ : Fin n) ∉ I) :
    vertexQuery S n I a pf w = none := by
  rw [vertexQuery]
  simp [hleaf, hi]

theorem vertexQuery_eq_none_of_not_path (n : ℕ) (I : Finset (Fin n))
    (a : Fin n → M) (pf : Opening n I Salt D) (w : ℕ)
    (hnleaf : ¬(n ≤ w ∧ w < 2 * n))
    (hnpath : ¬(0 < w ∧ w < n ∧ w ∈ Heap.pathSet n I)) :
    vertexQuery S n I a pf w = none := by
  rw [vertexQuery]
  simp [hnleaf, hnpath]

/-- The input presented at an opened leaf. -/
theorem vertexQuery_leaf_pos (n : ℕ) (I : Finset (Fin n)) (a : Fin n → M)
    (pf : Opening n I Salt D) (i : Fin n) (hi : i ∈ I) :
    vertexQuery S n I a pf (n + i.val) = some (S.leafEnc (pf.nonce ⟨i, hi⟩, a i)) := by
  have hlt := i.isLt
  have hleaf : n ≤ n + i.val ∧ n + i.val < 2 * n := by omega
  have hival : (⟨n + i.val - n, by omega⟩ : Fin n) = i :=
    Fin.ext (by show n + i.val - n = i.val; omega)
  have hi' : (⟨n + i.val - n, by omega⟩ : Fin n) ∈ I := by rw [hival]; exact hi
  rw [vertexQuery, dif_pos hleaf, dif_pos hi']
  exact congrArg some (congrArg S.leafEnc
    (Prod.ext (congrArg pf.nonce (Subtype.ext hival)) (congrArg a hival)))

/-- The input presented at an internal path vertex. -/
theorem vertexQuery_node (n : ℕ) (I : Finset (Fin n)) (a : Fin n → M)
    (pf : Opening n I Salt D) (v : ℕ) (hv : 0 < v ∧ v < n ∧ v ∈ Heap.pathSet n I) :
    vertexQuery S n I a pf v =
      some (S.nodeEnc (checkValues S n I a pf (2 * v), checkValues S n I a pf (2 * v + 1))) := by
  rw [vertexQuery]
  have hnleaf : ¬(n ≤ v ∧ v < 2 * n) := by omega
  simp [hnleaf, hv]

/-- The reconstruction's answer at a vertex is its value there.  This is what turns "a fresh query
was made" into "a fresh slot carries this value". -/
theorem vertexQuery_answer (n : ℕ) (I : Finset (Fin n)) (a : Fin n → M)
    (pf : Opening n I Salt D) (w : ℕ) (x : Enc)
    (h : vertexQuery S n I a pf w = some x) :
    S.H x = checkValues S n I a pf w := by
  rw [vertexQuery] at h
  split at h
  · rename_i hleaf
    split at h
    · rename_i hi
      rw [← Option.some_inj.mp h, checkValues_leaf_range S n I a pf w hleaf hi]
    · exact absurd h (by simp)
  · split at h
    · rename_i hpath
      rw [← Option.some_inj.mp h, checkValues_node S n I a pf w hpath]
    · exact absurd h (by simp)

/-- A vertex that presents an input lies on an opened path. -/
theorem mem_pathSet_of_vertexQuery (n : ℕ) (I : Finset (Fin n)) (a : Fin n → M)
    (pf : Opening n I Salt D) (w : ℕ) (x : Enc)
    (h : vertexQuery S n I a pf w = some x) :
    w ∈ Heap.pathSet n I := by
  rw [vertexQuery] at h
  split at h
  · rename_i hleaf
    split at h
    · rename_i hi
      refine Heap.mem_pathSet.mpr ⟨⟨w - n, by omega⟩, hi, ?_⟩
      have hmem := Heap.leaf_mem_pathOf n (⟨w - n, by omega⟩ : Fin n)
      rwa [show n + (⟨w - n, by omega⟩ : Fin n).val = w by
        show n + (w - n) = w; omega] at hmem
    · exact absurd h (by simp)
  · split at h
    · rename_i hpath
      exact hpath.2.2
    · exact absurd h (by simp)

/-- Every input `InIndexTrace` can present at an opened index is presented at a vertex of that
index's path. -/
theorem vertexQuery_of_inIndexTrace (n : ℕ) (I : Finset (Fin n)) (a : Fin n → M)
    (pf : Opening n I Salt D) (i : Fin n) (hi : i ∈ I) (x : Enc) (y : D)
    (hxy : InIndexTrace S n I a pf i hi x y) :
    ∃ w, 0 < w ∧ w < 2 * n ∧ vertexQuery S n I a pf w = some x := by
  rcases hxy with ⟨rfl, -⟩ | ⟨v, hvpath, hvlt, rfl, -⟩
  · have hlt := i.isLt
    exact ⟨n + i.val, by omega, by omega, vertexQuery_leaf_pos S n I a pf i hi⟩
  · have hvpos : 0 < v := (Heap.mem_pathOf.mp hvpath).1
    exact ⟨v, hvpos, by omega, vertexQuery_node S n I a pf v
      ⟨hvpos, hvlt, Heap.mem_pathSet.mpr ⟨i, hi, hvpath⟩⟩⟩


/-! ## The pass -/

variable {S}

/-- **The reconstruction as a bounded execution.**  `checkPass C n I a pf k vals` processes vertices
`k, k-1, …, 1`, in that order, and makes at most one oracle query per vertex — so `k = 2*n`
suffices for the whole heap. -/
def checkPass [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ) (I : Finset (Fin n))
    (a : Fin n → M) (pf : Opening n I Salt D) :
    (k : ℕ) → (ℕ → D) → Tree Enc D (ℕ → D) k
  | 0, vals => .done vals
  | k + 1, vals =>
      if hleaf : n ≤ k + 1 ∧ k + 1 < 2 * n then
        if hi : (⟨k + 1 - n, by omega⟩ : Fin n) ∈ I then
          .query (C.leafEnc (pf.nonce ⟨_, hi⟩, a ⟨k + 1 - n, by omega⟩))
            fun y => checkPass C n I a pf k (Function.update vals (k + 1) y)
        else
          (checkPass C n I a pf k
            (Function.update vals (k + 1) (staticValue pf (k + 1)))).weaken
      else if 0 < k + 1 ∧ k + 1 < n ∧ k + 1 ∈ Heap.pathSet n I then
        .query (C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1)))
          fun y => checkPass C n I a pf k (Function.update vals (k + 1) y)
      else
        (checkPass C n I a pf k
          (Function.update vals (k + 1) (staticValue pf (k + 1)))).weaken

/-- **The reconstruction queries only where it hashes.**  Its trace is as long as the opened path set
truncated at `k` — not as long as its fuel.  A pruned opening of `q` indices hashes at most
`q·(heapDepth n + 1)` vertices, which is what lets the binding numerator charge paths rather than the
whole tree. -/
theorem checkPass_trace_length_le [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ)
    (I : Finset (Fin n)) (a : Fin n → M) (pf : Opening n I Salt D) (H : Enc → D) :
    ∀ (k : ℕ) (vals : ℕ → D),
      (((checkPass C n I a pf k vals).run H).2).length ≤
        ((Heap.pathSet n I).filter (fun v => v ≤ k)).card := by
  intro k
  induction k with
  | zero => intro vals; simp [checkPass]
  | succ k ih =>
    intro vals
    have hsub : ((Heap.pathSet n I).filter (fun v => v ≤ k)) ⊆
        ((Heap.pathSet n I).filter (fun v => v ≤ k + 1)) := by
      intro v hv
      rw [Finset.mem_filter] at hv ⊢
      exact ⟨hv.1, by omega⟩
    have hstep : k + 1 ∈ Heap.pathSet n I →
        ((Heap.pathSet n I).filter (fun v => v ≤ k)).card + 1 ≤
          ((Heap.pathSet n I).filter (fun v => v ≤ k + 1)).card := by
      intro hmem
      have hnot : (k + 1) ∉ ((Heap.pathSet n I).filter (fun v => v ≤ k)) := by
        intro hc
        have := (Finset.mem_filter.mp hc).2
        omega
      calc ((Heap.pathSet n I).filter (fun v => v ≤ k)).card + 1
          = (insert (k + 1) ((Heap.pathSet n I).filter (fun v => v ≤ k))).card :=
            (Finset.card_insert_of_notMem hnot).symm
        _ ≤ _ := by
            refine Finset.card_le_card ?_
            intro v hv
            rcases Finset.mem_insert.mp hv with rfl | hv
            · exact Finset.mem_filter.mpr ⟨hmem, le_refl _⟩
            · exact hsub hv
    rw [checkPass]
    split
    · rename_i hleaf
      split
      · rename_i hi
        have hmem : k + 1 ∈ Heap.pathSet n I := by
          refine Heap.mem_pathSet.mpr ⟨⟨k + 1 - n, by omega⟩, hi, ?_⟩
          refine Heap.mem_pathOf.mpr ⟨by omega, 0, ?_⟩
          show k + 1 = (n + (k + 1 - n)) / 2 ^ 0
          simp
          omega
        rw [Tree.run_query]
        simp only [List.length_cons]
        exact le_trans (Nat.succ_le_succ (ih _)) (hstep hmem)
      · rw [Tree.run_weaken]
        exact le_trans (ih _) (Finset.card_le_card hsub)
    · split
      · rename_i hint
        rw [Tree.run_query]
        simp only [List.length_cons]
        exact le_trans (Nat.succ_le_succ (ih _)) (hstep hint.2.2)
      · rw [Tree.run_weaken]
        exact le_trans (ih _) (Finset.card_le_card hsub)

/-- **Simulation.**  Against any total oracle the pass computes `checkValues`, and its trace
records every input `checkValues` presents at a processed vertex.

Both halves come from one induction because they need the same per-vertex fact — that the value
written at `k+1` is `checkValues` there — and the descending order makes the children's values
already correct when the parent is hashed. -/
theorem checkPass_run [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ) (I : Finset (Fin n))
    (a : Fin n → M) (pf : Opening n I Salt D) (H : Enc → D) :
    ∀ (k : ℕ) (vals : ℕ → D),
      (∀ v, k < v → vals v = checkValues (C.withOracle H) n I a pf v) →
      (∀ v, 0 < v → ((checkPass C n I a pf k vals).run H).1 v =
          checkValues (C.withOracle H) n I a pf v) ∧
      (∀ w x, 0 < w → w ≤ k →
          vertexQuery (C.withOracle H) n I a pf w = some x →
          ∃ y, (x, y) ∈ ((checkPass C n I a pf k vals).run H).2) := by
  intro k
  induction k with
  | zero =>
    intro vals hinv
    refine ⟨fun v hv => ?_, fun w x hw hwk _ => absurd hwk (by omega)⟩
    show vals v = _
    exact hinv v hv
  | succ k ih =>
    intro vals hinv
    -- the value the step writes at `k+1`, in each of the three branches
    by_cases hleaf : n ≤ k + 1 ∧ k + 1 < 2 * n
    · by_cases hi : (⟨k + 1 - n, by omega⟩ : Fin n) ∈ I
      · -- opened leaf: the step queries the leaf encoding
        have hstep : checkPass C n I a pf (k + 1) vals =
            .query (C.leafEnc (pf.nonce ⟨_, hi⟩, a ⟨k + 1 - n, by omega⟩))
              (fun y => checkPass C n I a pf k (Function.update vals (k + 1) y)) := by
          rw [checkPass]
          simp only [dif_pos hleaf, dif_pos hi]
        set x : Enc := C.leafEnc (pf.nonce ⟨_, hi⟩, a ⟨k + 1 - n, by omega⟩) with hxdef
        have hik : n + (⟨k + 1 - n, by omega⟩ : Fin n).val = k + 1 := by
          simp only []
          omega
        have hcv : checkValues (C.withOracle H) n I a pf (k + 1) = H x := by
          rw [← hik, checkValues_leaf (C.withOracle H) n I a pf ⟨k + 1 - n, by omega⟩ hi, hxdef]
          rfl
        have hinv' : ∀ v, k < v →
            Function.update vals (k + 1) (H x) v =
              checkValues (C.withOracle H) n I a pf v := by
          intro v hv
          rw [Function.update_apply]
          split_ifs with hveq
          · rw [hveq, hcv]
          · exact hinv v (by omega)
        obtain ⟨ihvals, ihtrace⟩ := ih (Function.update vals (k + 1) (H x)) hinv'
        constructor
        · intro v hv
          rw [hstep, Tree.run_query]
          exact ihvals v hv
        · intro w x' hw hwk hq
          rw [hstep, Tree.run_query]
          by_cases hweq : w = k + 1
          · refine ⟨H x, ?_⟩
            have : x' = x := by
              rw [hweq] at hq
              rw [vertexQuery, dif_pos hleaf, dif_pos hi] at hq
              exact (Option.some_inj.mp hq).symm
            rw [this]
            simp
          · obtain ⟨y, hy⟩ := ihtrace w x' hw (by omega) hq
            exact ⟨y, by simp [hy]⟩
      · -- unopened leaf: no query
        have hstep : checkPass C n I a pf (k + 1) vals =
            (checkPass C n I a pf k
              (Function.update vals (k + 1) (staticValue pf (k + 1)))).weaken := by
          rw [checkPass]
          simp only [dif_pos hleaf, dif_neg hi]
        have hcv : checkValues (C.withOracle H) n I a pf (k + 1) =
            staticValue pf (k + 1) :=
          checkValues_eq_staticValue_of_leaf_not_mem (C.withOracle H) n I a pf (k + 1) hleaf hi
        have hinv' : ∀ v, k < v →
            Function.update vals (k + 1) (staticValue pf (k + 1)) v =
              checkValues (C.withOracle H) n I a pf v := by
          intro v hv
          rw [Function.update_apply]
          split_ifs with hveq
          · rw [hveq, hcv]
          · exact hinv v (by omega)
        obtain ⟨ihvals, ihtrace⟩ :=
          ih (Function.update vals (k + 1) (staticValue pf (k + 1))) hinv'
        constructor
        · intro v hv
          rw [hstep, Tree.run_weaken]
          exact ihvals v hv
        · intro w x' hw hwk hq
          rw [hstep, Tree.run_weaken]
          by_cases hweq : w = k + 1
          · rw [hweq, vertexQuery_eq_none_of_leaf_not_mem (C.withOracle H) n I a pf (k + 1)
              hleaf hi] at hq
            exact absurd hq (by simp)
          · exact ihtrace w x' hw (by omega) hq
    · by_cases hpath : 0 < k + 1 ∧ k + 1 < n ∧ k + 1 ∈ Heap.pathSet n I
      · -- internal path vertex: the step queries the node encoding
        have hchild₀ : vals (2 * (k + 1)) =
            checkValues (C.withOracle H) n I a pf (2 * (k + 1)) := hinv _ (by omega)
        have hchild₁ : vals (2 * (k + 1) + 1) =
            checkValues (C.withOracle H) n I a pf (2 * (k + 1) + 1) := hinv _ (by omega)
        have hstep : checkPass C n I a pf (k + 1) vals =
            .query (C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1)))
              (fun y => checkPass C n I a pf k (Function.update vals (k + 1) y)) := by
          rw [checkPass]
          simp only [dif_neg hleaf, if_pos hpath]
        set x : Enc := C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1)) with hxdef
        have hcv : checkValues (C.withOracle H) n I a pf (k + 1) = H x := by
          rw [checkValues_node (C.withOracle H) n I a pf (k + 1) hpath, hxdef, hchild₀, hchild₁]
          rfl
        have hinv' : ∀ v, k < v →
            Function.update vals (k + 1) (H x) v =
              checkValues (C.withOracle H) n I a pf v := by
          intro v hv
          rw [Function.update_apply]
          split_ifs with hveq
          · rw [hveq, hcv]
          · exact hinv v (by omega)
        obtain ⟨ihvals, ihtrace⟩ := ih (Function.update vals (k + 1) (H x)) hinv'
        constructor
        · intro v hv
          rw [hstep, Tree.run_query]
          exact ihvals v hv
        · intro w x' hw hwk hq
          rw [hstep, Tree.run_query]
          by_cases hweq : w = k + 1
          · refine ⟨H x, ?_⟩
            have hx' : x' = x := by
              rw [hweq] at hq
              rw [vertexQuery, dif_neg hleaf, if_pos hpath] at hq
              rw [hxdef, hchild₀, hchild₁]
              exact (Option.some_inj.mp hq).symm
            rw [hx']
            simp
          · obtain ⟨y, hy⟩ := ihtrace w x' hw (by omega) hq
            exact ⟨y, by simp [hy]⟩
      · -- neither: no query
        have hstep : checkPass C n I a pf (k + 1) vals =
            (checkPass C n I a pf k
              (Function.update vals (k + 1) (staticValue pf (k + 1)))).weaken := by
          rw [checkPass]
          simp only [dif_neg hleaf, if_neg hpath]
        have hcv : checkValues (C.withOracle H) n I a pf (k + 1) =
            staticValue pf (k + 1) :=
          checkValues_eq_staticValue_of_not_path (C.withOracle H) n I a pf (k + 1) hleaf hpath
        have hinv' : ∀ v, k < v →
            Function.update vals (k + 1) (staticValue pf (k + 1)) v =
              checkValues (C.withOracle H) n I a pf v := by
          intro v hv
          rw [Function.update_apply]
          split_ifs with hveq
          · rw [hveq, hcv]
          · exact hinv v (by omega)
        obtain ⟨ihvals, ihtrace⟩ :=
          ih (Function.update vals (k + 1) (staticValue pf (k + 1))) hinv'
        constructor
        · intro v hv
          rw [hstep, Tree.run_weaken]
          exact ihvals v hv
        · intro w x' hw hwk hq
          rw [hstep, Tree.run_weaken]
          by_cases hweq : w = k + 1
          · rw [hweq, vertexQuery_eq_none_of_not_path (C.withOracle H) n I a pf (k + 1)
              hleaf hpath] at hq
            exact absurd hq (by simp)
          · exact ihtrace w x' hw (by omega) hq

/-- Run the pass over the whole heap from the constant state: every input the reconstruction
presents at a heap vertex is in its trace. -/
theorem mem_checkPass_trace_of_vertexQuery [DecidableEq Enc] (C : Codec Salt M D Enc)
    (n : ℕ) (I : Finset (Fin n)) (a : Fin n → M) (pf : Opening n I Salt D) (H : Enc → D)
    (w : ℕ) (x : Enc) (hw : 0 < w) (hwn : w < 2 * n)
    (hq : vertexQuery (C.withOracle H) n I a pf w = some x) :
    ∃ y, (x, y) ∈ ((checkPass C n I a pf (2 * n) (fun _ => default)).run H).2 := by
  have hinit : ∀ v, 2 * n < v →
      (fun _ => (default : D)) v = checkValues (C.withOracle H) n I a pf v := by
    intro v hv
    exact (checkValues_of_ge (C.withOracle H) n I a pf v (by omega)).symm
  exact (checkPass_run C n I a pf H (2 * n) (fun _ => default) hinit).2 w x hw
    (by omega) hq

/-- The corollary the reduction uses: every input the reconstruction presents at an opened index is
in its trace. -/
theorem mem_checkPass_trace_of_inIndexTrace [DecidableEq Enc] (C : Codec Salt M D Enc)
    (n : ℕ) (I : Finset (Fin n)) (a : Fin n → M) (pf : Opening n I Salt D) (H : Enc → D)
    (i : Fin n) (hi : i ∈ I) (x : Enc) (y : D)
    (hxy : InIndexTrace (C.withOracle H) n I a pf i hi x y) :
    ∃ y', (x, y') ∈
      ((checkPass C n I a pf (2 * n) (fun _ => default)).run H).2 := by
  obtain ⟨w, hwpos, hwlt, hq⟩ :=
    vertexQuery_of_inIndexTrace (C.withOracle H) n I a pf i hi x y hxy
  exact mem_checkPass_trace_of_vertexQuery C n I a pf H w x hwpos hwlt hq

/-! ## The honest commitment as a bounded execution

Root hiding needs the *committer* inside the lazy execution too, and it needs it to run **first** —
which is also the real protocol order, since the distinguisher receives the root before it queries.
Running first is what makes the commitment's slot indices deterministic: from an empty seen-list its
`j`-th distinct query is slot `j`, with no dependence on how many distinct queries anyone else makes.

`commitPass` is that execution.  It is `checkPass`'s simpler sibling: no opening, no frontier, no
path set — just `commitLabels`'s own two cases. -/

/-- `commitLabels` is `default` off the heap. -/
theorem commitLabels_of_ge (n : ℕ) (nonce : Fin n → Salt) (m : Fin n → M) (v : ℕ)
    (hv : 2 * n ≤ v) :
    commitLabels S n nonce m v = default := by
  rw [commitLabels]
  simp [show ¬(n ≤ v ∧ v < 2 * n) by omega, show ¬(0 < v ∧ v < n) by omega]

/-- **The honest commitment as a bounded execution.**  Processes heap vertices in descending order —
children before parents — hashing a leaf encoding at every leaf and a node encoding at every
internal vertex, which is exactly `commitLabels`'s recurrence. -/
def commitPass [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ) (nonce : Fin n → Salt)
    (m : Fin n → M) :
    (k : ℕ) → (ℕ → D) → Tree Enc D (ℕ → D) k
  | 0, vals => .done vals
  | k + 1, vals =>
      if hleaf : n ≤ k + 1 ∧ k + 1 < 2 * n then
        .query (C.leafEnc (nonce ⟨k + 1 - n, by omega⟩, m ⟨k + 1 - n, by omega⟩))
          fun y => commitPass C n nonce m k (Function.update vals (k + 1) y)
      else if hint : 0 < k + 1 ∧ k + 1 < n then
        .query (C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1)))
          fun y => commitPass C n nonce m k (Function.update vals (k + 1) y)
      else
        (commitPass C n nonce m k (Function.update vals (k + 1) default)).weaken

/-- **Simulation.**  Against any oracle the pass computes `commitLabels`. -/
theorem commitPass_run [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ) (nonce : Fin n → Salt)
    (m : Fin n → M) (H : Enc → D) :
    ∀ (k : ℕ) (vals : ℕ → D),
      (∀ v, k < v → vals v = commitLabels (C.withOracle H) n nonce m v) →
      ∀ v, 0 < v → ((commitPass C n nonce m k vals).run H).1 v =
        commitLabels (C.withOracle H) n nonce m v := by
  intro k
  induction k with
  | zero =>
    intro vals hinv v hv
    show vals v = _
    exact hinv v hv
  | succ k ih =>
    intro vals hinv
    by_cases hleaf : n ≤ k + 1 ∧ k + 1 < 2 * n
    · have hstep : commitPass C n nonce m (k + 1) vals =
          .query (C.leafEnc (nonce ⟨k + 1 - n, by omega⟩, m ⟨k + 1 - n, by omega⟩))
            (fun y => commitPass C n nonce m k (Function.update vals (k + 1) y)) := by
        rw [commitPass]
        simp only [dif_pos hleaf]
      set x : Enc := C.leafEnc (nonce ⟨k + 1 - n, by omega⟩, m ⟨k + 1 - n, by omega⟩) with hxdef
      have hcv : commitLabels (C.withOracle H) n nonce m (k + 1) = H x := by
        rw [commitLabels_leaf (C.withOracle H) n nonce m (k + 1) hleaf, hxdef]
        rfl
      have hinv' : ∀ v, k < v →
          Function.update vals (k + 1) (H x) v =
            commitLabels (C.withOracle H) n nonce m v := by
        intro v hv
        rw [Function.update_apply]
        split_ifs with hveq
        · rw [hveq, hcv]
        · exact hinv v (by omega)
      intro v hv
      rw [hstep, Tree.run_query]
      exact ih (Function.update vals (k + 1) (H x)) hinv' v hv
    · by_cases hint : 0 < k + 1 ∧ k + 1 < n
      · have hchild₀ : vals (2 * (k + 1)) =
            commitLabels (C.withOracle H) n nonce m (2 * (k + 1)) := hinv _ (by omega)
        have hchild₁ : vals (2 * (k + 1) + 1) =
            commitLabels (C.withOracle H) n nonce m (2 * (k + 1) + 1) := hinv _ (by omega)
        have hstep : commitPass C n nonce m (k + 1) vals =
            .query (C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1)))
              (fun y => commitPass C n nonce m k (Function.update vals (k + 1) y)) := by
          rw [commitPass]
          simp only [dif_neg hleaf, dif_pos hint]
        set x : Enc := C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1)) with hxdef
        have hcv : commitLabels (C.withOracle H) n nonce m (k + 1) = H x := by
          rw [commitLabels_node (C.withOracle H) n nonce m (k + 1) hint, hxdef, hchild₀, hchild₁]
          rfl
        have hinv' : ∀ v, k < v →
            Function.update vals (k + 1) (H x) v =
              commitLabels (C.withOracle H) n nonce m v := by
          intro v hv
          rw [Function.update_apply]
          split_ifs with hveq
          · rw [hveq, hcv]
          · exact hinv v (by omega)
        intro v hv
        rw [hstep, Tree.run_query]
        exact ih (Function.update vals (k + 1) (H x)) hinv' v hv
      · have hstep : commitPass C n nonce m (k + 1) vals =
            (commitPass C n nonce m k (Function.update vals (k + 1) default)).weaken := by
          rw [commitPass]
          simp only [dif_neg hleaf, dif_neg hint]
        have hcv : commitLabels (C.withOracle H) n nonce m (k + 1) = default := by
          rw [commitLabels, dif_neg hleaf, dif_neg hint]
        have hinv' : ∀ v, k < v →
            Function.update vals (k + 1) default v =
              commitLabels (C.withOracle H) n nonce m v := by
          intro v hv
          rw [Function.update_apply]
          split_ifs with hveq
          · rw [hveq, hcv]
          · exact hinv v (by omega)
        intro v hv
        rw [hstep, Tree.run_weaken]
        exact ih (Function.update vals (k + 1) default) hinv' v hv

/-- The commitment pass over the whole heap computes the honest root. -/
theorem commitPass_root [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ) (hn : 0 < n)
    (nonce : Fin n → Salt) (m : Fin n → M) (H : Enc → D) :
    ((commitPass C n nonce m (2 * n - 1) fun _ => default).run H).1 1 =
      root (C.withOracle H) n nonce m := by
  refine commitPass_run C n nonce m H (2 * n - 1) (fun _ => default) (fun v hv => ?_) 1 (by omega)
  exact (commitLabels_of_ge (S := C.withOracle H) n nonce m v (by omega)).symm


/-- Every heap vertex in `[1, 2n-1]` makes exactly one query, so a pass over `k ≤ 2n-1` of them
records exactly `k`.  Vertex `2n` is the only one in range that hashes nothing. -/
theorem commitPass_trace_length [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ) (hn : 0 < n)
    (nonce : Fin n → Salt) (m : Fin n → M) (H : Enc → D) :
    ∀ (k : ℕ) (vals : ℕ → D), k ≤ 2 * n - 1 →
      ((commitPass C n nonce m k vals).run H).2.length = k := by
  intro k
  induction k with
  | zero => intro vals _; rfl
  | succ k ih =>
    intro vals hk
    by_cases hleaf : n ≤ k + 1 ∧ k + 1 < 2 * n
    · have hstep : commitPass C n nonce m (k + 1) vals =
          .query (C.leafEnc (nonce ⟨k + 1 - n, by omega⟩, m ⟨k + 1 - n, by omega⟩))
            (fun y => commitPass C n nonce m k (Function.update vals (k + 1) y)) := by
        rw [commitPass]; simp only [dif_pos hleaf]
      rw [hstep, Tree.run_query]
      simp only [List.length_cons]
      rw [ih _ (by omega)]
    · have hint : 0 < k + 1 ∧ k + 1 < n := by omega
      have hstep : commitPass C n nonce m (k + 1) vals =
          .query (C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1)))
            (fun y => commitPass C n nonce m k (Function.update vals (k + 1) y)) := by
        rw [commitPass]; simp only [dif_neg hleaf, dif_pos hint]
      rw [hstep, Tree.run_query]
      simp only [List.length_cons]
      rw [ih _ (by omega)]

/-- **The last query is the root's.**  The pass runs downwards, so vertex `1` is hashed last, and
its answer is the commitment's root. -/
theorem commitPass_trace_getLast [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ) (hn : 0 < n)
    (nonce : Fin n → Salt) (m : Fin n → M) (H : Enc → D) :
    ∀ (k : ℕ) (vals : ℕ → D), 1 ≤ k → k ≤ 2 * n - 1 →
      (∀ v, k < v → vals v = commitLabels (C.withOracle H) n nonce m v) →
      (((commitPass C n nonce m k vals).run H).2).getLast?.map Prod.snd =
        some (commitLabels (C.withOracle H) n nonce m 1) := by
  intro k
  induction k with
  | zero => intro _ h _ _; exact absurd h (by omega)
  | succ k ih =>
    intro vals _ hk hinv
    -- the value written at vertex `k+1`, in either query branch
    by_cases hleaf : n ≤ k + 1 ∧ k + 1 < 2 * n
    · have hstep : commitPass C n nonce m (k + 1) vals =
          .query (C.leafEnc (nonce ⟨k + 1 - n, by omega⟩, m ⟨k + 1 - n, by omega⟩))
            (fun y => commitPass C n nonce m k (Function.update vals (k + 1) y)) := by
        rw [commitPass]; simp only [dif_pos hleaf]
      set x : Enc := C.leafEnc (nonce ⟨k + 1 - n, by omega⟩, m ⟨k + 1 - n, by omega⟩) with hxdef
      have hcv : commitLabels (C.withOracle H) n nonce m (k + 1) = H x := by
        rw [commitLabels_leaf (C.withOracle H) n nonce m (k + 1) hleaf, hxdef]; rfl
      have hinv' : ∀ v, k < v →
          Function.update vals (k + 1) (H x) v = commitLabels (C.withOracle H) n nonce m v := by
        intro v hv
        rw [Function.update_apply]
        split_ifs with hveq
        · rw [hveq, hcv]
        · exact hinv v (by omega)
      rw [hstep, Tree.run_query]
      rcases Nat.eq_or_lt_of_le (show 1 ≤ k + 1 by omega) with hk1 | hk1
      · -- `k = 0`: this is vertex 1 itself, and the trace is a singleton
        have hk0 : k = 0 := by omega
        subst hk0
        simp only [commitPass, Tree.run_done]
        simpa using hcv.symm
      · have hne : ((commitPass C n nonce m k
            (Function.update vals (k + 1) (H x))).run H).2 ≠ [] := by
          intro hnil
          have := commitPass_trace_length C n hn nonce m H k
            (Function.update vals (k + 1) (H x)) (by omega)
          rw [hnil] at this
          simp at this
          omega
        rw [List.getLast?_cons_of_ne_nil hne]
        exact ih _ (by omega) (by omega) hinv'
    · have hint : 0 < k + 1 ∧ k + 1 < n := by omega
      have hstep : commitPass C n nonce m (k + 1) vals =
          .query (C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1)))
            (fun y => commitPass C n nonce m k (Function.update vals (k + 1) y)) := by
        rw [commitPass]; simp only [dif_neg hleaf, dif_pos hint]
      set x : Enc := C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1)) with hxdef
      have hcv : commitLabels (C.withOracle H) n nonce m (k + 1) = H x := by
        rw [commitLabels_node (C.withOracle H) n nonce m (k + 1) hint, hxdef,
          hinv _ (by omega), hinv _ (by omega)]
        rfl
      have hinv' : ∀ v, k < v →
          Function.update vals (k + 1) (H x) v = commitLabels (C.withOracle H) n nonce m v := by
        intro v hv
        rw [Function.update_apply]
        split_ifs with hveq
        · rw [hveq, hcv]
        · exact hinv v (by omega)
      rw [hstep, Tree.run_query]
      rcases Nat.eq_or_lt_of_le (show 1 ≤ k + 1 by omega) with hk1 | hk1
      · have hk0 : k = 0 := by omega
        subst hk0
        simp only [commitPass, Tree.run_done]
        simpa using hcv.symm
      · have hne : ((commitPass C n nonce m k
            (Function.update vals (k + 1) (H x))).run H).2 ≠ [] := by
          intro hnil
          have := commitPass_trace_length C n hn nonce m H k
            (Function.update vals (k + 1) (H x)) (by omega)
          rw [hnil] at this
          simp at this
          omega
        rw [List.getLast?_cons_of_ne_nil hne]
        exact ih _ (by omega) (by omega) hinv'



/-- Step equations for the commitment pass, one per branch. -/
theorem commitPass_step_leaf [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ)
    (nonce : Fin n → Salt) (m : Fin n → M) (k : ℕ) (vals : ℕ → D)
    (hleaf : n ≤ k + 1 ∧ k + 1 < 2 * n) :
    commitPass C n nonce m (k + 1) vals =
      .query (C.leafEnc (nonce ⟨k + 1 - n, by omega⟩, m ⟨k + 1 - n, by omega⟩))
        (fun y => commitPass C n nonce m k (Function.update vals (k + 1) y)) := by
  rw [commitPass]; simp only [dif_pos hleaf]

theorem commitPass_step_node [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ)
    (nonce : Fin n → Salt) (m : Fin n → M) (k : ℕ) (vals : ℕ → D)
    (hleaf : ¬(n ≤ k + 1 ∧ k + 1 < 2 * n)) (hint : 0 < k + 1 ∧ k + 1 < n) :
    commitPass C n nonce m (k + 1) vals =
      .query (C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1)))
        (fun y => commitPass C n nonce m k (Function.update vals (k + 1) y)) := by
  rw [commitPass]; simp only [dif_neg hleaf, dif_pos hint]

theorem commitPass_step_none [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ)
    (nonce : Fin n → Salt) (m : Fin n → M) (k : ℕ) (vals : ℕ → D)
    (hleaf : ¬(n ≤ k + 1 ∧ k + 1 < 2 * n)) (hint : ¬(0 < k + 1 ∧ k + 1 < n)) :
    commitPass C n nonce m (k + 1) vals =
      (commitPass C n nonce m k (Function.update vals (k + 1) default)).weaken := by
  rw [commitPass]; simp only [dif_neg hleaf, dif_neg hint]

/-- Writing the correct value at `k+1` extends the invariant down one vertex. -/
theorem commitPass_invariant_update [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ)
    (nonce : Fin n → Salt) (m : Fin n → M) (H : Enc → D) (k : ℕ) (vals : ℕ → D)
    (hinv : ∀ v, k + 1 < v → vals v = commitLabels (C.withOracle H) n nonce m v) (y : D)
    (hy : commitLabels (C.withOracle H) n nonce m (k + 1) = y) :
    ∀ v, k < v → Function.update vals (k + 1) y v =
      commitLabels (C.withOracle H) n nonce m v := by
  intro v hv
  rw [Function.update_apply]
  split_ifs with hveq
  · rw [hveq, hy]
  · exact hinv v (by omega)

/-! ### The commitment's inputs are pairwise distinct

Commit-first fixes the commitment's slot indices only if its own queries never repeat, so the whole
question is whether two heap vertices can present the same oracle input.  Three ways they can, and
each is an event to be bounded rather than a fact:

* two leaves — the same nonce-message pair (`nonceCollision`, `Hiding.lean`);
* two internal vertices — the same pair of child labels (`nodeCollision`);
* a leaf and an internal vertex — possible because the encoding *ranges* may overlap, which this
  development deliberately permits (`concrete_ranges_overlap_iff`) (`crossCollision`).

`commitInputsInjective` is what the slot argument actually consumes, and
`commitInputsInjective_of_no_collision` derives it from the absence of all three. -/

/-- The oracle input the honest commitment presents at vertex `v`, if any. -/
def commitInput [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ) (nonce : Fin n → Salt)
    (m : Fin n → M) (H : Enc → D) (v : ℕ) : Option Enc :=
  if hleaf : n ≤ v ∧ v < 2 * n then
    some (C.leafEnc (nonce ⟨v - n, by omega⟩, m ⟨v - n, by omega⟩))
  else if 0 < v ∧ v < n then
    some (C.nodeEnc (commitLabels (C.withOracle H) n nonce m (2 * v),
      commitLabels (C.withOracle H) n nonce m (2 * v + 1)))
  else none

/-- Two internal vertices present the same node input. -/
def nodeCollision [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ) (nonce : Fin n → Salt)
    (m : Fin n → M) (H : Enc → D) : Prop :=
  ∃ v w : ℕ, 0 < v ∧ v < n ∧ 0 < w ∧ w < n ∧ v ≠ w ∧
    C.nodeEnc (commitLabels (C.withOracle H) n nonce m (2 * v),
        commitLabels (C.withOracle H) n nonce m (2 * v + 1)) =
      C.nodeEnc (commitLabels (C.withOracle H) n nonce m (2 * w),
        commitLabels (C.withOracle H) n nonce m (2 * w + 1))

/-- A leaf and an internal vertex present the same input — possible only because leaf and node
encoding ranges are permitted to overlap. -/
def crossCollision [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ) (nonce : Fin n → Salt)
    (m : Fin n → M) (H : Enc → D) : Prop :=
  ∃ (i : Fin n) (v : ℕ), 0 < v ∧ v < n ∧
    C.leafEnc (nonce i, m i) =
      C.nodeEnc (commitLabels (C.withOracle H) n nonce m (2 * v),
        commitLabels (C.withOracle H) n nonce m (2 * v + 1))

/-- What the slot argument consumes: distinct vertices present distinct inputs. -/
def commitInputsInjective [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ)
    (nonce : Fin n → Salt) (m : Fin n → M) (H : Enc → D) : Prop :=
  ∀ v w : ℕ, 0 < v → v < 2 * n → 0 < w → w < 2 * n → v ≠ w →
    ∀ x, commitInput C n nonce m H v = some x → commitInput C n nonce m H w ≠ some x

/-- Off all three collision events the commitment's inputs are pairwise distinct. -/
theorem commitInputsInjective_of_no_collision [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ)
    (nonce : Fin n → Salt) (m : Fin n → M) (H : Enc → D)
    (hleafcol : ∀ i j : Fin n, i ≠ j → C.leafEnc (nonce i, m i) ≠ C.leafEnc (nonce j, m j))
    (hnodecol : ¬ nodeCollision C n nonce m H)
    (hcross : ¬ crossCollision C n nonce m H) :
    commitInputsInjective C n nonce m H := by
  intro v w hv hvlt hw hwlt hvw x hxv hxw
  unfold commitInput at hxv hxw
  split at hxv
  · rename_i hvleaf
    split at hxw
    · -- two leaves
      rename_i hwleaf
      refine hleafcol ⟨v - n, by omega⟩ ⟨w - n, by omega⟩ (fun hij => ?_) ?_
      · exact hvw (by have := Fin.mk.inj_iff.mp hij; omega)
      · exact (Option.some_inj.mp hxv).trans (Option.some_inj.mp hxw).symm
    · -- leaf then internal
      split at hxw
      · rename_i hwint
        exact hcross ⟨⟨v - n, by omega⟩, w, hwint.1, hwint.2,
          (Option.some_inj.mp hxv).trans (Option.some_inj.mp hxw).symm⟩
      · exact absurd hxw (by simp)
  · split at hxv
    · rename_i hvint
      split at hxw
      · -- internal then leaf
        rename_i hwleaf
        exact hcross ⟨⟨w - n, by omega⟩, v, hvint.1, hvint.2,
          (Option.some_inj.mp hxw).trans (Option.some_inj.mp hxv).symm⟩
      · split at hxw
        · -- two internal
          rename_i hwint
          exact hnodecol ⟨v, w, hvint.1, hvint.2, hwint.1, hwint.2, hvw,
            (Option.some_inj.mp hxv).trans (Option.some_inj.mp hxw).symm⟩
        · exact absurd hxw (by simp)
    · exact absurd hxv (by simp)

/-- Every input the pass queries is the input of one of the vertices it processed. -/
theorem mem_commitPass_trace_vertex [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ)
    (nonce : Fin n → Salt) (m : Fin n → M) (H : Enc → D) :
    ∀ (k : ℕ) (vals : ℕ → D),
      (∀ v, k < v → vals v = commitLabels (C.withOracle H) n nonce m v) →
      ∀ x ∈ ((commitPass C n nonce m k vals).run H).2.map Prod.fst,
        ∃ v, 0 < v ∧ v ≤ k ∧ commitInput C n nonce m H v = some x := by
  intro k
  induction k with
  | zero => intro vals _ x hx; simp [commitPass] at hx
  | succ k ih =>
    intro vals hinv x hx
    by_cases hleaf : n ≤ k + 1 ∧ k + 1 < 2 * n
    · rw [commitPass_step_leaf C n nonce m k vals hleaf, Tree.run_query] at hx
      simp only [List.map_cons, List.mem_cons] at hx
      have hcv : commitLabels (C.withOracle H) n nonce m (k + 1) =
          H (C.leafEnc (nonce ⟨k + 1 - n, by omega⟩, m ⟨k + 1 - n, by omega⟩)) := by
        rw [commitLabels_leaf (C.withOracle H) n nonce m (k + 1) hleaf]; rfl
      rcases hx with rfl | hx
      · exact ⟨k + 1, by omega, by omega, by rw [commitInput, dif_pos hleaf]⟩
      · obtain ⟨v, hv, hvk, hvx⟩ := ih _
          (commitPass_invariant_update C n nonce m H k vals hinv _ hcv) x hx
        exact ⟨v, hv, by omega, hvx⟩
    · by_cases hint : 0 < k + 1 ∧ k + 1 < n
      · rw [commitPass_step_node C n nonce m k vals hleaf hint, Tree.run_query] at hx
        simp only [List.map_cons, List.mem_cons] at hx
        have hcv : commitLabels (C.withOracle H) n nonce m (k + 1) =
            H (C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1))) := by
          rw [commitLabels_node (C.withOracle H) n nonce m (k + 1) hint,
            hinv _ (by omega), hinv _ (by omega)]
          rfl
        rcases hx with rfl | hx
        · refine ⟨k + 1, by omega, by omega, ?_⟩
          rw [commitInput, dif_neg hleaf, if_pos hint, hinv _ (by omega), hinv _ (by omega)]
        · obtain ⟨v, hv, hvk, hvx⟩ := ih _
            (commitPass_invariant_update C n nonce m H k vals hinv _ hcv) x hx
          exact ⟨v, hv, by omega, hvx⟩
      · rw [commitPass_step_none C n nonce m k vals hleaf hint, Tree.run_weaken] at hx
        have hcv : commitLabels (C.withOracle H) n nonce m (k + 1) = default := by
          rw [commitLabels, dif_neg hleaf, dif_neg hint]
        obtain ⟨v, hv, hvk, hvx⟩ := ih _
          (commitPass_invariant_update C n nonce m H k vals hinv _ hcv) x hx
        exact ⟨v, hv, by omega, hvx⟩

/-- **The commitment's queries never repeat.**  Off the three collision events, the pass's trace is
`Nodup` — which is exactly the hypothesis `RandomOracle.lazyRun_slot_eq_of_nodup` needs to pin the
commitment's slots. -/
theorem commitPass_trace_nodup [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ)
    (nonce : Fin n → Salt) (m : Fin n → M) (H : Enc → D)
    (hinj : commitInputsInjective C n nonce m H) :
    ∀ (k : ℕ) (vals : ℕ → D), k < 2 * n →
      (∀ v, k < v → vals v = commitLabels (C.withOracle H) n nonce m v) →
      (((commitPass C n nonce m k vals).run H).2.map Prod.fst).Nodup := by
  intro k
  induction k with
  | zero => intro vals _ _; simp [commitPass]
  | succ k ih =>
    intro vals hk hinv
    by_cases hleaf : n ≤ k + 1 ∧ k + 1 < 2 * n
    · have hcv : commitLabels (C.withOracle H) n nonce m (k + 1) =
          H (C.leafEnc (nonce ⟨k + 1 - n, by omega⟩, m ⟨k + 1 - n, by omega⟩)) := by
        rw [commitLabels_leaf (C.withOracle H) n nonce m (k + 1) hleaf]; rfl
      have hself : commitInput C n nonce m H (k + 1) =
          some (C.leafEnc (nonce ⟨k + 1 - n, by omega⟩, m ⟨k + 1 - n, by omega⟩)) := by
        rw [commitInput, dif_pos hleaf]
      rw [commitPass_step_leaf C n nonce m k vals hleaf, Tree.run_query]
      simp only [List.map_cons, List.nodup_cons]
      refine ⟨fun hmem => ?_, ih _ (by omega)
        (commitPass_invariant_update C n nonce m H k vals hinv _ hcv)⟩
      obtain ⟨v, hv, hvk, hvx⟩ := mem_commitPass_trace_vertex C n nonce m H k _
        (commitPass_invariant_update C n nonce m H k vals hinv _ hcv) _ hmem
      exact hinj (k + 1) v (by omega) (by omega) hv (by omega) (by omega) _ hself hvx
    · by_cases hint : 0 < k + 1 ∧ k + 1 < n
      · have hcv : commitLabels (C.withOracle H) n nonce m (k + 1) =
            H (C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1))) := by
          rw [commitLabels_node (C.withOracle H) n nonce m (k + 1) hint,
            hinv _ (by omega), hinv _ (by omega)]
          rfl
        have hself : commitInput C n nonce m H (k + 1) =
            some (C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1))) := by
          rw [commitInput, dif_neg hleaf, if_pos hint, hinv _ (by omega), hinv _ (by omega)]
        rw [commitPass_step_node C n nonce m k vals hleaf hint, Tree.run_query]
        simp only [List.map_cons, List.nodup_cons]
        refine ⟨fun hmem => ?_, ih _ (by omega)
          (commitPass_invariant_update C n nonce m H k vals hinv _ hcv)⟩
        obtain ⟨v, hv, hvk, hvx⟩ := mem_commitPass_trace_vertex C n nonce m H k _
          (commitPass_invariant_update C n nonce m H k vals hinv _ hcv) _ hmem
        exact hinj (k + 1) v (by omega) (by omega) hv (by omega) (by omega) _ hself hvx
      · have hcv : commitLabels (C.withOracle H) n nonce m (k + 1) = default := by
          rw [commitLabels, dif_neg hleaf, dif_neg hint]
        rw [commitPass_step_none C n nonce m k vals hleaf hint, Tree.run_weaken]
        exact ih _ (by omega) (commitPass_invariant_update C n nonce m H k vals hinv _ hcv)


/-! ### The root sits at a fixed slot

The point of all of the above.  The commitment runs first, from an empty seen-list, so off the three
collision events its `j`-th query occupies slot `j`; it makes `2n-1` queries; and the last of them is
vertex `1`'s, whose answer is the root.  So the root is the tape entry at the *constant* index
`2n-2` — a value a message-independent simulator can read, which is what root hiding needs. -/

/-- The commitment phase's own lazy-sampling oracle. -/
def commitOracle [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ) (nonce : Fin n → Salt)
    (m : Fin n → M) {T : ℕ} (answers : Fin T → D) : Enc → D :=
  fun x => tapeAt answers default
    ((lazyRun answers default (commitPass C n nonce m (2 * n - 1) fun _ => default) []).2.1.idxOf x)

/-- **The honest root is the tape at slot `2n-2`.** -/
theorem commitPass_root_eq_tape [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ) (hn : 0 < n)
    (nonce : Fin n → Salt) (m : Fin n → M) {T : ℕ} (answers : Fin T → D)
    (hinj : commitInputsInjective C n nonce m (commitOracle C n nonce m answers))
    (hT : 2 * n - 2 < T) :
    root (C.withOracle (commitOracle C n nonce m answers)) n nonce m =
      answers ⟨2 * n - 2, hT⟩ := by
  classical
  have hinvinit : ∀ v, 2 * n - 1 < v →
      (fun _ => (default : D)) v =
        commitLabels (C.withOracle (commitOracle C n nonce m answers)) n nonce m v :=
    fun v hv => (commitLabels_of_ge (S := C.withOracle (commitOracle C n nonce m answers))
      n nonce m v (by omega)).symm
  have hrun : (commitPass C n nonce m (2 * n - 1) fun _ => default).run
        (commitOracle C n nonce m answers) =
      ((lazyRun answers default (commitPass C n nonce m (2 * n - 1) fun _ => default) []).1,
        (lazyRun answers default
          (commitPass C n nonce m (2 * n - 1) fun _ => default) []).2.2) :=
    lazyRun_eq_run answers default _ [] _ fun _ => rfl
  have htr : ((commitPass C n nonce m (2 * n - 1) fun _ => default).run
        (commitOracle C n nonce m answers)).2 =
      (lazyRun answers default (commitPass C n nonce m (2 * n - 1) fun _ => default) []).2.2 := by
    rw [hrun]
  have hlen : ((commitPass C n nonce m (2 * n - 1) fun _ => default).run
      (commitOracle C n nonce m answers)).2.length = 2 * n - 1 :=
    commitPass_trace_length C n hn nonce m _ (2 * n - 1) _ (le_refl _)
  have hnd : (((commitPass C n nonce m (2 * n - 1) fun _ => default).run
      (commitOracle C n nonce m answers)).2.map Prod.fst).Nodup :=
    commitPass_trace_nodup C n nonce m _ hinj (2 * n - 1) _ (by omega) hinvinit
  have hlast := commitPass_trace_getLast C n hn nonce m
    (commitOracle C n nonce m answers) (2 * n - 1) _ (by omega) (le_refl _) hinvinit
  rw [List.getLast?_eq_getElem?, hlen] at hlast
  obtain ⟨qa, hqamem, hqasnd⟩ := Option.map_eq_some_iff.mp hlast
  have hlt : 2 * n - 2 < ((lazyRun answers default
      (commitPass C n nonce m (2 * n - 1) fun _ => default) []).2.2.map Prod.fst).length := by
    rw [List.length_map, ← htr, hlen]
    omega
  have hget : ((lazyRun answers default
      (commitPass C n nonce m (2 * n - 1) fun _ => default) []).2.2.map Prod.fst)[2 * n - 2] =
      qa.1 := by
    rw [← Option.some_inj, ← List.getElem?_eq_getElem hlt, ← htr, List.getElem?_map,
      show 2 * n - 2 = 2 * n - 1 - 1 by omega, hqamem]
    rfl
  have hidx : (lazyRun answers default
      (commitPass C n nonce m (2 * n - 1) fun _ => default) []).2.1.idxOf qa.1 = 2 * n - 2 := by
    rw [← hget]
    exact lazyRun_slot_eq_of_nodup answers default _ (by rw [← htr]; exact hnd) (2 * n - 2) hlt
  have hslot := lazyRun_trace_slot answers default
    (commitPass C n nonce m (2 * n - 1) fun _ => default) [] qa
    (by rw [← htr]; exact List.mem_of_getElem? hqamem)
  rw [root, ← hqasnd, hslot.2, hidx, tapeAt, dif_pos hT]

/-- **Every vertex's query sits at a fixed position.**  The pass runs downwards, so vertex `v` is the
`k - v`-th query of a pass started at `k`, and its answer is that vertex's label. -/
theorem commitPass_trace_getElem [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ) (hn : 0 < n)
    (nonce : Fin n → Salt) (m : Fin n → M) (H : Enc → D) :
    ∀ (k : ℕ) (vals : ℕ → D), k ≤ 2 * n - 1 →
      (∀ v, k < v → vals v = commitLabels (C.withOracle H) n nonce m v) →
      ∀ v, 1 ≤ v → v ≤ k →
        (((commitPass C n nonce m k vals).run H).2[k - v]?).map Prod.snd =
          some (commitLabels (C.withOracle H) n nonce m v) := by
  intro k
  induction k with
  | zero => intro _ _ _ v hv1 hvk; exact absurd hv1 (by omega)
  | succ k ih =>
    intro vals hk hinv v hv1 hvk
    by_cases hleaf : n ≤ k + 1 ∧ k + 1 < 2 * n
    · have hcv : commitLabels (C.withOracle H) n nonce m (k + 1) =
          H (C.leafEnc (nonce ⟨k + 1 - n, by omega⟩, m ⟨k + 1 - n, by omega⟩)) := by
        rw [commitLabels_leaf (C.withOracle H) n nonce m (k + 1) hleaf]; rfl
      rw [commitPass_step_leaf C n nonce m k vals hleaf, Tree.run_query]
      rcases Nat.eq_or_lt_of_le hvk with hveq | hvlt
      · subst hveq
        simp [hcv]
      · rw [show k + 1 - v = (k - v) + 1 by omega]
        simpa using ih _ (by omega)
          (commitPass_invariant_update C n nonce m H k vals hinv _ hcv) v hv1 (by omega)
    · by_cases hint : 0 < k + 1 ∧ k + 1 < n
      · have hcv : commitLabels (C.withOracle H) n nonce m (k + 1) =
            H (C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1))) := by
          rw [commitLabels_node (C.withOracle H) n nonce m (k + 1) hint,
            hinv _ (by omega), hinv _ (by omega)]
          rfl
        rw [commitPass_step_node C n nonce m k vals hleaf hint, Tree.run_query]
        rcases Nat.eq_or_lt_of_le hvk with hveq | hvlt
        · subst hveq
          simp [hcv]
        · rw [show k + 1 - v = (k - v) + 1 by omega]
          simpa using ih _ (by omega)
            (commitPass_invariant_update C n nonce m H k vals hinv _ hcv) v hv1 (by omega)
      · exact absurd hleaf (by omega)

/-- The query counterpart of `commitPass_trace_getElem`: vertex `v`'s *input* sits at position
`k - v` of the trace.  Needed to pin a commitment input's slot, where the answer version pins the
label's. -/
theorem commitPass_trace_getElem_fst [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ)
    (nonce : Fin n → Salt) (m : Fin n → M) (H : Enc → D) :
    ∀ (k : ℕ) (vals : ℕ → D), k ≤ 2 * n - 1 →
      (∀ v, k < v → vals v = commitLabels (C.withOracle H) n nonce m v) →
      ∀ v, 1 ≤ v → v ≤ k →
        (((commitPass C n nonce m k vals).run H).2[k - v]?).map Prod.fst =
          commitInput C n nonce m H v := by
  intro k
  induction k with
  | zero => intro _ _ _ v hv1 hvk; exact absurd hv1 (by omega)
  | succ k ih =>
    intro vals hk hinv v hv1 hvk
    by_cases hleaf : n ≤ k + 1 ∧ k + 1 < 2 * n
    · have hcv : commitLabels (C.withOracle H) n nonce m (k + 1) =
          H (C.leafEnc (nonce ⟨k + 1 - n, by omega⟩, m ⟨k + 1 - n, by omega⟩)) := by
        rw [commitLabels_leaf (C.withOracle H) n nonce m (k + 1) hleaf]; rfl
      rw [commitPass_step_leaf C n nonce m k vals hleaf, Tree.run_query]
      rcases Nat.eq_or_lt_of_le hvk with hveq | hvlt
      · subst hveq
        have hself : commitInput C n nonce m H (k + 1) =
            some (C.leafEnc (nonce ⟨k + 1 - n, by omega⟩, m ⟨k + 1 - n, by omega⟩)) := by
          rw [commitInput, dif_pos hleaf]
        rw [hself]
        simp
      · rw [show k + 1 - v = (k - v) + 1 by omega]
        simpa using ih _ (by omega)
          (commitPass_invariant_update C n nonce m H k vals hinv _ hcv) v hv1 (by omega)
    · by_cases hint : 0 < k + 1 ∧ k + 1 < n
      · have hcv : commitLabels (C.withOracle H) n nonce m (k + 1) =
            H (C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1))) := by
          rw [commitLabels_node (C.withOracle H) n nonce m (k + 1) hint,
            hinv _ (by omega), hinv _ (by omega)]
          rfl
        rw [commitPass_step_node C n nonce m k vals hleaf hint, Tree.run_query]
        rcases Nat.eq_or_lt_of_le hvk with hveq | hvlt
        · subst hveq
          have hself : commitInput C n nonce m H (k + 1) =
              some (C.nodeEnc (vals (2 * (k + 1)), vals (2 * (k + 1) + 1))) := by
            rw [commitInput, dif_neg hleaf, if_pos hint, hinv _ (by omega), hinv _ (by omega)]
          rw [hself]
          simp
        · rw [show k + 1 - v = (k - v) + 1 by omega]
          simpa using ih _ (by omega)
            (commitPass_invariant_update C n nonce m H k vals hinv _ hcv) v hv1 (by omega)
      · exact absurd hleaf (by omega)

/-- **Every honest label is a fixed tape slot.**  Off the collision events, vertex `v`'s label is the
tape entry at index `2n-1-v` — an index depending on the vertex alone, not on the message.  This is
what makes the whole honest tree, root and frontier digests alike, message-independent as a function
of the tape, and it is the engine behind both hiding statements. -/
theorem commitLabels_eq_tape [DecidableEq Enc] (C : Codec Salt M D Enc) (n : ℕ) (hn : 0 < n)
    (nonce : Fin n → Salt) (m : Fin n → M) {T : ℕ} (answers : Fin T → D)
    (hinj : commitInputsInjective C n nonce m (commitOracle C n nonce m answers))
    (v : ℕ) (hv1 : 1 ≤ v) (hv : v ≤ 2 * n - 1) (hT : 2 * n - 1 - v < T) :
    commitLabels (C.withOracle (commitOracle C n nonce m answers)) n nonce m v =
      answers ⟨2 * n - 1 - v, hT⟩ := by
  classical
  have hinvinit : ∀ w, 2 * n - 1 < w →
      (fun _ => (default : D)) w =
        commitLabels (C.withOracle (commitOracle C n nonce m answers)) n nonce m w :=
    fun w hw => (commitLabels_of_ge (S := C.withOracle (commitOracle C n nonce m answers))
      n nonce m w (by omega)).symm
  have hrun : (commitPass C n nonce m (2 * n - 1) fun _ => default).run
        (commitOracle C n nonce m answers) =
      ((lazyRun answers default (commitPass C n nonce m (2 * n - 1) fun _ => default) []).1,
        (lazyRun answers default
          (commitPass C n nonce m (2 * n - 1) fun _ => default) []).2.2) :=
    lazyRun_eq_run answers default _ [] _ fun _ => rfl
  have htr : ((commitPass C n nonce m (2 * n - 1) fun _ => default).run
        (commitOracle C n nonce m answers)).2 =
      (lazyRun answers default (commitPass C n nonce m (2 * n - 1) fun _ => default) []).2.2 := by
    rw [hrun]
  have hlen : ((commitPass C n nonce m (2 * n - 1) fun _ => default).run
      (commitOracle C n nonce m answers)).2.length = 2 * n - 1 :=
    commitPass_trace_length C n hn nonce m _ (2 * n - 1) _ (le_refl _)
  have hnd : (((commitPass C n nonce m (2 * n - 1) fun _ => default).run
      (commitOracle C n nonce m answers)).2.map Prod.fst).Nodup :=
    commitPass_trace_nodup C n nonce m _ hinj (2 * n - 1) _ (by omega) hinvinit
  obtain ⟨qa, hqamem, hqasnd⟩ := Option.map_eq_some_iff.mp
    (commitPass_trace_getElem C n hn nonce m (commitOracle C n nonce m answers)
      (2 * n - 1) _ (le_refl _) hinvinit v hv1 hv)
  have hlt : 2 * n - 1 - v < ((lazyRun answers default
      (commitPass C n nonce m (2 * n - 1) fun _ => default) []).2.2.map Prod.fst).length := by
    rw [List.length_map, ← htr, hlen]
    omega
  have hget : ((lazyRun answers default
      (commitPass C n nonce m (2 * n - 1) fun _ => default) []).2.2.map Prod.fst)[2 * n - 1 - v] =
      qa.1 := by
    rw [← Option.some_inj, ← List.getElem?_eq_getElem hlt, ← htr, List.getElem?_map, hqamem]
    rfl
  have hidx : (lazyRun answers default
      (commitPass C n nonce m (2 * n - 1) fun _ => default) []).2.1.idxOf qa.1 =
      2 * n - 1 - v := by
    rw [← hget]
    exact lazyRun_slot_eq_of_nodup answers default _ (by rw [← htr]; exact hnd) _ hlt
  have hslot := lazyRun_trace_slot answers default
    (commitPass C n nonce m (2 * n - 1) fun _ => default) [] qa
    (by rw [← htr]; exact List.mem_of_getElem? hqamem)
  rw [← hqasnd, hslot.2, hidx, tapeAt, dif_pos hT]


end MH

end Merkle
