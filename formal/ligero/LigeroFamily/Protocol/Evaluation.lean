import CodingTheory.Basic
import Mathlib.LinearAlgebra.Dimension.Finrank

/-!
# LigeroFamily evaluation spaces

This file deliberately uses evaluations and interpolation only.  A base row
has `k = r + w` message evaluations: `r` random-padding evaluations followed
by `w` witness evaluations.  Its committed part consists of `n` code
evaluations.  Response rows have interpolation dimension `2 * k`.

`MultiplicativeCode` is the exact interface needed by the corrected protocol.
It is not restricted to Reed--Solomon syntax: the common proximity theorem
sees only `baseCode`, an arbitrary linear code.  The main LigeroFamily analysis
additionally assumes the interpolation and coordinatewise-multiplication laws
recorded here.
-/

namespace LigeroFamily





structure MaskingRateCondition (r w : ℕ) : Prop where
  query_le_witness : r ≤ w

/-- Longfellow message locations: random padding, then witness values. -/
abbrev MessagePosition (r w : ℕ) := Fin r ⊕ Fin w

/-- All locations at which an evaluation row is discussed. -/
abbrev Position (r w n : ℕ) := MessagePosition r w ⊕ Fin n

/-- An evaluation-space row, including message and committed locations. -/
abbrev EvaluationRow (F : Type*) (r w n : ℕ) := Position r w n → F

def randomPosition {r w n : ℕ} (i : Fin r) : Position r w n :=
  Sum.inl (Sum.inl i)

def witnessPosition {r w n : ℕ} (i : Fin w) : Position r w n :=
  Sum.inl (Sum.inr i)

def codePosition {r w n : ℕ} (i : Fin n) : Position r w n :=
  Sum.inr i

def randomValues {F : Type*} {r w n : ℕ}
    (row : EvaluationRow F r w n) : Fin r → F :=
  fun i ↦ row (randomPosition i)

def witnessValues {F : Type*} {r w n : ℕ}
    (row : EvaluationRow F r w n) : Fin w → F :=
  fun i ↦ row (witnessPosition i)

def codeword {F : Type*} {r w n : ℕ}
    (row : EvaluationRow F r w n) : CodingTheory.Word F n :=
  fun i ↦ row (codePosition i)

def rowMul {F : Type*} [Mul F] {r w n : ℕ}
    (left right : EvaluationRow F r w n) : EvaluationRow F r w n :=
  fun i ↦ left i * right i

@[simp] theorem rowMul_apply {F : Type*} [Mul F] {r w n : ℕ}
    (left right : EvaluationRow F r w n) (i : Position r w n) :
    rowMul left right i = left i * right i := rfl

def randomPositions (r w n : ℕ) : Finset (Position r w n) :=
  Finset.univ.image randomPosition

def witnessPositions (r w n : ℕ) : Finset (Position r w n) :=
  Finset.univ.image witnessPosition

def messagePositions (r w n : ℕ) : Finset (Position r w n) :=
  Finset.univ.image Sum.inl

def codePositions {r w n : ℕ} (Q : Finset (Fin n)) :
    Finset (Position r w n) :=
  Q.image codePosition

@[simp] theorem card_randomPositions (r w n : ℕ) :
    (randomPositions r w n).card = r := by
  rw [randomPositions, Finset.card_image_of_injective]
  · simp
  · intro i j hij
    exact Sum.inl.inj (Sum.inl.inj hij)

@[simp] theorem card_witnessPositions (r w n : ℕ) :
    (witnessPositions r w n).card = w := by
  rw [witnessPositions, Finset.card_image_of_injective]
  · simp
  · intro i j hij
    exact Sum.inr.inj (Sum.inl.inj hij)

@[simp] theorem card_messagePositions (r w n : ℕ) :
    (messagePositions r w n).card = r + w := by
  rw [messagePositions, Finset.card_image_of_injective _ Sum.inl_injective]
  simp

@[simp] theorem card_codePositions {r w n : ℕ} (Q : Finset (Fin n)) :
    (codePositions (r := r) (w := w) Q).card = Q.card := by
  rw [codePositions, Finset.card_image_of_injective]
  exact Sum.inr_injective

theorem messagePositions_disjoint_codePositions {r w n : ℕ}
    (Q : Finset (Fin n)) :
    Disjoint (messagePositions r w n) (codePositions (r := r) (w := w) Q) := by
  refine Finset.disjoint_left.mpr ?_
  intro i hi hj
  rcases Finset.mem_image.mp hi with ⟨a, _, rfl⟩
  rcases Finset.mem_image.mp hj with ⟨b, _, h⟩
  cases h

theorem randomPositions_disjoint_codePositions {r w n : ℕ}
    (Q : Finset (Fin n)) :
    Disjoint (randomPositions r w n) (codePositions (r := r) (w := w) Q) := by
  refine Finset.disjoint_left.mpr ?_
  intro i hi hj
  rcases Finset.mem_image.mp hi with ⟨a, _, rfl⟩
  rcases Finset.mem_image.mp hj with ⟨b, _, h⟩
  cases h

theorem witnessPositions_disjoint_codePositions {r w n : ℕ}
    (Q : Finset (Fin n)) :
    Disjoint (witnessPositions r w n) (codePositions (r := r) (w := w) Q) := by
  refine Finset.disjoint_left.mpr ?_
  intro i hi hj
  rcases Finset.mem_image.mp hi with ⟨a, _, rfl⟩
  rcases Finset.mem_image.mp hj with ⟨b, _, h⟩
  cases h

@[simp] theorem card_messagePositions_union_codePositions {r w n : ℕ}
    (Q : Finset (Fin n)) :
    (messagePositions r w n ∪ codePositions (r := r) (w := w) Q).card =
      r + w + Q.card := by
  rw [Finset.card_union_of_disjoint
    (messagePositions_disjoint_codePositions Q)]
  simp

@[simp] theorem card_randomPositions_union_codePositions {r w n : ℕ}
    (Q : Finset (Fin n)) :
    (randomPositions r w n ∪ codePositions (r := r) (w := w) Q).card =
      r + Q.card := by
  rw [Finset.card_union_of_disjoint
    (randomPositions_disjoint_codePositions Q)]
  simp

@[simp] theorem card_witnessPositions_union_codePositions {r w n : ℕ}
    (Q : Finset (Fin n)) :
    (witnessPositions r w n ∪ codePositions (r := r) (w := w) Q).card =
      w + Q.card := by
  rw [Finset.card_union_of_disjoint
    (witnessPositions_disjoint_codePositions Q)]
  simp

/-- An MDS-style multiplicative evaluation code used by LigeroFamily.

The interpolation field is stated for every set of at most `k` locations;
uniqueness is stated at exactly `k` (or `2k`) locations.  These are intrinsic
evaluation-space properties. -/
structure MultiplicativeCode (F : Type*) [Field F] (r w n : ℕ) where
  k : ℕ
  k_eq : k = r + w
  k_le_n : k ≤ n
  base : Submodule F (EvaluationRow F r w n)
  response : Submodule F (EvaluationRow F r w n)
  base_le_response : base ≤ response
  interpolateBase : ∀ (S : Finset (Position r w n)), S.card ≤ k →
    ∀ values : ↥S → F, ∃ row : EvaluationRow F r w n,
      row ∈ base ∧ ∀ i : ↥S, row i.1 = values i
  base_unique : ∀ {left right : EvaluationRow F r w n},
    left ∈ base → right ∈ base →
    ∀ S : Finset (Position r w n), S.card = k →
      (∀ i ∈ S, left i = right i) → left = right
  response_unique : ∀ {left right : EvaluationRow F r w n},
    left ∈ response → right ∈ response →
    ∀ S : Finset (Position r w n), S.card = 2 * k →
      (∀ i ∈ S, left i = right i) → left = right
  mul_mem : ∀ {left right : EvaluationRow F r w n},
    left ∈ base → right ∈ base → rowMul left right ∈ response

namespace MultiplicativeCode

variable {F : Type*} [Field F] {r w n : ℕ}

/-- The protocol query size fits in the committed codeword length. -/
theorem query_le_length (C : MultiplicativeCode F r w n) : r ≤ n := by
  have hk := C.k_le_n
  rw [C.k_eq] at hk
  omega

/-- Choose the base row with prescribed evaluations on at most `k`
locations. -/
noncomputable def interpolateBaseRow (C : MultiplicativeCode F r w n)
    (S : Finset (Position r w n)) (hS : S.card ≤ C.k)
    (values : ↥S → F) : EvaluationRow F r w n :=
  Classical.choose (C.interpolateBase S hS values)

theorem interpolateBaseRow_mem (C : MultiplicativeCode F r w n)
    (S : Finset (Position r w n)) (hS : S.card ≤ C.k)
    (values : ↥S → F) : C.interpolateBaseRow S hS values ∈ C.base :=
  (Classical.choose_spec (C.interpolateBase S hS values)).1

@[simp] theorem interpolateBaseRow_apply (C : MultiplicativeCode F r w n)
    (S : Finset (Position r w n)) (hS : S.card ≤ C.k)
    (values : ↥S → F) (i : ↥S) :
    C.interpolateBaseRow S hS values i.1 = values i :=
  (Classical.choose_spec (C.interpolateBase S hS values)).2 i

private def codewordLinearMap :
    EvaluationRow F r w n →ₗ[F] CodingTheory.Word F n where
  toFun := codeword
  map_add' := by intros; rfl
  map_smul' := by intros; rfl

/-- The arbitrary linear code seen by affine agreement extraction. -/
def baseCode (C : MultiplicativeCode F r w n) :
    CodingTheory.LinearCode F n :=
  C.base.map codewordLinearMap

/-- The response-code projection used by the common arithmetic-mask
agreement argument. -/
def responseCode (C : MultiplicativeCode F r w n) :
    CodingTheory.LinearCode F n :=
  C.response.map codewordLinearMap

theorem codeword_mem_baseCode (C : MultiplicativeCode F r w n)
    {row : EvaluationRow F r w n} (hrow : row ∈ C.base) :
    codeword row ∈ C.baseCode := by
  unfold baseCode
  exact Submodule.mem_map.mpr ⟨row, hrow, rfl⟩

theorem codeword_mem_responseCode (C : MultiplicativeCode F r w n)
    {row : EvaluationRow F r w n} (hrow : row ∈ C.response) :
    codeword row ∈ C.responseCode := by
  unfold responseCode
  exact Submodule.mem_map.mpr ⟨row, hrow, rfl⟩

/-- Every word in the protocol-facing base code has an evaluation-row lift. -/
theorem exists_base_row_of_mem_baseCode (C : MultiplicativeCode F r w n)
    {word : CodingTheory.Word F n} (hword : word ∈ C.baseCode) :
    ∃ row : EvaluationRow F r w n, row ∈ C.base ∧ codeword row = word := by
  unfold baseCode at hword
  rcases Submodule.mem_map.mp hword with ⟨row, hrow, heq⟩
  exact ⟨row, hrow, heq⟩

theorem exists_response_row_of_mem_responseCode
    (C : MultiplicativeCode F r w n)
    {word : CodingTheory.Word F n} (hword : word ∈ C.responseCode) :
    ∃ row : EvaluationRow F r w n,
      row ∈ C.response ∧ codeword row = word := by
  unfold responseCode at hword
  rcases Submodule.mem_map.mp hword with ⟨row, hrow, heq⟩
  exact ⟨row, hrow, heq⟩

private def messagePrescription (values : MessagePosition r w → F) :
    EvaluationRow F r w n
  | Sum.inl i => values i
  | Sum.inr _ => 0

/-- Interpolate a base row from all `k = r+w` message evaluations. -/
noncomputable def encodeMessage (C : MultiplicativeCode F r w n)
    (values : MessagePosition r w → F) : EvaluationRow F r w n :=
  C.interpolateBaseRow (messagePositions r w n) (by simp [C.k_eq])
    (fun i ↦ messagePrescription values i.1)

theorem encodeMessage_mem (C : MultiplicativeCode F r w n)
    (values : MessagePosition r w → F) : C.encodeMessage values ∈ C.base := by
  apply C.interpolateBaseRow_mem

@[simp] theorem encodeMessage_message (C : MultiplicativeCode F r w n)
    (values : MessagePosition r w → F) (i : MessagePosition r w) :
    C.encodeMessage values (Sum.inl i) = values i := by
  let hi : Sum.inl i ∈ messagePositions r w n := by
    simp [messagePositions]
  have hvalue := C.interpolateBaseRow_apply (messagePositions r w n)
    (by simp [C.k_eq]) (fun j ↦ messagePrescription values j.1)
    ⟨Sum.inl i, hi⟩
  simpa [encodeMessage, messagePrescription] using hvalue

/-- Longfellow encoding: explicit random prefix and witness suffix. -/
noncomputable def encode (C : MultiplicativeCode F r w n)
    (padding : Fin r → F) (witness : Fin w → F) : EvaluationRow F r w n :=
  C.encodeMessage (Sum.elim padding witness)

@[simp] theorem encode_random (C : MultiplicativeCode F r w n)
    (padding : Fin r → F) (witness : Fin w → F) (i : Fin r) :
    C.encode padding witness (randomPosition i) = padding i := by
  simp [encode, randomPosition]

@[simp] theorem encode_witness (C : MultiplicativeCode F r w n)
    (padding : Fin r → F) (witness : Fin w → F) (i : Fin w) :
    C.encode padding witness (witnessPosition i) = witness i := by
  simp [encode, witnessPosition]

theorem encode_mem (C : MultiplicativeCode F r w n)
    (padding : Fin r → F) (witness : Fin w → F) :
    C.encode padding witness ∈ C.base := C.encodeMessage_mem _

/-- The canonical public `Z_W` row: one on the random prefix and zero on
the witness suffix. -/
noncomputable def zW (C : MultiplicativeCode F r w n) :
    EvaluationRow F r w n :=
  C.encode 1 0

theorem zW_mem (C : MultiplicativeCode F r w n) : C.zW ∈ C.base :=
  C.encode_mem 1 0

@[simp] theorem zW_random (C : MultiplicativeCode F r w n) (i : Fin r) :
    C.zW (randomPosition i) = 1 :=
  C.encode_random 1 0 i

@[simp] theorem zW_witness (C : MultiplicativeCode F r w n) (i : Fin w) :
    C.zW (witnessPosition i) = 0 :=
  C.encode_witness 1 0 i

/-- The canonical public `Z_R` row: zero on the random prefix and one on
the witness suffix. -/
noncomputable def zR (C : MultiplicativeCode F r w n) :
    EvaluationRow F r w n :=
  C.encode 0 1

theorem zR_mem (C : MultiplicativeCode F r w n) : C.zR ∈ C.base :=
  C.encode_mem 0 1

@[simp] theorem zR_random (C : MultiplicativeCode F r w n) (i : Fin r) :
    C.zR (randomPosition i) = 0 :=
  C.encode_random 0 1 i

@[simp] theorem zR_witness (C : MultiplicativeCode F r w n) (i : Fin w) :
    C.zR (witnessPosition i) = 1 :=
  C.encode_witness 0 1 i

/-- The public vanishing multiplier `V` used by both two-row masks.  In the
Reed--Solomon model it evaluates the monic polynomial vanishing at every
message point. -/
structure MaskingBasis (C : MultiplicativeCode F r w n) where
  vanishing : EvaluationRow F r w n
  vanishing_message : ∀ i : MessagePosition r w,
    vanishing (Sum.inl i) = 0
  vanishing_code_ne : ∀ i : Fin n, vanishing (codePosition i) ≠ 0
  vanishing_mul_mem : ∀ {row : EvaluationRow F r w n},
    row ∈ C.base → rowMul vanishing row ∈ C.response

end MultiplicativeCode

end LigeroFamily
