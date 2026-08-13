import Ligero.Common.Protocol.Evaluation
import Ligero.Common.Protocol.Finite
import Mathlib.Tactic.DeriveFintype

/-!
# The Ligero.Common oracle protocol

This is the corrected protocol from the design discussion, expressed entirely
with evaluation rows.  The code parameters are:

* `r`: both the random-padding length in every row and the number of queried
  committed columns;
* `w`: the number of witness values carried by every row;
* `n`: the number of committed codeword columns;
* `k = r + w`: the dimension of the base code;
* `nw`: the number of linear rows;
* `nq`: the number of quadratic rows; each has `left`, `right`, and `output`
  component rows.

The response interpolation dimension is `2*k`.

Every committed secret row below is a base row and participates in the common
affine proximity test.  There is no committed full-dimension blind.
-/

namespace Ligero.Common

inductive CoreBlock
  | linear
  | left
  | right
  | output
  deriving DecidableEq, Fintype

/-- Number of rows in a core block.  Linear-tableau rows and quadratic-check
rows are independent protocol dimensions. -/
def CoreBlock.rowCount (nw nq : ℕ) : CoreBlock → ℕ
  | .linear => nw
  | .left | .right | .output => nq



inductive ConstraintMask
  | quadraticVCoefficient
  | quadraticZWCoefficient
  | linearVCoefficient
  | linearZRCoefficient
  deriving DecidableEq, Fintype

@[simp] theorem constraintMask_card : Fintype.card ConstraintMask = 4 := by
  decide

abbrev CoreRow (nw nq : ℕ) :=
  (block : CoreBlock) × Fin (block.rowCount nw nq)

/-- The protocol transport and privacy layers retain a generalized number of
parallel repetitions.  The soundness classifier and collected Ligero.Common
theorem deliberately specialize this parameter to one. -/
abbrev TestedRow (nw nq repetitions : ℕ) :=
  CoreRow nw nq ⊕ (Fin repetitions × ConstraintMask)

structure Oracle (F : Type*) (nw nq n repetitions : ℕ) where
  core : (block : CoreBlock) → Fin (block.rowCount nw nq) → Fin n → F
  mask : Fin repetitions → ConstraintMask → Fin n → F
  proximityBlind : Fin repetitions → Fin n → F

structure Column (F : Type*) (nw nq repetitions : ℕ) where
  core : (block : CoreBlock) → Fin (block.rowCount nw nq) → F
  mask : Fin repetitions → ConstraintMask → F
  proximityBlind : Fin repetitions → F

@[ext] theorem Column.ext {F : Type*} {nw nq repetitions : ℕ}
    {first second : Column F nw nq repetitions}
    (hcore : first.core = second.core)
    (hmask : first.mask = second.mask)
    (hproximityBlind : first.proximityBlind = second.proximityBlind) :
    first = second := by
  cases first
  cases second
  simp_all

namespace Oracle

def row {F : Type*} {nw nq n repetitions : ℕ}
    (oracle : Oracle F nw nq n repetitions) :
    TestedRow nw nq repetitions → CodingTheory.Word F n
  | Sum.inl row => oracle.core row.1 row.2
  | Sum.inr row => oracle.mask row.1 row.2

def column {F : Type*} {nw nq n repetitions : ℕ}
    (oracle : Oracle F nw nq n repetitions) (j : Fin n) :
    Column F nw nq repetitions where
  core block i := oracle.core block i j
  mask h kind := oracle.mask h kind j
  proximityBlind h := oracle.proximityBlind h j

end Oracle

abbrev Opening (F : Type*) (nw nq repetitions n r : ℕ)
    (query : QuerySet n r) :=
  (j : ↥query.coordinates) → Column F nw nq repetitions

def openOracle {F : Type*} {nw nq n repetitions r : ℕ}
    (oracle : Oracle F nw nq n repetitions) (query : QuerySet n r) :
    Opening F nw nq repetitions n r query :=
  fun j ↦ oracle.column j.1

abbrev CoreMessages (F : Type*) (nw nq w : ℕ) :=
  (block : CoreBlock) → Fin (block.rowCount nw nq) → Fin w → F

structure ConstraintSystem (F : Type*) (nw nq w : ℕ) (Equations : Type*) where
  coefficient : Equations → (block : CoreBlock) →
    Fin (block.rowCount nw nq) → Fin w → F
  target : Equations → F

namespace ConstraintSystem

variable {F Equations : Type*} [CommSemiring F] [Fintype Equations]
variable {nw nq w : ℕ}

def linearValue (statement : ConstraintSystem F nw nq w Equations)
    (messages : CoreMessages F nw nq w) (equation : Equations) : F :=
  ∑ block : CoreBlock,
    ∑ row : Fin (block.rowCount nw nq), ∑ i : Fin w,
    statement.coefficient equation block row i * messages block row i

def Satisfies (statement : ConstraintSystem F nw nq w Equations)
    (messages : CoreMessages F nw nq w) : Prop :=
  (∀ equation, statement.linearValue messages equation = statement.target equation) ∧
  ∀ (row : Fin nq) i,
    messages .left row i * messages .right row i = messages .output row i

def Language (statement : ConstraintSystem F nw nq w Equations) : Prop :=
  ∃ messages, statement.Satisfies messages

/-- Rust's `a_full`: the challenge-weighted linear coefficient at one tableau
entry. -/
def A (statement : ConstraintSystem F nw nq w Equations)
    (weights : Equations → F) (block : CoreBlock)
    (row : Fin (block.rowCount nw nq))
    (i : Fin w) : F :=
  ∑ equation, weights equation * statement.coefficient equation block row i

def combinedTarget (statement : ConstraintSystem F nw nq w Equations)
    (weights : Equations → F) : F :=
  ∑ equation, weights equation * statement.target equation

end ConstraintSystem

namespace ConstraintSystem

variable {F Equations : Type*} [Field F]
variable {nw nq w : ℕ}

/-- A false constraint system has either a nonzero linear residual vector or
a nonzero quadratic residual vector. -/
theorem false_residual
    (statement : ConstraintSystem F nw nq w Equations)
    (messages : CoreMessages F nw nq w) (hfalse : ¬statement.Language) :
    (fun equation ↦ statement.linearValue messages equation -
      statement.target equation) ≠ 0 ∨
      ∃ i, (fun row ↦ messages .left row i * messages .right row i -
        messages .output row i) ≠ 0 := by
  have hnotSatisfies : ¬statement.Satisfies messages :=
    fun hsatisfies ↦ hfalse ⟨messages, hsatisfies⟩
  rcases not_and_or.mp hnotSatisfies with hlinear | hquadratic
  · left
    intro hzero
    apply hlinear
    intro equation
    exact sub_eq_zero.mp (congrFun hzero equation)
  · right
    obtain ⟨row, hrow⟩ := not_forall.mp hquadratic
    obtain ⟨i, hnonzero⟩ := not_forall.mp hrow
    refine ⟨i, ?_⟩
    intro hzero
    exact hnonzero (sub_eq_zero.mp (congrFun hzero row))

end ConstraintSystem

structure RoundChallenge (F : Type*) (nw nq repetitions : ℕ)
    (Equations : Type*) where
  proximity : TestedRow nw nq repetitions → F
  linear : Equations → F
  quadratic : Fin nq → F

def roundChallengeEquiv (F Equations : Type*) (nw nq repetitions : ℕ) :
    RoundChallenge F nw nq repetitions Equations ≃
      (TestedRow nw nq repetitions → F) × (Equations → F) × (Fin nq → F) where
  toFun challenge :=
    (challenge.proximity, challenge.linear, challenge.quadratic)
  invFun values := ⟨values.1, values.2.1, values.2.2⟩
  left_inv challenge := by cases challenge; rfl
  right_inv values := by cases values with | mk first rest => cases rest; rfl

theorem roundChallenge_ext {F Equations : Type*} {nw nq repetitions : ℕ}
    {first second : RoundChallenge F nw nq repetitions Equations}
    (hproximity : first.proximity = second.proximity)
    (hlinear : first.linear = second.linear)
    (hquadratic : first.quadratic = second.quadratic) : first = second := by
  cases first
  cases second
  simp_all

noncomputable instance roundChallengeFintype
    {F Equations : Type*} [Fintype F] [Fintype Equations]
    {nw nq repetitions : ℕ} :
    Fintype (RoundChallenge F nw nq repetitions Equations) := by
  classical
  letI : Fintype (TestedRow nw nq repetitions) := Fintype.ofFinite _
  exact Fintype.ofEquiv
    ((TestedRow nw nq repetitions → F) × (Equations → F) × (Fin nq → F))
    (roundChallengeEquiv F Equations nw nq repetitions).symm

instance roundChallengeNonempty
    {F Equations : Type*} [Zero F] {nw nq repetitions : ℕ} :
    Nonempty (RoundChallenge F nw nq repetitions Equations) :=
  ⟨⟨0, 0, 0⟩⟩

noncomputable instance roundChallengeDecidableEq
    {F Equations : Type*} [DecidableEq F] [DecidableEq Equations]
    {nw nq repetitions : ℕ} :
    DecidableEq (RoundChallenge F nw nq repetitions Equations) := Classical.decEq _

abbrev Challenge (F : Type*) (nw nq repetitions : ℕ) (Equations : Type*) :=
  Fin repetitions → RoundChallenge F nw nq repetitions Equations

structure Response (F : Type*) (r w n repetitions : ℕ) where
  proximity : Fin repetitions → EvaluationRow F r w n
  linear : Fin repetitions → EvaluationRow F r w n
  quadratic : Fin repetitions → EvaluationRow F r w n

@[ext] theorem Response.ext {F : Type*} {r w n repetitions : ℕ}
    {first second : Response F r w n repetitions}
    (hproximity : first.proximity = second.proximity)
    (hlinear : first.linear = second.linear)
    (hquadratic : first.quadratic = second.quadratic) : first = second := by
  cases first
  cases second
  simp_all

namespace Verifier

open MultiplicativeCode

variable {F Equations : Type*} [Field F] [Fintype Equations]
variable {r w n nw nq repetitions : ℕ}

noncomputable def coefficientRow (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations) (weights : Equations → F)
    (block : CoreBlock) (row : Fin (block.rowCount nw nq)) :
    EvaluationRow F r w n :=
  C.encode 0 (statement.A weights block row)

/-- Shared evaluation-space formula for the unmasked linear response. -/
noncomputable def linearCore
    (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (weights : Equations → F)
    (core : (block : CoreBlock) → Fin (block.rowCount nw nq) →
      EvaluationRow F r w n) : EvaluationRow F r w n :=
  ∑ block : CoreBlock, ∑ row : Fin (block.rowCount nw nq),
    rowMul (coefficientRow C statement weights block row) (core block row)

/-- Shared evaluation-space formula for the two-row linear mask `V*A + Z_R*B`. -/
noncomputable def linearMask
    (C : MultiplicativeCode F r w n) (M : C.MaskingBasis)
    (mask : ConstraintMask → EvaluationRow F r w n) : EvaluationRow F r w n :=
  rowMul M.vanishing (mask .linearVCoefficient) +
    rowMul C.zR (mask .linearZRCoefficient)

/-- Shared complete linear-response formula. -/
noncomputable def linearResponse
    (C : MultiplicativeCode F r w n) (M : C.MaskingBasis)
    (statement : ConstraintSystem F nw nq w Equations)
    (weights : Equations → F)
    (core : (block : CoreBlock) → Fin (block.rowCount nw nq) →
      EvaluationRow F r w n)
    (mask : ConstraintMask → EvaluationRow F r w n) : EvaluationRow F r w n :=
  linearCore C statement weights core + linearMask C M mask

/-- Shared evaluation-space formula for the unmasked quadratic response. -/
noncomputable def quadraticCore
    (weights : Fin nq → F)
    (core : (block : CoreBlock) → Fin (block.rowCount nw nq) →
      EvaluationRow F r w n) : EvaluationRow F r w n :=
  ∑ row : Fin nq, weights row •
    (rowMul (core .left row) (core .right row) - core .output row)

/-- Shared evaluation-space formula for the quadratic mask `V*A + Z_W*B`. -/
noncomputable def quadraticMask
    (C : MultiplicativeCode F r w n) (M : C.MaskingBasis)
    (mask : ConstraintMask → EvaluationRow F r w n) : EvaluationRow F r w n :=
  rowMul M.vanishing (mask .quadraticVCoefficient) +
    rowMul C.zW (mask .quadraticZWCoefficient)

/-- Shared complete quadratic-response formula. -/
noncomputable def quadraticResponse
    (C : MultiplicativeCode F r w n) (M : C.MaskingBasis)
    (weights : Fin nq → F)
    (core : (block : CoreBlock) → Fin (block.rowCount nw nq) →
      EvaluationRow F r w n)
    (mask : ConstraintMask → EvaluationRow F r w n) : EvaluationRow F r w n :=
  quadraticCore weights core + quadraticMask C M mask

def ProximityAccepts (C : MultiplicativeCode F r w n)
    (weights : TestedRow nw nq repetitions → F)
    (response : EvaluationRow F r w n) (query : QuerySet n r)
    (opening : Opening F nw nq repetitions n r query)
    (h : Fin repetitions) : Prop :=
  response ∈ C.base ∧ ∀ j : ↥query.coordinates,
    response (codePosition j.1) =
      (∑ row : TestedRow nw nq repetitions,
        weights row * match row with
          | Sum.inl core => (opening j).core core.1 core.2
          | Sum.inr mask => (opening j).mask mask.1 mask.2) +
      (opening j).proximityBlind h

/-- Linear verification checks response-code membership, the witness-suffix
functional, and queried code evaluations.  It deliberately does not assume
that a malicious claimed response vanishes on the random prefix; zero on that
prefix is a structural fact about honest and canonical linear responses. -/
noncomputable def LinearAccepts
    (C : MultiplicativeCode F r w n) (M : C.MaskingBasis)
    (statement : ConstraintSystem F nw nq w Equations) (weights : Equations → F)
    (response : EvaluationRow F r w n) (query : QuerySet n r)
    (opening : Opening F nw nq repetitions n r query)
    (h : Fin repetitions) : Prop :=
  response ∈ C.response ∧
    (∑ i : Fin w, response (witnessPosition i)) =
      statement.combinedTarget weights ∧
    ∀ j : ↥query.coordinates,
      response (codePosition j.1) =
        (∑ block : CoreBlock,
          ∑ row : Fin (block.rowCount nw nq),
          coefficientRow C statement weights block row (codePosition j.1) *
            (opening j).core block row) +
        M.vanishing (codePosition j.1) *
          (opening j).mask h .linearVCoefficient +
        C.zR (codePosition j.1) *
          (opening j).mask h .linearZRCoefficient

def QuadraticAccepts
    (C : MultiplicativeCode F r w n) (M : C.MaskingBasis)
    (weights : Fin nq → F) (response : EvaluationRow F r w n)
    (query : QuerySet n r)
    (opening : Opening F nw nq repetitions n r query)
    (h : Fin repetitions) : Prop :=
  response ∈ C.response ∧
    (∀ i : Fin w, response (witnessPosition i) = 0) ∧
    ∀ j : ↥query.coordinates,
      response (codePosition j.1) =
        (∑ row : Fin nq, weights row *
          ((opening j).core .left row * (opening j).core .right row -
            (opening j).core .output row)) +
        M.vanishing (codePosition j.1) *
          (opening j).mask h .quadraticVCoefficient +
        C.zW (codePosition j.1) *
          (opening j).mask h .quadraticZWCoefficient

noncomputable def Accepts
    (C : MultiplicativeCode F r w n) (M : C.MaskingBasis)
    (statement : ConstraintSystem F nw nq w Equations)
    (challenge : Challenge F nw nq repetitions Equations)
    (response : Response F r w n repetitions) (query : QuerySet n r)
    (opening : Opening F nw nq repetitions n r query) : Prop :=
  ∀ h : Fin repetitions,
    ProximityAccepts C (challenge h).proximity (response.proximity h)
        query opening h ∧
      LinearAccepts C M statement (challenge h).linear (response.linear h)
        query opening h ∧
      QuadraticAccepts C M (challenge h).quadratic (response.quadratic h)
        query opening h

end Verifier

end Ligero.Common
