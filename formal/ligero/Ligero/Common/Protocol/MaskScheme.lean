import Ligero.Common.Protocol.Basic


















namespace Ligero.Common



inductive NoMask : Type
  deriving DecidableEq, Fintype

instance : IsEmpty NoMask := ⟨fun mask ↦ nomatch mask⟩

namespace NoMask

universe u

/-- Eliminate the empty mask index into any sort. -/
def elim {α : Sort u} (mask : NoMask) : α := nomatch mask

end NoMask

/-- The two direct response masks committed by V1. -/
inductive V1Mask
  | linear
  | quadratic
  deriving DecidableEq, Fintype

/-- Rows covered by the common proximity test for a mask representation. -/
abbrev SchemeTestedRow (CheckedMask : Type*) (nw nq repetitions : ℕ) :=
  CoreRow nw nq ⊕ (Fin repetitions × CheckedMask)

/-- A normal statement has at least one committed core row.  This explicit
shape fact is the public premise used by V1 selected-MCA soundness, rather
than exposing an implementation-level `Nonempty` typeclass. -/
def CoreRowsNonempty (nw nq : ℕ) : Prop := 0 < nw ∨ 0 < nq

/-- Construct an inhabitant of the common tested-row type from statement
well-formedness, independently of the mask representation. -/
@[reducible] def schemeTestedRowNonemptyOfCoreRows
    {CheckedMask : Type*} {nw nq repetitions : ℕ}
    (hrows : CoreRowsNonempty nw nq) :
    Nonempty (SchemeTestedRow CheckedMask nw nq repetitions) := by
  rcases hrows with hnw | hnq
  · exact ⟨Sum.inl ⟨.linear, ⟨0, hnw⟩⟩⟩
  · exact ⟨Sum.inl ⟨.left, ⟨0, hnq⟩⟩⟩

/-- A commitment in the common architecture.  `checkedMask` participates in
the common proximity test; `directMask` is committed before the challenge but
is deliberately absent from that test. -/
structure SchemeOracle (F CheckedMask DirectMask : Type*)
    (nw nq n repetitions : ℕ) where
  core : (block : CoreBlock) → Fin (block.rowCount nw nq) → Fin n → F
  checkedMask : Fin repetitions → CheckedMask → Fin n → F
  directMask : Fin repetitions → DirectMask → Fin n → F
  proximityBlind : Fin repetitions → Fin n → F

/-- One opened column of a scheme-parametric commitment. -/
structure SchemeColumn (F CheckedMask DirectMask : Type*)
    (nw nq repetitions : ℕ) where
  core : (block : CoreBlock) → Fin (block.rowCount nw nq) → F
  checkedMask : Fin repetitions → CheckedMask → F
  directMask : Fin repetitions → DirectMask → F
  proximityBlind : Fin repetitions → F

@[ext] theorem SchemeColumn.ext
    {F CheckedMask DirectMask : Type*} {nw nq repetitions : ℕ}
    {first second : SchemeColumn F CheckedMask DirectMask nw nq repetitions}
    (hcore : first.core = second.core)
    (hchecked : first.checkedMask = second.checkedMask)
    (hdirect : first.directMask = second.directMask)
    (hproximity : first.proximityBlind = second.proximityBlind) :
    first = second := by
  cases first
  cases second
  simp_all

namespace SchemeOracle

def testedRow {F CheckedMask DirectMask : Type*}
    {nw nq n repetitions : ℕ}
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n repetitions) :
    SchemeTestedRow CheckedMask nw nq repetitions → CodingTheory.Word F n
  | Sum.inl row => oracle.core row.1 row.2
  | Sum.inr row => oracle.checkedMask row.1 row.2

def column {F CheckedMask DirectMask : Type*}
    {nw nq n repetitions : ℕ}
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n repetitions)
    (j : Fin n) : SchemeColumn F CheckedMask DirectMask nw nq repetitions where
  core block row := oracle.core block row j
  checkedMask h kind := oracle.checkedMask h kind j
  directMask h kind := oracle.directMask h kind j
  proximityBlind h := oracle.proximityBlind h j

end SchemeOracle

abbrev SchemeOpening (F CheckedMask DirectMask : Type*)
    (nw nq repetitions n r : ℕ) (query : QuerySet n r) :=
  (j : ↥query.coordinates) →
    SchemeColumn F CheckedMask DirectMask nw nq repetitions

def openSchemeOracle {F CheckedMask DirectMask : Type*}
    {nw nq n repetitions r : ℕ}
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n repetitions)
    (query : QuerySet n r) :
    SchemeOpening F CheckedMask DirectMask nw nq repetitions n r query :=
  fun j ↦ oracle.column j.1



structure MaskScheme (F CheckedMask DirectMask : Type*) (r w n : ℕ) where
  linearAt : Position r w n → (CheckedMask → F) → (DirectMask → F) → F
  quadraticAt : Position r w n → (CheckedMask → F) → (DirectMask → F) → F

namespace MaskScheme

variable {F : Type*} [Field F]
variable {r w n : ℕ}

/-- Ligero.Common's checked four-row mask representation. -/
noncomputable def checked
    (C : MultiplicativeCode F r w n) (M : C.MaskingBasis) :
    MaskScheme F ConstraintMask NoMask r w n where
  linearAt position mask _ :=
    M.vanishing position * mask .linearVCoefficient +
      C.zR position * mask .linearZRCoefficient
  quadraticAt position mask _ :=
    M.vanishing position * mask .quadraticVCoefficient +
      C.zW position * mask .quadraticZWCoefficient

/-- V1's direct, unchecked response-code masks. -/
def v1 : MaskScheme F NoMask V1Mask r w n where
  linearAt _ _ mask := mask .linear
  quadraticAt _ _ mask := mask .quadratic

end MaskScheme



structure SchemeRoundChallenge (F CheckedMask : Type*)
    (nw nq repetitions : ℕ) (Equations : Type*) where
  proximity : SchemeTestedRow CheckedMask nw nq repetitions → F
  linear : Equations → F
  quadratic : Fin nq → F

instance schemeRoundChallengeNonempty
    {F CheckedMask Equations : Type*} [Zero F]
    {nw nq repetitions : ℕ} :
    Nonempty (SchemeRoundChallenge F CheckedMask nw nq repetitions Equations) :=
  ⟨⟨0, 0, 0⟩⟩

def schemeRoundChallengeEquiv
    (F CheckedMask Equations : Type*) (nw nq repetitions : ℕ) :
    SchemeRoundChallenge F CheckedMask nw nq repetitions Equations ≃
      (SchemeTestedRow CheckedMask nw nq repetitions → F) ×
        (Equations → F) × (Fin nq → F) where
  toFun challenge := (challenge.proximity, challenge.linear, challenge.quadratic)
  invFun values := ⟨values.1, values.2.1, values.2.2⟩
  left_inv challenge := by cases challenge; rfl
  right_inv values := by rcases values with ⟨proximity, linear, quadratic⟩; rfl

noncomputable instance schemeRoundChallengeFintype
    {F CheckedMask Equations : Type*}
    [Fintype F] [Fintype CheckedMask] [Fintype Equations]
    {nw nq repetitions : ℕ} :
    Fintype (SchemeRoundChallenge F CheckedMask nw nq repetitions Equations) := by
  letI : Fintype (SchemeTestedRow CheckedMask nw nq repetitions) :=
    Fintype.ofFinite _
  letI : Fintype
      ((SchemeTestedRow CheckedMask nw nq repetitions → F) ×
        (Equations → F) × (Fin nq → F)) := Fintype.ofFinite _
  exact Fintype.ofEquiv
    ((SchemeTestedRow CheckedMask nw nq repetitions → F) ×
      (Equations → F) × (Fin nq → F))
    (schemeRoundChallengeEquiv F CheckedMask Equations nw nq repetitions).symm

noncomputable instance schemeRoundChallengeDecidableEq
    {F CheckedMask Equations : Type*}
    [DecidableEq F] [DecidableEq CheckedMask] [DecidableEq Equations]
    {nw nq repetitions : ℕ} :
    DecidableEq
      (SchemeRoundChallenge F CheckedMask nw nq repetitions Equations) :=
  Classical.decEq _

abbrev SchemeChallenge (F CheckedMask : Type*)
    (nw nq repetitions : ℕ) (Equations : Type*) :=
  Fin repetitions → SchemeRoundChallenge F CheckedMask nw nq repetitions Equations

/- Stable public instantiations.  These aliases keep callers on the common
row layout while making the sole mask-representation choice explicit. -/
abbrev V1Scheme (F : Type*) (r w n : ℕ) :=
  MaskScheme F NoMask V1Mask r w n

abbrev V1Oracle (F : Type*) (nw nq n repetitions : ℕ) :=
  SchemeOracle F NoMask V1Mask nw nq n repetitions

abbrev V1Challenge (F : Type*) (nw nq repetitions : ℕ) (Equations : Type*) :=
  SchemeChallenge F NoMask nw nq repetitions Equations

abbrev V1Opening (F : Type*) (nw nq repetitions n r : ℕ)
    (query : QuerySet n r) :=
  SchemeOpening F NoMask V1Mask nw nq repetitions n r query

namespace SchemeVerifier

open MultiplicativeCode

variable {F Equations CheckedMask DirectMask : Type*}
variable [Field F] [Fintype Equations] [Fintype CheckedMask]
variable {r w n nw nq repetitions : ℕ}

def ProximityAccepts (C : MultiplicativeCode F r w n)
    (weights : SchemeTestedRow CheckedMask nw nq repetitions → F)
    (response : EvaluationRow F r w n) (query : QuerySet n r)
    (opening : SchemeOpening F CheckedMask DirectMask nw nq repetitions n r query)
    (h : Fin repetitions) : Prop :=
  response ∈ C.base ∧ ∀ j : ↥query.coordinates,
    response (codePosition j.1) =
      (∑ row : SchemeTestedRow CheckedMask nw nq repetitions,
        weights row * match row with
          | Sum.inl core => (opening j).core core.1 core.2
          | Sum.inr mask => (opening j).checkedMask mask.1 mask.2) +
      (opening j).proximityBlind h

noncomputable def LinearAccepts
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations) (weights : Equations → F)
    (response : EvaluationRow F r w n) (query : QuerySet n r)
    (opening : SchemeOpening F CheckedMask DirectMask nw nq repetitions n r query)
    (h : Fin repetitions) : Prop :=
  response ∈ C.response ∧
    (∑ i : Fin w, response (witnessPosition i)) =
      statement.combinedTarget weights ∧
    ∀ j : ↥query.coordinates,
      response (codePosition j.1) =
        (∑ block : CoreBlock,
          ∑ row : Fin (block.rowCount nw nq),
          Verifier.coefficientRow C statement weights block row
              (codePosition j.1) * (opening j).core block row) +
        scheme.linearAt (codePosition j.1)
          ((opening j).checkedMask h) ((opening j).directMask h)

def QuadraticAccepts
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (weights : Fin nq → F) (response : EvaluationRow F r w n)
    (query : QuerySet n r)
    (opening : SchemeOpening F CheckedMask DirectMask nw nq repetitions n r query)
    (h : Fin repetitions) : Prop :=
  response ∈ C.response ∧
    (∀ i : Fin w, response (witnessPosition i) = 0) ∧
    ∀ j : ↥query.coordinates,
      response (codePosition j.1) =
        (∑ row : Fin nq, weights row *
          ((opening j).core .left row * (opening j).core .right row -
            (opening j).core .output row)) +
        scheme.quadraticAt (codePosition j.1)
          ((opening j).checkedMask h) ((opening j).directMask h)

noncomputable def Accepts
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (challenge : SchemeChallenge F CheckedMask nw nq repetitions Equations)
    (response : Response F r w n repetitions) (query : QuerySet n r)
    (opening : SchemeOpening F CheckedMask DirectMask nw nq repetitions n r query) : Prop :=
  ∀ h : Fin repetitions,
    ProximityAccepts C (challenge h).proximity (response.proximity h)
        query opening h ∧
      LinearAccepts C scheme statement (challenge h).linear (response.linear h)
        query opening h ∧
      QuadraticAccepts C scheme (challenge h).quadratic (response.quadratic h)
        query opening h

end SchemeVerifier


def Oracle.asScheme {F : Type*} {nw nq n repetitions : ℕ}
    (oracle : Oracle F nw nq n repetitions) :
    SchemeOracle F ConstraintMask NoMask nw nq n repetitions where
  core := oracle.core
  checkedMask := oracle.mask
  directMask _ impossible := NoMask.elim impossible
  proximityBlind := oracle.proximityBlind


def Opening.asScheme {F : Type*} {nw nq repetitions n r : ℕ}
    {query : QuerySet n r} (opening : Opening F nw nq repetitions n r query) :
    SchemeOpening F ConstraintMask NoMask nw nq repetitions n r query :=
  fun j ↦ {
    core := (opening j).core
    checkedMask := (opening j).mask
    directMask := fun _ impossible ↦ NoMask.elim impossible
    proximityBlind := (opening j).proximityBlind }

theorem openOracle_asScheme {F : Type*} {nw nq repetitions n r : ℕ}
    (oracle : Oracle F nw nq n repetitions) (query : QuerySet n r) :
    openSchemeOracle oracle.asScheme query =
      (openOracle oracle query).asScheme := by
  funext j
  apply SchemeColumn.ext
  · rfl
  · rfl
  · funext _ impossible
    exact NoMask.elim impossible
  · rfl


def RoundChallenge.asScheme {F Equations : Type*} {nw nq repetitions : ℕ}
    (challenge : RoundChallenge F nw nq repetitions Equations) :
    SchemeRoundChallenge F ConstraintMask nw nq repetitions Equations where
  proximity := challenge.proximity
  linear := challenge.linear
  quadratic := challenge.quadratic

def challengeAsScheme {F Equations : Type*} {nw nq repetitions : ℕ}
    (challenge : Challenge F nw nq repetitions Equations) :
    SchemeChallenge F ConstraintMask nw nq repetitions Equations :=
  fun h ↦ (challenge h).asScheme

def schemeChallengeAsChecked {F Equations : Type*} {nw nq repetitions : ℕ}
    (challenge : SchemeChallenge F ConstraintMask nw nq repetitions Equations) :
    Challenge F nw nq repetitions Equations :=
  fun h ↦ {
    proximity := (challenge h).proximity
    linear := (challenge h).linear
    quadratic := (challenge h).quadratic }


def checkedChallengeEquiv (F Equations : Type*) (nw nq repetitions : ℕ) :
    Challenge F nw nq repetitions Equations ≃
      SchemeChallenge F ConstraintMask nw nq repetitions Equations where
  toFun := challengeAsScheme
  invFun := schemeChallengeAsChecked
  left_inv challenge := by rfl
  right_inv challenge := by rfl

/-- The checked instantiation is definitionally the existing Ligero.Common
verifier.  This is the compatibility theorem which lets the current proof
stack remain unchanged while new arguments use `MaskScheme`. -/
theorem checked_accepts_iff
    {F Equations : Type*} [Field F] [Fintype Equations]
    {r w n nw nq repetitions : ℕ}
    (C : MultiplicativeCode F r w n) (M : C.MaskingBasis)
    (statement : ConstraintSystem F nw nq w Equations)
    (challenge : Challenge F nw nq repetitions Equations)
    (response : Response F r w n repetitions) (query : QuerySet n r)
    (opening : Opening F nw nq repetitions n r query) :
    SchemeVerifier.Accepts C (MaskScheme.checked C M) statement
        (challengeAsScheme challenge) response query opening.asScheme ↔
      Verifier.Accepts C M statement challenge response query opening := by
  constructor
  · intro haccept h
    refine ⟨?_, ?_, ?_⟩
    · simpa [SchemeVerifier.ProximityAccepts, Verifier.ProximityAccepts,
        challengeAsScheme, RoundChallenge.asScheme, Opening.asScheme] using
        (haccept h).1
    · simpa [SchemeVerifier.LinearAccepts, Verifier.LinearAccepts,
        MaskScheme.checked, challengeAsScheme, RoundChallenge.asScheme,
        Opening.asScheme, add_assoc] using (haccept h).2.1
    · simpa [SchemeVerifier.QuadraticAccepts, Verifier.QuadraticAccepts,
        MaskScheme.checked, challengeAsScheme, RoundChallenge.asScheme,
        Opening.asScheme, add_assoc] using (haccept h).2.2
  · intro haccept h
    refine ⟨?_, ?_, ?_⟩
    · simpa [SchemeVerifier.ProximityAccepts, Verifier.ProximityAccepts,
        challengeAsScheme, RoundChallenge.asScheme, Opening.asScheme] using
        (haccept h).1
    · simpa [SchemeVerifier.LinearAccepts, Verifier.LinearAccepts,
        MaskScheme.checked, challengeAsScheme, RoundChallenge.asScheme,
        Opening.asScheme, add_assoc] using (haccept h).2.1
    · simpa [SchemeVerifier.QuadraticAccepts, Verifier.QuadraticAccepts,
        MaskScheme.checked, challengeAsScheme, RoundChallenge.asScheme,
        Opening.asScheme, add_assoc] using (haccept h).2.2

end Ligero.Common
