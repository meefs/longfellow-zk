import JBAgreement.LigeroCode
import Ligero.V1.Soundness.V1EndToEnd
import examples.Grid









namespace Ligero.Examples.Grid

open LigeroFamily

set_option maxHeartbeats 1000000

structure Certificate where
  n : ℕ
  k : ℕ
  d : ℕ
  e : ℕ
  g : ℕ
  m : ℕ
  fieldBits : ℕ
  targetBits : ℕ
  openings : ℕ
  /-- Exact field cardinality, when it is not `2 ^ fieldBits`.

  Zero means "binary", i.e. `2 ^ fieldBits`, which is what every committed row
  uses -- so the field is defaulted and those rows are unchanged.  A nonzero
  value carries the order itself, which is what a prime-order field needs: the
  soundness expressions read the field only through `fieldSize`, so nothing else
  in the grid changes.  A prime order additionally means large characteristic,
  the hypothesis the eta-squared and Sudan routes need and a binary field can
  never satisfy. -/
  fieldOrder : ℕ := 0

/-- The protocol-neutral point represented by a Ligero certificate. -/
def Certificate.point (certificate : Certificate) : Examples.GridPoint :=
  { n := certificate.n
    k := certificate.k
    d := certificate.d
    e := certificate.e
    fieldBits := certificate.fieldBits
    targetBits := certificate.targetBits }


abbrev V1Certificate := Certificate
def Certificate.fieldSize (c : Certificate) : ℕ :=
  if c.fieldOrder = 0 then 2 ^ c.fieldBits else c.fieldOrder

def Certificate.lineBound (c : Certificate) : ℕ :=
  SelectedMCA.directLineFailureBound c.m

def Certificate.listSize (c : Certificate) : ℕ :=
  CodingTheory.InterleavedJohnson.listBound c.n c.d (c.e + c.g)

def Certificate.v1Threshold (c : Certificate) : ℕ :=
  Nat.sqrt (c.n * (2 * c.k - 1)) + 1

def Certificate.failureProfile (c : Certificate) : AgreementProfile c.n :=
  SchemeSelectedMCA.selectedMCAFailureProfile c.n c.g c.d c.lineBound

namespace V1Certificate

def v1Profile (c : V1Certificate) : AgreementProfile c.n :=
  uncheckedAgreementProfile c.fieldSize c.n (2 * c.k - 1) c.listSize
    c.v1Threshold

theorem v1JohnsonRange (c : V1Certificate)
    (hkpos : 0 < c.k) (hresponse : 2 * c.k ≤ c.n)
    {F : Type*} [_root_.Field F] {openings w : ℕ}
    (C : MultiplicativeCode F openings w c.n) (hk : C.k = c.k) :
    Ligero.V1.V1JohnsonRange C c.v1Threshold := by
  unfold Certificate.v1Threshold
  apply Ligero.V1.V1JohnsonRange.ofSquare C
    (Nat.sqrt (c.n * (2 * c.k - 1)) + 1)
  · omega
  · rw [hk]
    exact hresponse
  · rw [hk]
    have hsqrt : 2 * c.k - 1 ≤ Nat.sqrt (c.n * (2 * c.k - 1)) := by
      apply Nat.le_sqrt.mpr
      have hcutoff : 2 * c.k - 1 ≤ c.n := by omega
      simpa [Nat.mul_comm] using
        Nat.mul_le_mul_right (2 * c.k - 1) hcutoff
    omega
  · rw [hk]
    simpa [Nat.succ_eq_add_one] using Nat.lt_succ_sqrt (c.n * (2 * c.k - 1))

end V1Certificate

def Certificate.failureContribution (c : Certificate) (queries : ℕ) : ℚ :=
  c.failureProfile.contribution (c.fieldSize - (c.g + 1)) c.n c.n 0 queries

def V1Certificate.v1Soundness (c : V1Certificate) (queries : ℕ) : ℚ :=
  c.failureContribution queries +
    c.v1Profile.contribution c.fieldSize c.n c.e c.g queries



/-- Executable form of the exact V1 bound. -/
def V1Certificate.compressedV1Soundness
    (c : V1Certificate) (queries : ℕ) : ℚ :=
  c.failureProfile.compressedContribution
      (c.fieldSize - (c.g + 1)) c.n c.n 0 queries +
    c.v1Profile.compressedContribution c.fieldSize c.n c.e c.g queries

theorem V1Certificate.compressedV1Soundness_eq
    (c : V1Certificate) (queries : ℕ) :
    c.compressedV1Soundness queries = c.v1Soundness queries := by
  simp only [compressedV1Soundness, v1Soundness, Certificate.failureContribution]
  rw [AgreementProfile.contribution_eq_compressedContribution,
    AgreementProfile.contribution_eq_compressedContribution]

/-- **The Johnson-route conditions of a certificate.**  The punctured and
lift-list conditions are the clique route's; the clique condition itself is
replaced by a checked Johnson certificate at `η = 1 / 2 ^ etaBits`, with the
certificate's `lineBound` as the bad-parameter count.

A Johnson row stores its line bound in `m` exactly as a clique row does -- the
soundness expression reads `lineBound = m - 1` either way -- so the two routes
produce comparable certificates and only the checked conditions differ. -/
def Certificate.johnsonConditions (c : Certificate) (etaBits : ℕ) : Bool :=
  JBAgreement.johnsonConditionsBool c.n (c.k - 1) c.e etaBits c.lineBound
      c.fieldSize &&
    (3 * c.g < c.d - c.e) && (c.g + 1 < c.fieldSize) &&
    decide (0 < CodingTheory.InterleavedJohnson.denominator c.n c.d (c.e + c.g))

/-- The Johnson-route certificate reaches the same route-agnostic bundle the
masters consume, given a Reed–Solomon presentation of the base code. -/
theorem Certificate.johnsonLineConditions (c : Certificate) {etaBits : ℕ}
    {F : Type*} [_root_.Field F] [Fintype F] [DecidableEq F]
    {C : CodingTheory.LinearCode F c.n}
    (P : JBAgreement.RSPresentation c.n (c.k - 1) C)
    (hfield : Fintype.card F = c.fieldSize)
    (h : c.johnsonConditions etaBits = true) :
    LigeroFamily.SelectedMCALineConditions C c.fieldSize c.e c.g c.d
      c.lineBound := by
  simp only [Certificate.johnsonConditions, Bool.and_eq_true,
    decide_eq_true_eq] at h
  exact
    { line := JBAgreement.lineFailureBound_of_johnsonConditions P hfield
        (JBAgreement.johnsonConditions_of_bool h.1.1.1)
      punctured := ⟨h.1.1.2, h.1.2⟩
      johnson := ⟨h.2⟩ }

def Certificate.conditions (c : Certificate) : Prop :=
  SelectedMCAParameterConditions c.fieldSize c.n c.e c.g c.d c.m

theorem V1Certificate.v1_protocol_soundness
    (c : V1Certificate) (hconditions : c.conditions)
    {F Equations : Type*} [_root_.Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    {w nw nq : ℕ}
    (hrows : CoreRowsNonempty nw nq)
    (hfield : Fintype.card F = c.fieldSize)
    (C : MultiplicativeCode F c.openings w c.n) (hk : C.k = c.k)
    (hkpos : 0 < c.k) (hresponse : 2 * c.k ≤ c.n)
    (statement : ConstraintSystem F nw nq w Equations)
    (hfalse : ¬statement.Language)
    (prover : IPCPProver
      (ConstraintSystem F nw nq w Equations)
      (Ligero.V1.Oracle F nw nq c.n 1)
      (Ligero.V1.Challenge F nw nq 1 Equations)
      (Response F c.openings w c.n 1))
    (hmin : CodingTheory.HasMinimumDistanceAtLeast C.baseCode c.d) :
    (SchemeVerifier.protocol C Ligero.V1.scheme).acceptanceRate prover
      statement ≤
      c.v1Soundness c.openings := by
  have hnumeric : LigeroFamily.SelectedMCAParameterConditions
      (Fintype.card F) c.n c.e c.g c.d c.m := by
    simpa [Certificate.conditions, hfield] using hconditions
  have hmaster := Ligero.V1.v1_ligero_soundness_selectedMCA
    hrows C statement prover (LigeroFamily.NoDecodedSolution.of_not_language hfalse)
    hmin (hnumeric.lineConditions hmin)
      (c.v1JohnsonRange hkpos hresponse C hk)
  simpa [V1Certificate.v1Soundness, Certificate.failureContribution,
    Certificate.failureProfile, V1Certificate.v1Profile,
    Certificate.fieldSize, Certificate.lineBound, Certificate.listSize,
    Certificate.v1Threshold, hfield, hk] using hmaster

end Ligero.Examples.Grid
