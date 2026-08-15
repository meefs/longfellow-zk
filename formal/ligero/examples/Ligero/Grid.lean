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

/-- The protocol-neutral point represented by a Ligero certificate. -/
def Certificate.point (certificate : Certificate) : Examples.GridPoint :=
  { n := certificate.n
    k := certificate.k
    d := certificate.d
    e := certificate.e
    fieldBits := certificate.fieldBits
    targetBits := certificate.targetBits }


abbrev V1Certificate := Certificate
def Certificate.fieldSize (c : Certificate) : ℕ := 2 ^ c.fieldBits

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
  have hmaster := Ligero.V1.v1_ligero_soundness_selectedMCA
    hrows C statement hfalse prover hmin (by
      simpa [Certificate.conditions, hfield] using hconditions)
      (c.v1JohnsonRange hkpos hresponse C hk)
  simpa [V1Certificate.v1Soundness, Certificate.failureContribution,
    Certificate.failureProfile, V1Certificate.v1Profile,
    Certificate.fieldSize, Certificate.lineBound, Certificate.listSize,
    Certificate.v1Threshold, hfield, hk] using hmaster

end Ligero.Examples.Grid
