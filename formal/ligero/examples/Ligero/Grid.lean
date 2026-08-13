import Ligero.MaskV1.Soundness.V1EndToEnd
import Ligero.Code.UnifiedReedSolomonAnalysis

/-!
# Exhaustive opening-count grid

The generated files below cover every requested block length, nominal rate,
field-size lower bound, and soundness target.  Common certificate data is
normalized: derived quantities are functions, and only V1 certificates carry
V1 range data.
-/

namespace Ligero.Examples.Grid

open Ligero.Common

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

/-- V1-only unchecked Johnson range data. -/
structure V1Certificate extends Certificate where
  /-- Largest unchecked Johnson bound at the first V1 range. -/
  v1FirstBound : ℕ
  /-- Last agreement coordinate in the first bounded V1 range. -/
  v1Middle : ℕ
  /-- Last agreement coordinate in the `≤ 3` V1 range. -/
  v1Last : ℕ


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

abbrev common (c : V1Certificate) : Certificate := c.toCertificate
abbrev fieldSize (c : V1Certificate) : ℕ := c.common.fieldSize
abbrev lineBound (c : V1Certificate) : ℕ := c.common.lineBound
abbrev listSize (c : V1Certificate) : ℕ := c.common.listSize
abbrev v1Threshold (c : V1Certificate) : ℕ := c.common.v1Threshold
abbrev failureProfile (c : V1Certificate) := c.common.failureProfile

def v1Profile (c : V1Certificate) : AgreementProfile c.n :=
  uncheckedAgreementProfile c.fieldSize c.n (2 * c.k - 1) c.listSize
    c.v1Threshold

theorem v1JohnsonRange (c : V1Certificate)
    (hkpos : 0 < c.k) (hresponse : 2 * c.k ≤ c.n)
    {F : Type*} [_root_.Field F] {openings w : ℕ}
    (C : MultiplicativeCode F openings w c.n) (hk : C.k = c.k) :
    Ligero.MaskV1.V1JohnsonRange C c.v1Threshold := by
  unfold V1Certificate.v1Threshold V1Certificate.common
    Certificate.v1Threshold
  apply Ligero.MaskV1.V1JohnsonRange.ofSquare C
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
  c.common.failureContribution queries +
    c.v1Profile.contribution c.fieldSize c.n c.e c.g queries

/-- Closed-form three-band upper certificate for selected-MCA failure. -/
def Certificate.failureEnvelope (c : Certificate) (queries : ℕ) : ℚ :=
  AgreementProfile.coverRatio c.n c.n 0 queries 0 +
    ((c.lineBound : ℚ) / ((c.fieldSize - (c.g + 1) : ℕ) : ℚ)) *
      AgreementProfile.coverRatio c.n c.n 0 queries
        (c.n - (c.d - 1) / 3 - 1) +
    ((1 + (c.d - 1) / 3 / (c.g + 1) : ℕ) : ℚ) /
      ((c.fieldSize - (c.g + 1) : ℕ) : ℚ) *
      AgreementProfile.coverRatio c.n c.n 0 queries (c.n - c.g - 1) +
    ((1 : ℚ) / ((c.fieldSize - (c.g + 1) : ℕ) : ℚ)) *
      AgreementProfile.coverRatio c.n c.n 0 queries c.n


/-- Closed-form four-band V1 certificate whose minimum is reported. -/
def V1Certificate.v1Envelope (c : V1Certificate) (queries : ℕ) : ℚ :=
  c.common.failureEnvelope queries +
    AgreementProfile.coverRatio c.n c.e c.g queries (c.v1Threshold - 1) +
    ((c.listSize * c.v1FirstBound : ℕ) : ℚ) / c.fieldSize *
      AgreementProfile.coverRatio c.n c.e c.g queries c.v1Middle +
    ((c.listSize * 3 : ℕ) : ℚ) / c.fieldSize *
      AgreementProfile.coverRatio c.n c.e c.g queries c.v1Last +
    (c.listSize : ℚ) / c.fieldSize *
      AgreementProfile.coverRatio c.n c.e c.g queries c.n

theorem coverRatio_antitone (n e g cutoff : ℕ) :
    Antitone (fun queries ↦ AgreementProfile.coverRatio n e g queries cutoff) := by
  unfold AgreementProfile.coverRatio
  exact hypergeometricRatio_antitone_query _ _ (by omega)

private theorem weighted_coverRatio_antitone
    (u : ℚ) (hu : 0 ≤ u) (n e g cutoff : ℕ) :
    Antitone (fun queries ↦
      u * AgreementProfile.coverRatio n e g queries cutoff) := by
  intro a b hab
  exact mul_le_mul_of_nonneg_left (coverRatio_antitone n e g cutoff hab) hu

private theorem natRatio_nonnegative (a b : ℕ) : 0 ≤ (a : ℚ) / b := by
  exact div_nonneg (by positivity) (by positivity)

theorem Certificate.failureEnvelope_antitone (c : Certificate) :
    Antitone c.failureEnvelope := by
  intro a b hab
  have h0 := coverRatio_antitone c.n c.n 0 0 hab
  have h1 := weighted_coverRatio_antitone
    ((c.lineBound : ℚ) / ((c.fieldSize - (c.g + 1) : ℕ) : ℚ))
      (natRatio_nonnegative ..)
    c.n c.n 0 (c.n - (c.d - 1) / 3 - 1) hab
  have h2 := weighted_coverRatio_antitone
    (((1 + (c.d - 1) / 3 / (c.g + 1) : ℕ) : ℚ) /
      ((c.fieldSize - (c.g + 1) : ℕ) : ℚ)) (natRatio_nonnegative ..)
    c.n c.n 0 (c.n - c.g - 1) hab
  have h3 := weighted_coverRatio_antitone
    ((1 : ℚ) / ((c.fieldSize - (c.g + 1) : ℕ) : ℚ))
      (natRatio_nonnegative ..)
    c.n c.n 0 c.n hab
  unfold Certificate.failureEnvelope
  exact add_le_add (add_le_add (add_le_add h0 h1) h2) h3

theorem V1Certificate.v1Envelope_antitone (c : V1Certificate) :
    Antitone c.v1Envelope := by
  intro a b hab
  have hf := c.common.failureEnvelope_antitone hab
  have h0 := coverRatio_antitone c.n c.e c.g (c.v1Threshold - 1) hab
  have h1 := weighted_coverRatio_antitone
    (((c.listSize * c.v1FirstBound : ℕ) : ℚ) / c.fieldSize) (by positivity)
    c.n c.e c.g c.v1Middle hab
  have h2 := weighted_coverRatio_antitone
    (((c.listSize * 3 : ℕ) : ℚ) / c.fieldSize) (by positivity)
    c.n c.e c.g c.v1Last hab
  have h3 := weighted_coverRatio_antitone
    ((c.listSize : ℚ) / c.fieldSize) (by positivity)
    c.n c.e c.g c.n hab
  unfold V1Certificate.v1Envelope
  exact add_le_add (add_le_add (add_le_add (add_le_add hf h0) h1) h2) h3

theorem minimum_of_antitone_certificate
    (bound : ℕ → ℚ) (opening targetBits : ℕ) (hopen : 0 < opening)
    (hmono : Antitone bound)
    (hsuccess : bound opening ≤ (1 : ℚ) / 2 ^ targetBits)
    (hprevious : (1 : ℚ) / 2 ^ targetBits < bound (opening - 1)) :
    bound opening ≤ (1 : ℚ) / 2 ^ targetBits ∧
      ∀ t < opening, (1 : ℚ) / 2 ^ targetBits < bound t := by
  refine ⟨hsuccess, ?_⟩
  intro t ht
  exact hprevious.trans_le (hmono (by omega))

def Certificate.conditions (c : Certificate) : Prop :=
  SelectedMCAParameterConditions c.fieldSize c.n c.e c.g c.d c.m

abbrev V1Certificate.conditions (c : V1Certificate) : Prop :=
  c.common.conditions

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
      (V1Oracle F nw nq c.n 1) (V1Challenge F nw nq 1 Equations)
      (Response F c.openings w c.n 1))
    (hmin : CodingTheory.HasMinimumDistanceAtLeast C.baseCode c.d) :
    (SchemeVerifier.protocol C MaskScheme.v1).acceptanceRate prover statement ≤
      c.v1Soundness c.openings := by
  have hmaster := Ligero.MaskV1.v1_ligero_soundness_selectedMCA
    hrows C statement hfalse prover hmin (by
      simpa [Certificate.conditions, hfield] using hconditions)
      (c.v1JohnsonRange hkpos hresponse C hk)
  simpa [V1Certificate.v1Soundness, Certificate.failureContribution,
    Certificate.failureProfile, V1Certificate.v1Profile,
    Certificate.fieldSize, Certificate.lineBound, Certificate.listSize,
    Certificate.v1Threshold, hfield, hk] using hmaster

end Ligero.Examples.Grid
