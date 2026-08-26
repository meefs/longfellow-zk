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
  /-- Agreement cutoff for the refined MCA profile.  Zero selects the
  conservative endpoint `n - e`, preserving legacy certificate data. -/
  cutoff : ℕ := 0
  /-- Local line-failure threshold above `cutoff`.  Zero reuses `m`. -/
  localM : ℕ := 0
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

def Certificate.refinedCutoff (c : Certificate) : ℕ :=
  if c.cutoff = 0 then c.n - c.e else c.cutoff

def Certificate.refinedLocalM (c : Certificate) : ℕ :=
  if c.localM = 0 then c.m else c.localM

def Certificate.localLineBound (c : Certificate) : ℕ :=
  SelectedMCA.directLineFailureBound c.refinedLocalM

/-- Fuel-bounded binary search for a direct-clique threshold.  The result is
not trusted: every concrete grid theorem checks both the returned condition
and failure of its predecessor.  Sixty-four rounds cover all stored search
caps while keeping native validation logarithmic. -/
def binaryCliqueSearch (n radius g d : ℕ) : ℕ → ℕ → ℕ → ℕ
  | 0, _lo, hi => hi
  | fuel + 1, lo, hi =>
      if lo < hi then
        let mid := (lo + hi) / 2
        if decide (SelectedMCA.DirectCliqueCondition n radius g d mid) then
          binaryCliqueSearch n radius g d fuel lo mid
        else
          binaryCliqueSearch n radius g d fuel (mid + 1) hi
      else hi

/-- Pointwise direct-clique threshold at actual agreement `a`. -/
def Certificate.integratedLocalM (c : Certificate) (a : ℕ) : ℕ :=
  if 3 * (c.n - a) < c.d then c.m
  else binaryCliqueSearch c.n (c.n - a) c.g c.d 64 3
    (max c.m c.refinedLocalM)

def Certificate.integratedLocalLineBound (c : Certificate) (a : ℕ) : ℕ :=
  SelectedMCA.directLineFailureBound (c.integratedLocalM a)

/-- Executable sharpness certificate for the pointwise MCA threshold at one
agreement value.  The first conjunct is the theorem hypothesis consumed by the
integrated profile; the second checks the immediate predecessor.  We do not
silently assume global monotonicity of the rounded clique predicate. -/
def Certificate.IntegratedLocalPointValid (c : Certificate) (a : ℕ) : Prop :=
  SelectedMCA.DirectCliqueCondition c.n (c.n - a) c.g c.d
      (c.integratedLocalM a) ∧
    (¬3 * (c.n - a) < c.d →
      ¬SelectedMCA.DirectCliqueCondition c.n (c.n - a) c.g c.d
        (c.integratedLocalM a - 1))

/-- Finite checker for every agreement value used by the threshold-free
layer-cake integral.  Values below `n-e` are outside the selected-response
event and deliberately ignored. -/
def Certificate.integratedLocalValidBool (c : Certificate) : Bool :=
  (List.range (c.n + 1)).all fun a ↦
    if c.n - c.e ≤ a then
      @decide (c.IntegratedLocalPointValid a) (by
        unfold Certificate.IntegratedLocalPointValid
        infer_instance)
    else true

theorem Certificate.integratedLocalPointValid_of_bool (c : Certificate)
    (h : c.integratedLocalValidBool = true) (a : ℕ)
    (ha : c.n - c.e ≤ a) (han : a ≤ c.n) :
    c.IntegratedLocalPointValid a := by
  unfold Certificate.integratedLocalValidBool at h
  rw [List.all_eq_true] at h
  have hmem : a ∈ List.range (c.n + 1) := by simp; omega
  have hp := h a hmem
  simp only [if_pos ha] at hp
  exact @of_decide_eq_true (c.IntegratedLocalPointValid a) (by
    unfold Certificate.IntegratedLocalPointValid
    infer_instance) hp

/-- The same executable check also records predecessor sharpness, which is not
needed for soundness but is used by the tightening audit. -/
theorem Certificate.integratedLocalM_predecessor_fails (c : Certificate)
    (h : c.integratedLocalValidBool = true) (a : ℕ)
    (ha : c.n - c.e ≤ a) (han : a ≤ c.n)
    (hnsharp : ¬3 * (c.n - a) < c.d) :
    ¬SelectedMCA.DirectCliqueCondition c.n (c.n - a) c.g c.d
      (c.integratedLocalM a - 1) :=
  (c.integratedLocalPointValid_of_bool h a ha han).2 hnsharp

def Certificate.listSize (c : Certificate) : ℕ :=
  CodingTheory.InterleavedJohnson.listBound c.n c.d (c.e + c.g)

def Certificate.v1Threshold (c : Certificate) : ℕ :=
  Nat.sqrt (c.n * (2 * c.k - 1)) + 1

def Certificate.failureProfile (c : Certificate) : AgreementProfile c.n :=
  SchemeSelectedMCA.selectedMCAIntegratedFailureProfile c.n c.e c.g c.d
    c.lineBound c.integratedLocalLineBound

/-- Public optimized MCA profile.  It retains the exact pointwise integral
and sharpens only the full-agreement endpoint by the proved chord count. -/
def Certificate.optimizedFailureProfile (c : Certificate) : AgreementProfile c.n :=
  SchemeSelectedMCA.selectedMCAOptimizedIntegratedFailureProfile
    c.fieldSize c.n c.e c.g c.d c.lineBound c.integratedLocalLineBound

def Certificate.optimizedFailureDenominator (c : Certificate) : ℕ :=
  SchemeSelectedMCA.selectedMCAOptimizedFailureDenominator c.fieldSize c.g

/-- The least integral bad-line bound represented by the cleared Johnson
threshold at a local agreement level.  The Boolean Johnson certificate below
independently checks that this rounded value satisfies every theorem premise. -/
def Certificate.johnsonLocalLineBound
    (c : Certificate) (etaBits agreement : ℕ) : ℕ :=
  Nat.ceil (JBAgreement.johnsonThresholdQ c.k c.n (c.n - agreement) etaBits) - 1

/-- The rounded local Johnson count is arithmetically minimal: every smaller
natural bound fails the threshold inequality required by `JohnsonConditions`.
This is independent of the remaining Johnson hypotheses. -/
theorem Certificate.johnsonLocalLineBound_minimal
    (c : Certificate) (etaBits agreement bound : ℕ)
    (hbound : bound < c.johnsonLocalLineBound etaBits agreement) :
    ¬JBAgreement.johnsonThresholdQ c.k c.n (c.n - agreement) etaBits ≤
      (bound : ℚ) + 1 := by
  intro hthreshold
  have hceil : Nat.ceil
      (JBAgreement.johnsonThresholdQ c.k c.n (c.n - agreement) etaBits) ≤
        bound + 1 := by
    rw [Nat.ceil_le]
    exact_mod_cast hthreshold
  unfold johnsonLocalLineBound at hbound
  omega

/-- Johnson-route optimized profile.  The outer radius uses the row's checked
bound, while every smaller radius uses its own least rounded Johnson threshold.
Thus the layer-cake integral contains no reused outer-bound slack. -/
def Certificate.johnsonOptimizedFailureProfile
    (c : Certificate) (etaBits : ℕ) : AgreementProfile c.n :=
  SchemeSelectedMCA.selectedMCAOptimizedIntegratedFailureProfile
    c.fieldSize c.n c.e c.g c.d c.lineBound
      (c.johnsonLocalLineBound etaBits)

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

/-- Shared proximity/arithmetic query baseline used by the disjoint ledger. -/
def Certificate.eventBaseline (c : Certificate) : ℕ :=
  max (c.n - c.e - 1) (min c.n (c.g + (2 * c.k - 1)))

def Certificate.failureExcessContribution
    (c : Certificate) (queries : ℕ) : ℚ :=
  c.optimizedFailureProfile.excessContribution c.optimizedFailureDenominator
    c.n c.n 0 queries c.eventBaseline

def Certificate.johnsonFailureExcessContribution
    (c : Certificate) (etaBits queries : ℕ) : ℚ :=
  (c.johnsonOptimizedFailureProfile etaBits).excessContribution
    c.optimizedFailureDenominator c.n c.n 0 queries c.eventBaseline

namespace V1Certificate

/-- V1's shared baseline uses the last full-mass point of its unchecked
Johnson profile. -/
def eventBaseline (c : V1Certificate) : ℕ :=
  max (c.n - c.e - 1) (min c.n (c.g + (c.v1Threshold - 1)))

def failureExcessContribution (c : V1Certificate) (queries : ℕ) : ℚ :=
  c.optimizedFailureProfile.excessContribution c.optimizedFailureDenominator
    c.n c.n 0 queries c.eventBaseline

def v1Soundness (c : V1Certificate) (queries : ℕ) : ℚ :=
  c.failureExcessContribution queries +
    c.v1Profile.contribution c.fieldSize c.n c.e c.g queries

end V1Certificate



/-- Executable form of the exact V1 bound. -/
def V1Certificate.compressedV1Soundness
    (c : V1Certificate) (queries : ℕ) : ℚ :=
  c.optimizedFailureProfile.compressedExcessContribution
      c.optimizedFailureDenominator c.n c.n 0 queries c.eventBaseline +
    c.v1Profile.compressedContribution c.fieldSize c.n c.e c.g queries

theorem V1Certificate.compressedV1Soundness_eq
    (c : V1Certificate) (queries : ℕ) :
    c.compressedV1Soundness queries = c.v1Soundness queries := by
  simp only [compressedV1Soundness, v1Soundness, failureExcessContribution]
  rw [AgreementProfile.compressedExcessContribution_eq,
    AgreementProfile.contribution_eq_compressedContribution]

/-- **The Johnson-route conditions of a certificate.**  The punctured and
lift-list conditions are the clique route's; the clique condition itself is
replaced by a checked Johnson certificate at `η = 1 / 2 ^ etaBits`, with the
certificate's `lineBound` as the bad-parameter count.

A Johnson row stores its outer line bound in `m` exactly as a clique row does.
At smaller radii the checker uses the least rounded local Johnson threshold. -/
def Certificate.johnsonConditions (c : Certificate) (etaBits : ℕ) : Bool :=
  JBAgreement.johnsonConditionsBool c.n c.k c.e etaBits c.lineBound
      c.fieldSize &&
    (List.range (c.n + 1)).all (fun a ↦
      if c.n - c.e ≤ a then
        JBAgreement.johnsonConditionsBool c.n c.k (c.n - a)
          etaBits (c.johnsonLocalLineBound etaBits a) c.fieldSize
      else true) &&
    (3 * c.g < c.d - c.e) && (c.g + 1 < c.fieldSize) &&
    decide (0 < CodingTheory.InterleavedJohnson.denominator c.n c.d (c.e + c.g))

/-- The Johnson-route certificate reaches the same route-agnostic bundle the
masters consume, given a Reed–Solomon presentation of the base code. -/
theorem Certificate.johnsonLineConditions (c : Certificate) {etaBits : ℕ}
    {F : Type*} [_root_.Field F] [Fintype F] [DecidableEq F]
    {C : CodingTheory.LinearCode F c.n}
    (P : JBAgreement.RSPresentation c.n c.k C)
    (hfield : Fintype.card F = c.fieldSize)
    (h : c.johnsonConditions etaBits = true) :
    LigeroFamily.IntegratedSelectedMCALineConditions C c.fieldSize c.e c.g c.d
      c.lineBound (c.johnsonLocalLineBound etaBits) := by
  simp only [Certificate.johnsonConditions, Bool.and_eq_true,
    decide_eq_true_eq] at h
  have hlocal (a : ℕ) (ha : c.n - c.e ≤ a) (han : a ≤ c.n) :
      JBAgreement.johnsonConditionsBool c.n c.k (c.n - a) etaBits
        (c.johnsonLocalLineBound etaBits a) c.fieldSize = true := by
    have hall := h.1.1.1.2
    rw [List.all_eq_true] at hall
    have hmem : a ∈ List.range (c.n + 1) := by simp; omega
    simpa [ha] using hall a hmem
  exact {
    outer := {
      line := JBAgreement.lineFailureBound_of_johnsonConditions P hfield
        (JBAgreement.johnsonConditions_of_bool h.1.1.1.1)
      punctured := ⟨h.1.1.2, h.1.2⟩
      johnson := ⟨h.2⟩ }
    localLine := fun a ha han ↦
      JBAgreement.lineFailureBound_of_johnsonConditions P hfield
        (JBAgreement.johnsonConditions_of_bool (hlocal a ha han))
    local_three_radius := by
      intro a ha han
      have houter := h.1.1.2
      omega }

def Certificate.conditions (c : Certificate) : Prop :=
  IntegratedSelectedMCAParameterConditions c.fieldSize c.n c.e c.g c.d c.m
    c.integratedLocalM

/-- Assemble the threshold-free numerical bundle from the finite pointwise
checker and the four genuinely global hypotheses. -/
theorem Certificate.conditions_of_checked (c : Certificate)
    (hdirect : SelectedMCA.DirectCliqueCondition c.n c.e c.g c.d c.m)
    (hthree : 3 * c.g < c.d - c.e)
    (hfield : c.g + 1 < c.fieldSize)
    (hdenominator : 0 < CodingTheory.InterleavedJohnson.denominator
      c.n c.d (c.e + c.g))
    (hlocal : c.integratedLocalValidBool = true) : c.conditions := by
  exact {
    toSelectedMCAParameterConditions :=
      ⟨⟨hdirect⟩, ⟨hthree, hfield⟩, ⟨hdenominator⟩⟩
    localDirect := fun a ha han ↦
      (c.integratedLocalPointValid_of_bool hlocal a ha han).1
    local_three_radius := by
      intro a ha han
      omega }

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
  have hnumeric : LigeroFamily.IntegratedSelectedMCAParameterConditions
      (Fintype.card F) c.n c.e c.g c.d c.m c.integratedLocalM := by
    simpa [Certificate.conditions, hfield] using hconditions
  have hmaster := Ligero.V1.v1_ligero_soundness_optimizedIntegrated
    hrows C statement prover (LigeroFamily.NoDecodedSolution.of_not_language hfalse)
    hmin (hnumeric.lineConditions hmin)
      (c.v1JohnsonRange hkpos hresponse C hk)
  have hlocal :
      (fun a ↦ SelectedMCA.directLineFailureBound (c.integratedLocalM a)) =
        c.integratedLocalLineBound := rfl
  rw [hlocal] at hmaster
  simpa [V1Certificate.v1Soundness, V1Certificate.failureExcessContribution,
    V1Certificate.eventBaseline,
    Certificate.optimizedFailureProfile,
    Certificate.optimizedFailureDenominator, V1Certificate.v1Profile,
    Certificate.fieldSize, Certificate.lineBound,
    Certificate.integratedLocalLineBound, Certificate.listSize,
    Certificate.v1Threshold, hfield, hk] using hmaster

/-! ## Singleton-lift (unique-decoding) certificate endpoints

These definitions and theorems are the protocol-level basis of the UDR grid.
They use the same threshold-free integrated selected-MCA failure profile as the
ordinary flat grid, but the proved unique-decoding hypothesis replaces the
oracle-fixed lift-list size by exactly one.  No numerical row is introduced in
this section.
-/



/-- V1 arithmetic agreement profile when the oracle-fixed lift list is proved
to be a singleton. -/
def V1Certificate.uniqueV1Profile
    (c : V1Certificate) : AgreementProfile c.n :=
  uncheckedAgreementProfile c.fieldSize c.n (2 * c.k - 1) 1 c.v1Threshold

def V1Certificate.uniqueV1Soundness
    (c : V1Certificate) (queries : ℕ) : ℚ :=
  c.failureExcessContribution queries +
    c.uniqueV1Profile.contribution c.fieldSize c.n c.e c.g queries

def V1Certificate.compressedUniqueV1Soundness
    (c : V1Certificate) (queries : ℕ) : ℚ :=
  c.optimizedFailureProfile.compressedExcessContribution
      c.optimizedFailureDenominator c.n c.n 0 queries c.eventBaseline +
    c.uniqueV1Profile.compressedContribution c.fieldSize c.n c.e c.g queries

theorem V1Certificate.compressedUniqueV1Soundness_eq
    (c : V1Certificate) (queries : ℕ) :
    c.compressedUniqueV1Soundness queries = c.uniqueV1Soundness queries := by
  simp only [compressedUniqueV1Soundness, uniqueV1Soundness,
    failureExcessContribution]
  rw [AgreementProfile.compressedExcessContribution_eq,
    AgreementProfile.contribution_eq_compressedContribution]

/-- Checked V1 certificate endpoint in the singleton-lift regime. -/
theorem V1Certificate.v1_unique_protocol_soundness
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
    (hmin : CodingTheory.HasMinimumDistanceAtLeast C.baseCode c.d)
    (hunique : 2 * (c.e + c.g) < c.d) :
    (SchemeVerifier.protocol C Ligero.V1.scheme).acceptanceRate prover
        statement ≤ c.uniqueV1Soundness c.openings := by
  have hnumeric : LigeroFamily.IntegratedSelectedMCAParameterConditions
      (Fintype.card F) c.n c.e c.g c.d c.m c.integratedLocalM := by
    simpa [Certificate.conditions, hfield] using hconditions
  have hmaster := Ligero.V1.v1_ligero_soundness_optimizedIntegrated_unique
    hrows C statement prover (LigeroFamily.NoDecodedSolution.of_not_language hfalse)
    hmin (hnumeric.lineConditions hmin) hunique
      (c.v1JohnsonRange hkpos hresponse C hk)
  have hlocal :
      (fun a ↦ SelectedMCA.directLineFailureBound (c.integratedLocalM a)) =
        c.integratedLocalLineBound := rfl
  rw [hlocal] at hmaster
  simpa [V1Certificate.uniqueV1Soundness,
    V1Certificate.failureExcessContribution, V1Certificate.eventBaseline,
    Certificate.optimizedFailureProfile,
    Certificate.optimizedFailureDenominator, V1Certificate.uniqueV1Profile,
    Certificate.fieldSize, Certificate.lineBound,
    Certificate.integratedLocalLineBound, Certificate.v1Threshold,
    hfield, hk] using hmaster


end Ligero.Examples.Grid
