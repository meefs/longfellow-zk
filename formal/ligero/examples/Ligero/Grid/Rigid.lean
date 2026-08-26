import examples.Ligero.Grid.Data
import Bcs.ResponseRigid
import Merkle.PrefixBinding
import LigeroFamily.Soundness.CanonicalResponse
import LigeroFamily.Soundness.RigidCompiler
import Ligero.V1.RoundByRound
namespace Ligero.Examples.Grid.Rigid

open LigeroFamily

set_option maxHeartbeats 20000000

inductive Variant where
  | v1
deriving DecidableEq, Repr

structure GCertificateEntry where
  m : ℕ
deriving DecidableEq, Repr

/-- Direct-clique thresholds for every residual at one extraction radius. -/
structure RadiusCertificate where
  thresholds : List GCertificateEntry := []
deriving DecidableEq, Repr

structure Result where
  variant : Variant := .v1
  certificate : Ligero.Examples.Grid.Certificate
  /-- Whether `e` overrides the protocol-neutral extraction radius.  This is
  separate from the numeral because radius zero is a legitimate optimized
  choice. -/
  overrideE : Bool := false
  e : ℕ := 0
  g : ℕ
  m : ℕ
  cutoff : ℕ := 0
  localM : ℕ := 0
  /-- Zero selects the least floor justified by the two Johnson radii. -/
  floor : ℕ := 0
  /-- Search certificates set this flag so the literal floor zero remains
  representable; displayed rows retain the compact zero-means-minimum form. -/
  overrideFloor : Bool := false
  openings : ℕ
  unique : Bool := false
  /-- One residual-threshold row for every extraction radius `0 ≤ e ≤` the
  protocol-neutral radius.  Route and response-floor coverage are quantified
  by `CompleteSearchValid`, so neither is hidden in this data. -/
  searchCertificate : List RadiusCertificate := []

def Result.effectiveE (result : Result) : ℕ :=
  if result.overrideE then result.e else result.certificate.e

/-- The same protocol point with the CA parameters used by rigid accounting. -/
def Result.tightCertificate (result : Result) :
    Ligero.Examples.Grid.Certificate :=
  { result.certificate with
      e := result.effectiveE
      g := result.g
      m := result.m
      cutoff := result.cutoff
      localM := result.localM
      openings := result.openings }

def Result.proximityAgreementCap (result : Result) : ℕ :=
  result.certificate.k - 1

def Result.responseAgreementCap (result : Result) : ℕ :=
  2 * result.certificate.k - 1

/-- Largest agreement that is still on the unlisted/floor side. -/
def Result.minimumResponseFloor (result : Result) : ℕ :=
  max (result.certificate.n - result.effectiveE - 1)
    (max (Nat.sqrt (result.certificate.n * result.proximityAgreementCap))
      (Nat.sqrt (result.certificate.n * result.responseAgreementCap)))

def Result.responseFloor (result : Result) : ℕ :=
  if result.overrideFloor then result.floor
  else if result.floor = 0 then result.minimumResponseFloor else result.floor

def Result.firstListedAgreement (result : Result) : ℕ :=
  result.responseFloor + 1

def Result.responseDistance (result : Result) : ℕ :=
  result.certificate.n - result.responseAgreementCap

/-- Pointwise response-list multiplicity.  The complete response tuple is one
interleaved word over the response code, so one Johnson factor bounds every
protocol variant at each agreement level. -/
def Result.responseMultiplicity (result : Result) (agreement : ℕ) : ℕ :=
  CodingTheory.InterleavedJohnson.listBound
    result.certificate.n result.responseDistance
      (result.certificate.n - agreement)

/-- The selected-MCA agreement-tail profile for one chosen valid response. -/
def Result.failureProfile (result : Result) : AgreementProfile result.certificate.n :=
  result.tightCertificate.optimizedFailureProfile

def Result.arithmeticProfile (result : Result) : AgreementProfile result.certificate.n :=
  match result.variant with
  | .v1 => uncheckedAgreementProfile result.certificate.fieldSize
      result.certificate.n (2 * result.certificate.k - 1)
      (if result.unique then 1 else
        CodingTheory.InterleavedJohnson.listBound result.certificate.n
          result.certificate.d (result.effectiveE + result.g))
      result.tightCertificate.v1Threshold
def Result.arithmeticBaselineAgreement (result : Result) : ℕ :=
  match result.variant with
  | .v1 => result.tightCertificate.v1Threshold - 1
def Result.eventBaseline (result : Result) : ℕ :=
  max (result.certificate.n - result.effectiveE - 1)
    (min result.certificate.n (result.g + result.arithmeticBaselineAgreement))

theorem Result.arithmeticBaselineAgreement_le (result : Result)
    (h2k : 2 * result.certificate.k ≤ result.certificate.n) :
    result.arithmeticBaselineAgreement ≤ result.certificate.n := by
  cases result.variant with
  | v1 =>
      simp only [arithmeticBaselineAgreement, Result.tightCertificate, Certificate.v1Threshold, Nat.add_sub_cancel]
      have hlambda : 2 * result.certificate.k - 1 ≤ result.certificate.n := by omega
      rw [← Nat.lt_succ_iff, Nat.sqrt_lt]
      nlinarith
theorem Result.arithmeticProfile_floor (result : Result)
    (h2k : 2 * result.certificate.k ≤ result.certificate.n) :
    ∀ a ≤ result.arithmeticBaselineAgreement,
      result.certificate.fieldSize ≤ result.arithmeticProfile.labelsAtLeast a := by
  intro a ha
  have han := result.arithmeticBaselineAgreement_le h2k
  have haN : a ≤ result.certificate.n := ha.trans han
  cases result.variant with
  | v1 =>
      have hthreshold : a < result.tightCertificate.v1Threshold := by
        simp [arithmeticBaselineAgreement, Result.tightCertificate,
          Certificate.v1Threshold] at ha ⊢
        omega
      have hnotn : ¬result.certificate.n < a := by omega
      simp only [arithmeticProfile]
      have hfieldtight : result.certificate.fieldSize =
          result.tightCertificate.fieldSize := by rfl
      have hnotntight : ¬result.tightCertificate.n < a := by
        simpa [Result.tightCertificate] using hnotn
      rw [hfieldtight]
      simp [uncheckedAgreementProfile, hnotn, hthreshold]
/-- The denominator in the selected-MCA tail-density theorem. -/
def Result.failureDenominator (result : Result) : ℕ :=
  result.tightCertificate.optimizedFailureDenominator

/-- Joint response-agreement profile obtained from the failure and arithmetic
classifiers. -/
def Result.responseAgreementProfile (result : Result) :
    AgreementProfile result.certificate.n :=
  ResponseAgreement.combinedProfile result.failureDenominator
    result.certificate.fieldSize result.g result.failureProfile
      result.arithmeticProfile

def Result.responseAgreementDenominator (result : Result) : ℕ :=
  ResponseAgreement.combinedDenominator result.failureDenominator
    result.certificate.fieldSize

/-- Exact executable response-agreement excess above the common baseline. -/
def Result.responseAgreementExcess (result : Result) (queries : ℕ) : ℚ :=
  (ResponseAgreement.multipliedProfile (fun a ↦ result.responseMultiplicity a)
      result.responseAgreementProfile).rawExcessContribution
        result.responseAgreementDenominator result.certificate.n
          result.certificate.n 0 queries result.responseFloor

theorem Result.responseAgreementExcess_eq (result : Result) (queries : ℕ) :
    result.responseAgreementExcess queries =
      (ResponseAgreement.multipliedProfile (fun a ↦ result.responseMultiplicity a)
        result.responseAgreementProfile).rawExcessContribution
          result.responseAgreementDenominator result.certificate.n
            result.certificate.n 0 queries result.responseFloor := by
  rfl

def Result.strategyPairBound (result : Result) (queries : ℕ) : ℚ :=
  result.failureProfile.compressedExcessContribution result.failureDenominator
      result.certificate.n result.certificate.n 0 queries result.eventBaseline +
    result.arithmeticProfile.compressedContribution result.certificate.fieldSize
      result.certificate.n result.effectiveE result.g queries

theorem Result.strategyPairBound_eq (result : Result) (queries : ℕ) :
    result.strategyPairBound queries =
      result.failureProfile.excessContribution result.failureDenominator
          result.certificate.n result.certificate.n 0 queries result.eventBaseline +
        result.arithmeticProfile.contribution result.certificate.fieldSize
          result.certificate.n result.effectiveE result.g queries := by
  simp only [strategyPairBound]
  rw [AgreementProfile.compressedExcessContribution_eq,
    ← AgreementProfile.contribution_eq_compressedContribution]

/-- Literal `epsilonA + epsilonB` from the complete rigid compiler. -/
def Result.workNormalizedBound (result : Result) (queries : ℕ) : ℚ :=
  min 1 (hypergeometricRatio result.responseFloor result.certificate.n queries +
    result.responseAgreementExcess queries) +
    result.strategyPairBound queries

/-! ## Integer executable coefficient

The following naturals are a second executable presentation of the unchanged
compiler coefficient.  They are deliberately phrased in terms of the same
profiles as `workNormalizedBound`; generated Python numerals are not trusted.
-/

def Result.integerizedCaseANumerator (result : Result) (queries : ℕ) : ℕ :=
  min
    (result.certificate.n.choose queries * result.responseAgreementDenominator)
    (result.responseFloor.choose queries * result.responseAgreementDenominator +
      (ResponseAgreement.multipliedProfile
        (fun a ↦ result.responseMultiplicity a)
        result.responseAgreementProfile).rawExcessNumerator
          queries result.responseFloor)

def Result.integerizedFailureNumerator (result : Result) (queries : ℕ) : ℕ :=
  result.failureProfile.excessContributionNumerator result.failureDenominator
    queries result.eventBaseline

def Result.integerizedArithmeticNumerator (result : Result) (queries : ℕ) : ℕ :=
  result.arithmeticProfile.contributionNumerator result.certificate.fieldSize
    result.effectiveE result.g queries

def Result.integerizedTotalNumerator (result : Result) (queries : ℕ) : ℕ :=
  result.integerizedCaseANumerator queries +
    result.certificate.fieldSize * result.integerizedFailureNumerator queries +
    result.failureDenominator * result.integerizedArithmeticNumerator queries

def Result.integerizedTotalDenominator (result : Result) (queries : ℕ) : ℕ :=
  result.certificate.n.choose queries * result.responseAgreementDenominator

def Result.integerizedWorkNormalizedBound (result : Result) (queries : ℕ) : ℚ :=
  (result.integerizedTotalNumerator queries : ℚ) /
    result.integerizedTotalDenominator queries

theorem Result.workNormalizedBound_eq_integerized (result : Result)
    (queries : ℕ) (hqueries : queries ≤ result.certificate.n)
    (hfailure : 0 < result.failureDenominator)
    (hfield : 0 < result.certificate.fieldSize) :
    result.workNormalizedBound queries =
      result.integerizedWorkNormalizedBound queries := by
  have hchoose : 0 < result.certificate.n.choose queries :=
    Nat.choose_pos hqueries
  have hcombined : 0 < result.responseAgreementDenominator := by
    exact Nat.mul_pos hfailure hfield
  have hraw := AgreementProfile.rawExcessContribution_eq_numerator_div
    (ResponseAgreement.multipliedProfile
      (fun a ↦ result.responseMultiplicity a)
      result.responseAgreementProfile)
    result.responseAgreementDenominator queries result.responseFloor
    hcombined hqueries
  have hfailureEq := AgreementProfile.excessContribution_eq_numerator_div
    result.failureProfile result.failureDenominator queries result.eventBaseline
    hfailure hqueries
  have harithmeticEq := AgreementProfile.contribution_eq_numerator_div
    result.arithmeticProfile result.certificate.fieldSize result.effectiveE
      result.g queries hfield hqueries
  have hcaseInside :
      hypergeometricRatio result.responseFloor result.certificate.n queries +
          result.responseAgreementExcess queries =
        ((result.responseFloor.choose queries *
            result.responseAgreementDenominator +
          (ResponseAgreement.multipliedProfile
            (fun a ↦ result.responseMultiplicity a)
            result.responseAgreementProfile).rawExcessNumerator
              queries result.responseFloor : ℕ) : ℚ) /
          (result.certificate.n.choose queries *
            result.responseAgreementDenominator) := by
    rw [result.responseAgreementExcess_eq, hraw]
    unfold hypergeometricRatio
    push_cast
    field_simp
  have hcase :
      min 1 (hypergeometricRatio result.responseFloor result.certificate.n queries +
          result.responseAgreementExcess queries) =
        (result.integerizedCaseANumerator queries : ℚ) /
          (result.certificate.n.choose queries *
            result.responseAgreementDenominator) := by
    rw [hcaseInside]
    simpa [integerizedCaseANumerator, Nat.cast_mul] using
      (AgreementProfile.min_one_nat_div_eq
        (result.responseFloor.choose queries *
            result.responseAgreementDenominator +
          (ResponseAgreement.multipliedProfile
            (fun a ↦ result.responseMultiplicity a)
            result.responseAgreementProfile).rawExcessNumerator
              queries result.responseFloor)
        (result.certificate.n.choose queries *
          result.responseAgreementDenominator)
        (Nat.mul_pos hchoose hcombined))
  rw [workNormalizedBound, hcase, strategyPairBound_eq,
    hfailureEq, harithmeticEq]
  unfold integerizedWorkNormalizedBound integerizedTotalNumerator
    integerizedTotalDenominator integerizedFailureNumerator
    integerizedArithmeticNumerator responseAgreementDenominator
    ResponseAgreement.combinedDenominator
  push_cast
  field_simp
  ring

theorem Result.workNormalizedBound_eq_compiler (result : Result)
    (queries : ℕ) :
    result.workNormalizedBound queries =
      min 1 (hypergeometricRatio result.responseFloor result.certificate.n queries +
        (ResponseAgreement.multipliedProfile
          (fun a ↦ result.responseMultiplicity a)
          result.responseAgreementProfile).rawExcessContribution
            result.responseAgreementDenominator result.certificate.n
              result.certificate.n 0 queries result.responseFloor) +
        (result.failureProfile.excessContribution result.failureDenominator
            result.certificate.n result.certificate.n 0 queries result.eventBaseline +
          result.arithmeticProfile.contribution result.certificate.fieldSize
            result.certificate.n result.effectiveE result.g queries) := by
  rw [workNormalizedBound, responseAgreementExcess_eq, strategyPairBound_eq]




/-- The floor term is a certified candidate-independent lower bound on the
complete rigid coefficient.  The exact optimizer uses it to discard an
extraction radius only when no residual or route at that radius can improve
the current opening count. -/
theorem Result.floorTerm_le_workNormalizedBound (result : Result) (queries : ℕ)
    (hfloor : result.responseFloor ≤ result.certificate.n)
    (hqueries : queries ≤ result.certificate.n) :
    hypergeometricRatio result.responseFloor result.certificate.n queries ≤
      result.workNormalizedBound queries := by
  have hchoose : (0 : ℚ) < result.certificate.n.choose queries := by
    exact_mod_cast Nat.choose_pos hqueries
  have hratio :
      hypergeometricRatio result.responseFloor result.certificate.n queries ≤ 1 := by
    unfold hypergeometricRatio
    rw [div_le_one hchoose]
    exact_mod_cast Nat.choose_le_choose queries hfloor
  have hresponse : 0 ≤ result.responseAgreementExcess queries :=
    AgreementProfile.rawExcessContribution_nonnegative _ _ _ _ _ _ _
  have hpair : 0 ≤ result.strategyPairBound queries := by
    rw [result.strategyPairBound_eq]
    exact add_nonneg
      (AgreementProfile.excessContribution_nonnegative _ _ _ _ _ _ _)
      (AgreementProfile.contribution_nonnegative _ _ _ _ _ _)
  unfold workNormalizedBound
  have hinside :
      hypergeometricRatio result.responseFloor result.certificate.n queries ≤
        hypergeometricRatio result.responseFloor result.certificate.n queries +
          result.responseAgreementExcess queries :=
    le_add_of_nonneg_right hresponse
  exact le_add_of_le_of_nonneg (le_min hratio hinside) hpair

/-- Check every numerical premise consumed by the compiler theorem.  The
first five conjuncts are the selected-MCA CA certificate, including failure of
the immediate predecessor of `m` for the displayed `g`. -/
def Result.ParametersValid (result : Result) : Prop :=
  SelectedMCA.DirectCliqueCondition result.certificate.n
      result.effectiveE result.g result.certificate.d result.m ∧
    ¬SelectedMCA.DirectCliqueCondition result.certificate.n
      result.effectiveE result.g result.certificate.d (result.m - 1) ∧
    3 * result.g < result.certificate.d - result.effectiveE ∧
    result.g + 1 < result.certificate.fieldSize ∧
    0 < CodingTheory.InterleavedJohnson.denominator result.certificate.n
      result.certificate.d (result.effectiveE + result.g) ∧
    (result.unique = true →
      2 * (result.effectiveE + result.g) < result.certificate.d) ∧
    result.tightCertificate.integratedLocalValidBool = true ∧
    0 < result.certificate.k ∧
    2 * result.certificate.k ≤ result.certificate.n ∧
    result.openings ≤ result.certificate.n ∧
    result.responseFloor < result.certificate.n ∧
    result.certificate.n - result.effectiveE - 1 ≤ result.responseFloor ∧
    result.certificate.n - result.firstListedAgreement < result.responseDistance ∧
    0 < CodingTheory.InterleavedJohnson.denominator result.certificate.n
      result.responseDistance
        (result.certificate.n - result.firstListedAgreement)

/-- Floor-independent part of `ParametersValid`, evaluated once per
`(e,route,g)` in the complete checker. -/
def Result.CoreParametersValid (result : Result) : Prop :=
  SelectedMCA.DirectCliqueCondition result.certificate.n
      result.effectiveE result.g result.certificate.d result.m ∧
    ¬SelectedMCA.DirectCliqueCondition result.certificate.n
      result.effectiveE result.g result.certificate.d (result.m - 1) ∧
    3 * result.g < result.certificate.d - result.effectiveE ∧
    result.g + 1 < result.certificate.fieldSize ∧
    0 < CodingTheory.InterleavedJohnson.denominator result.certificate.n
      result.certificate.d (result.effectiveE + result.g) ∧
    (result.unique = true →
      2 * (result.effectiveE + result.g) < result.certificate.d) ∧
    result.tightCertificate.integratedLocalValidBool = true ∧
    0 < result.certificate.k ∧
    2 * result.certificate.k ≤ result.certificate.n ∧
    result.openings ≤ result.certificate.n

/-- The endpoint radius and denominator numerals stored in a row certify every
pointwise Johnson call used by the response-agreement layer cake. -/
theorem Result.responsePointwisePremises (result : Result)
    (hvalid : result.ParametersValid) (agreement : ℕ)
    (hfloor : result.responseFloor < agreement)
    (_hagreement : agreement ≤ result.certificate.n) :
    result.certificate.n - agreement < result.responseDistance ∧
      0 < CodingTheory.InterleavedJohnson.denominator result.certificate.n
        result.responseDistance (result.certificate.n - agreement) := by
  rcases hvalid with
    ⟨_, _, _, _, _, _, _, _, _, _, _, _, hradius, hdenominator⟩
  have herrors : result.certificate.n - agreement ≤
      result.certificate.n - result.firstListedAgreement :=
    Nat.sub_le_sub_left (by simp [Result.firstListedAgreement]; omega) _
  exact ⟨herrors.trans_lt hradius,
    CodingTheory.InterleavedJohnson.denominator_pos_of_le herrors
      (Nat.sub_le _ _) hdenominator⟩

def Result.NumericValid (result : Result) : Prop :=
  result.ParametersValid ∧
    0 < result.openings ∧
    result.workNormalizedBound result.openings ≤
      (1 : ℚ) / 2 ^ result.certificate.targetBits ∧
    (1 : ℚ) / 2 ^ result.certificate.targetBits <
      result.workNormalizedBound (result.openings - 1)

/-- An executable, exact-integer presentation of the numerical validity
test.  It avoids constructing and normalizing rational values in the grid's
native decision procedure. -/
def Result.IntegerNumericValid (result : Result) : Prop :=
  result.ParametersValid ∧
    0 < result.openings ∧
    2 ^ result.certificate.targetBits *
        result.integerizedTotalNumerator result.openings ≤
      result.integerizedTotalDenominator result.openings ∧
    result.integerizedTotalDenominator (result.openings - 1) <
      2 ^ result.certificate.targetBits *
        result.integerizedTotalNumerator (result.openings - 1)

def Result.maximumG (result : Result) : ℕ :=
  (result.certificate.d - result.effectiveE - 1) / 3

/-- Premises that make one residual `g` a theorem-admissible search point,
apart from the direct-clique threshold supplied by the radius certificate. -/
def Result.gAdmissible (result : Result) (candidateG : ℕ) : Prop :=
  3 * candidateG < result.certificate.d - result.effectiveE ∧
    candidateG + 1 < result.certificate.fieldSize ∧
    0 < CodingTheory.InterleavedJohnson.denominator result.certificate.n
      result.certificate.d (result.effectiveE + candidateG) ∧
    (result.unique = true →
      2 * (result.effectiveE + candidateG) < result.certificate.d)

def Result.searchCandidate (result : Result) (candidateE : ℕ)
    (candidateUnique : Bool) (candidateG : ℕ)
    (entry : GCertificateEntry) (candidateFloor : ℕ) : Result :=
  { result with
      overrideE := true
      e := candidateE
      unique := candidateUnique
      g := candidateG
      m := entry.m
      floor := candidateFloor
      overrideFloor := true }

def Result.floorAdmissible (result : Result) (candidateFloor : ℕ) : Prop :=
  result.certificate.n - result.effectiveE - 1 ≤ candidateFloor ∧
    candidateFloor < result.certificate.n ∧
    result.certificate.n - (candidateFloor + 1) < result.responseDistance ∧
    0 < CodingTheory.InterleavedJohnson.denominator result.certificate.n
      result.responseDistance
        (result.certificate.n - (candidateFloor + 1))

theorem Result.parametersValid_of_core_floor (result : Result)
    (hcore : result.CoreParametersValid)
    (hfloor : result.floorAdmissible result.responseFloor) :
    result.ParametersValid := by
  rcases hcore with ⟨hdirect, hminimal, hthree, hfield, hjohnson,
    hroute, hlocal, hk, h2k, hopenings⟩
  rcases hfloor with ⟨hfar, hlt, hradius, hdenominator⟩
  exact ⟨hdirect, hminimal, hthree, hfield, hjohnson, hroute, hlocal,
    hk, h2k, hopenings, hlt, hfar, by
      simpa [firstListedAgreement] using hradius, by
      simpa [firstListedAgreement] using hdenominator⟩

/-- The stored clique threshold is genuinely the first theorem-valid one;
checking only its immediate predecessor is not used as a monotonicity
assumption. -/
def Result.cliqueThresholdLeast (result : Result) : Prop :=
  SelectedMCA.DirectCliqueCondition result.certificate.n result.effectiveE
      result.g result.certificate.d result.m ∧
    ∀ candidateM : Fin result.m,
      ¬SelectedMCA.DirectCliqueCondition result.certificate.n result.effectiveE
        result.g result.certificate.d candidateM.1

/-- Complete theorem-admissible search certificate.  Radius, route, residual,
and response floor are all explicit quantifiers.  The predecessor is evaluated
with the Lean integerized expression; the semantic compiler expression is
connected by `workNormalizedBound_eq_integerized`. -/
def Result.CompleteSearchValid (result : Result) : Prop :=
  result.searchCertificate.length = result.certificate.e + 1 ∧
    ∀ candidateE : Fin (result.certificate.e + 1),
      let radiusCertificate :=
        result.searchCertificate.getD candidateE.1 { thresholds := [] }
      let radiusBase := result.searchCandidate candidateE.1 false 0 { m := 0 } 0
      radiusCertificate.thresholds.length = radiusBase.maximumG + 1 ∧
        ∀ candidateUnique : Bool,
          ∀ candidateG : Fin (radiusBase.maximumG + 1),
            let entry := radiusCertificate.thresholds.getD candidateG.1 { m := 0 }
            let base := result.searchCandidate candidateE.1 candidateUnique
              candidateG.1 entry 0
            base.gAdmissible candidateG.1 →
              ∀ candidateFloor : Fin result.certificate.n,
                let candidate := result.searchCandidate candidateE.1
                  candidateUnique candidateG.1 entry candidateFloor.1
                candidate.floorAdmissible candidateFloor.1 →
                  candidate.ParametersValid ∧
                    candidate.cliqueThresholdLeast ∧
                    (1 : ℚ) / 2 ^ result.certificate.targetBits <
                      candidate.integerizedWorkNormalizedBound
                        (result.openings - 1)

def Result.parametersValidBool (result : Result) : Bool :=
  @decide result.ParametersValid (by unfold ParametersValid; infer_instance)

theorem Result.parametersValid_of_bool (result : Result)
    (h : result.parametersValidBool = true) : result.ParametersValid := by
  letI : Decidable result.ParametersValid := by unfold ParametersValid; infer_instance
  exact of_decide_eq_true (by simpa [parametersValidBool] using h)

def Result.coreParametersValidBool (result : Result) : Bool :=
  @decide result.CoreParametersValid
    (by unfold CoreParametersValid; infer_instance)

theorem Result.coreParametersValid_of_bool (result : Result)
    (h : result.coreParametersValidBool = true) :
    result.CoreParametersValid := by
  letI : Decidable result.CoreParametersValid := by
    unfold CoreParametersValid
    infer_instance
  exact of_decide_eq_true (by simpa [coreParametersValidBool] using h)

def Result.gAdmissibleBool (result : Result) (candidateG : ℕ) : Bool :=
  @decide (result.gAdmissible candidateG) (by unfold gAdmissible; infer_instance)

theorem Result.gAdmissible_of_bool (result : Result) (candidateG : ℕ)
    (h : result.gAdmissibleBool candidateG = true) :
    result.gAdmissible candidateG := by
  letI : Decidable (result.gAdmissible candidateG) := by
    unfold gAdmissible
    infer_instance
  exact of_decide_eq_true (by simpa [gAdmissibleBool] using h)

theorem Result.gAdmissibleBool_of (result : Result) (candidateG : ℕ)
    (h : result.gAdmissible candidateG) :
    result.gAdmissibleBool candidateG = true := by
  exact @decide_eq_true (result.gAdmissible candidateG)
    (by unfold Result.gAdmissible; infer_instance) h

def Result.floorAdmissibleBool (result : Result) (candidateFloor : ℕ) : Bool :=
  @decide (result.floorAdmissible candidateFloor)
    (by unfold floorAdmissible; infer_instance)

theorem Result.floorAdmissible_of_bool (result : Result) (candidateFloor : ℕ)
    (h : result.floorAdmissibleBool candidateFloor = true) :
    result.floorAdmissible candidateFloor := by
  letI : Decidable (result.floorAdmissible candidateFloor) := by
    unfold floorAdmissible
    infer_instance
  exact of_decide_eq_true (by simpa [floorAdmissibleBool] using h)

theorem Result.floorAdmissibleBool_of (result : Result) (candidateFloor : ℕ)
    (h : result.floorAdmissible candidateFloor) :
    result.floorAdmissibleBool candidateFloor = true := by
  exact @decide_eq_true (result.floorAdmissible candidateFloor)
    (by unfold Result.floorAdmissible; infer_instance) h

def Result.cliqueThresholdLeastBool (result : Result) : Bool :=
  @decide (SelectedMCA.DirectCliqueCondition result.certificate.n
      result.effectiveE result.g result.certificate.d result.m)
      (by unfold SelectedMCA.DirectCliqueCondition; infer_instance) &&
    (List.range result.m).all fun candidateM ↦
      @decide (¬SelectedMCA.DirectCliqueCondition result.certificate.n
        result.effectiveE result.g result.certificate.d candidateM)
        (by unfold SelectedMCA.DirectCliqueCondition; infer_instance)

theorem Result.cliqueThresholdLeast_of_bool (result : Result)
    (h : result.cliqueThresholdLeastBool = true) :
    result.cliqueThresholdLeast := by
  rw [cliqueThresholdLeastBool, Bool.and_eq_true] at h
  constructor
  · exact of_decide_eq_true h.1
  · intro candidateM
    rw [List.all_eq_true] at h
    exact of_decide_eq_true (h.2 candidateM.1 (by simp))

def Result.predecessorFailsBool (selected candidate : Result) : Bool :=
  @decide ((1 : ℚ) / 2 ^ selected.certificate.targetBits <
      candidate.integerizedWorkNormalizedBound (selected.openings - 1))
    (by infer_instance)

theorem Result.predecessorFails_of_bool (selected candidate : Result)
    (h : selected.predecessorFailsBool candidate = true) :
    (1 : ℚ) / 2 ^ selected.certificate.targetBits <
      candidate.integerizedWorkNormalizedBound (selected.openings - 1) := by
  exact of_decide_eq_true (by simpa [predecessorFailsBool] using h)

/-- Executable complete-domain checker.  Every loop is an explicit finite
range; there is no frontier, binary search, or pruning predicate. -/
def Result.completeSearchValidBool (result : Result) : Bool :=
  result.searchCertificate.length == result.certificate.e + 1 &&
    (List.range (result.certificate.e + 1)).all fun candidateE ↦
      let radiusCertificate := result.searchCertificate.getD candidateE
        { thresholds := [] }
      let radiusBase := result.searchCandidate candidateE false 0 { m := 0 } 0
      radiusCertificate.thresholds.length == radiusBase.maximumG + 1 &&
        ([false, true] : List Bool).all fun candidateUnique ↦
          (List.range (radiusBase.maximumG + 1)).all fun candidateG ↦
            let entry := radiusCertificate.thresholds.getD candidateG { m := 0 }
            let base := result.searchCandidate candidateE candidateUnique
              candidateG entry 0
            if base.gAdmissibleBool candidateG then
              base.coreParametersValidBool &&
                base.cliqueThresholdLeastBool &&
                (List.range result.certificate.n).all fun candidateFloor ↦
                  let candidate := result.searchCandidate candidateE candidateUnique
                    candidateG entry candidateFloor
                  if candidate.floorAdmissibleBool candidateFloor then
                    result.predecessorFailsBool candidate
                  else true
            else true

theorem Result.completeSearchValid_of_bool (result : Result)
    (h : result.completeSearchValidBool = true) :
    result.CompleteSearchValid := by
  rw [completeSearchValidBool, Bool.and_eq_true] at h
  refine ⟨by simpa using h.1, ?_⟩
  intro candidateE
  rw [List.all_eq_true] at h
  have he := h.2 candidateE.1 (by simp; omega)
  dsimp only at he ⊢
  rw [Bool.and_eq_true] at he
  refine ⟨by simpa using he.1, ?_⟩
  intro candidateUnique candidateG
  rw [List.all_eq_true] at he
  have hunique := he.2 candidateUnique (by cases candidateUnique <;> simp)
  rw [List.all_eq_true] at hunique
  have hgEntry := hunique candidateG.1 (by simp; omega)
  intro hg
  rw [if_pos (gAdmissibleBool_of _ _ hg)] at hgEntry
  simp only [Bool.and_eq_true] at hgEntry
  have hcore := coreParametersValid_of_bool _ hgEntry.1.1
  have hleast := cliqueThresholdLeast_of_bool _ hgEntry.1.2
  intro candidateFloor
  rw [List.all_eq_true] at hgEntry
  have hfloorEntry := hgEntry.2 candidateFloor.1 (by simp)
  intro hfloor
  rw [if_pos (floorAdmissibleBool_of _ _ hfloor)] at hfloorEntry
  have hparameters :
      (result.searchCandidate candidateE.1 candidateUnique candidateG.1
        ((result.searchCertificate.getD candidateE.1
          { thresholds := [] }).thresholds.getD candidateG.1 { m := 0 })
        candidateFloor.1).ParametersValid := by
    apply parametersValid_of_core_floor
    · simpa [searchCandidate, CoreParametersValid, effectiveE,
        tightCertificate] using hcore
    · simpa [searchCandidate, responseFloor] using hfloor
  exact ⟨hparameters, by
      simpa [searchCandidate, cliqueThresholdLeast, effectiveE] using hleast,
    predecessorFails_of_bool _ _ hfloorEntry⟩

theorem Result.failureDenominator_pos_of_field (result : Result)
    (hfield : result.g + 1 < result.certificate.fieldSize) :
    0 < result.failureDenominator := by
  unfold failureDenominator Result.tightCertificate
    Certificate.optimizedFailureDenominator
    SchemeSelectedMCA.selectedMCAOptimizedFailureDenominator
  exact Nat.mul_pos ((Nat.succ_pos result.g).trans hfield)
    (Nat.sub_pos_of_lt hfield)

theorem Result.integerizedTotalDenominator_pos (result : Result)
    (queries : ℕ) (hqueries : queries ≤ result.certificate.n)
    (hfailure : 0 < result.failureDenominator)
    (hfield : 0 < result.certificate.fieldSize) :
    0 < result.integerizedTotalDenominator queries := by
  unfold integerizedTotalDenominator
  exact Nat.mul_pos (Nat.choose_pos hqueries) (Nat.mul_pos hfailure hfield)

/-- Semantic predecessor failure for any tuple covered by the complete
integer certificate. -/
theorem Result.completeSearchCandidate_fails (result : Result)
    (hsearch : result.CompleteSearchValid)
    (candidateE : Fin (result.certificate.e + 1))
    (candidateUnique : Bool)
    (candidateG : Fin
      ((result.searchCandidate candidateE.1 false 0 { m := 0 } 0).maximumG + 1))
    (hg :
      let radiusCertificate := result.searchCertificate.getD candidateE.1
        { thresholds := [] }
      let entry := radiusCertificate.thresholds.getD candidateG.1 { m := 0 }
      let base := result.searchCandidate candidateE.1 candidateUnique
        candidateG.1 entry 0
      base.gAdmissible candidateG.1)
    (candidateFloor : Fin result.certificate.n)
    (hfloor :
      let radiusCertificate := result.searchCertificate.getD candidateE.1
        { thresholds := [] }
      let entry := radiusCertificate.thresholds.getD candidateG.1 { m := 0 }
      let candidate := result.searchCandidate candidateE.1 candidateUnique
        candidateG.1 entry candidateFloor.1
      candidate.floorAdmissible candidateFloor.1) :
    let radiusCertificate := result.searchCertificate.getD candidateE.1
      { thresholds := [] }
    let entry := radiusCertificate.thresholds.getD candidateG.1 { m := 0 }
    let candidate := result.searchCandidate candidateE.1 candidateUnique
      candidateG.1 entry candidateFloor.1
    candidate.ParametersValid ∧ candidate.cliqueThresholdLeast ∧
      (1 : ℚ) / 2 ^ result.certificate.targetBits <
        candidate.workNormalizedBound (result.openings - 1) := by
  rcases hsearch with ⟨_hlength, hall⟩
  have hradius := hall candidateE
  dsimp only at hradius
  have hroute := hradius.2 candidateUnique candidateG
  dsimp only at hroute hg hfloor ⊢
  have hchecked := hroute hg candidateFloor hfloor
  let candidate := result.searchCandidate candidateE.1 candidateUnique
    candidateG.1
      ((result.searchCertificate.getD candidateE.1 { thresholds := [] }).thresholds.getD
        candidateG.1 { m := 0 }) candidateFloor.1
  change candidate.ParametersValid ∧ candidate.cliqueThresholdLeast ∧
    (1 : ℚ) / 2 ^ result.certificate.targetBits <
      candidate.integerizedWorkNormalizedBound (result.openings - 1) at hchecked
  change candidate.ParametersValid ∧ candidate.cliqueThresholdLeast ∧
    (1 : ℚ) / 2 ^ result.certificate.targetBits <
      candidate.workNormalizedBound (result.openings - 1)
  refine ⟨hchecked.1, hchecked.2.1, ?_⟩
  have hparams := hchecked.1
  have hfieldLarge := hparams.2.2.2.1
  have hqueries := hparams.2.2.2.2.2.2.2.2.2.1
  have hqueryPred : result.openings - 1 ≤ candidate.certificate.n := by
    change candidate.openings - 1 ≤ candidate.certificate.n
    exact (Nat.sub_le candidate.openings 1).trans hqueries
  have hfieldPos : 0 < candidate.certificate.fieldSize :=
    (Nat.succ_pos candidate.g).trans hfieldLarge
  rw [Result.workNormalizedBound_eq_integerized candidate _ hqueryPred
    (Result.failureDenominator_pos_of_field candidate hfieldLarge) hfieldPos]
  exact hchecked.2.2

/-- Exact cross multiplication turns the integer executable predicate into
the unchanged rational proposition consumed by the compiler endpoints. -/
theorem Result.numericValid_of_integerNumericValid (result : Result)
    (hvalid : result.IntegerNumericValid) : result.NumericValid := by
  rcases hvalid with ⟨hparams, hopeningsPos, hpassing, hpredecessor⟩
  rcases hparams with
    ⟨hdirect, hminimal, hthree, hfieldLarge, hjohnson, hroute, hlocal,
      hk, h2k, hopenings, hfloor, hfar, hradius, hresponseDenominator⟩
  have hparams : result.ParametersValid :=
    ⟨hdirect, hminimal, hthree, hfieldLarge, hjohnson, hroute, hlocal,
      hk, h2k, hopenings, hfloor, hfar, hradius, hresponseDenominator⟩
  have hfailure : 0 < result.failureDenominator :=
    result.failureDenominator_pos_of_field hfieldLarge
  have hfield : 0 < result.certificate.fieldSize :=
    (Nat.succ_pos result.g).trans hfieldLarge
  have hpredecessorQueries : result.openings - 1 ≤ result.certificate.n :=
    (Nat.sub_le result.openings 1).trans hopenings
  have hpassingDenominator :
      0 < result.integerizedTotalDenominator result.openings :=
    result.integerizedTotalDenominator_pos _ hopenings hfailure hfield
  have hpredecessorDenominator :
      0 < result.integerizedTotalDenominator (result.openings - 1) :=
    result.integerizedTotalDenominator_pos _ hpredecessorQueries hfailure hfield
  have hpower : (0 : ℚ) < 2 ^ result.certificate.targetBits :=
    pow_pos (by norm_num) _
  refine ⟨hparams, hopeningsPos, ?_, ?_⟩
  · rw [result.workNormalizedBound_eq_integerized _ hopenings hfailure hfield]
    unfold integerizedWorkNormalizedBound
    rw [div_le_div_iff₀ (by exact_mod_cast hpassingDenominator) hpower]
    have hpassing' :
        (result.integerizedTotalNumerator result.openings : ℚ) *
            2 ^ result.certificate.targetBits ≤
          result.integerizedTotalDenominator result.openings := by
      exact_mod_cast (show
        result.integerizedTotalNumerator result.openings *
            2 ^ result.certificate.targetBits ≤
          result.integerizedTotalDenominator result.openings by
        simpa [mul_comm] using hpassing)
    simpa using hpassing'
  · rw [result.workNormalizedBound_eq_integerized _ hpredecessorQueries
      hfailure hfield]
    unfold integerizedWorkNormalizedBound
    rw [div_lt_div_iff₀ hpower (by exact_mod_cast hpredecessorDenominator)]
    have hpredecessor' :
        (result.integerizedTotalDenominator (result.openings - 1) : ℚ) <
          result.integerizedTotalNumerator (result.openings - 1) *
            2 ^ result.certificate.targetBits := by
      exact_mod_cast (show
        result.integerizedTotalDenominator (result.openings - 1) <
          result.integerizedTotalNumerator (result.openings - 1) *
            2 ^ result.certificate.targetBits by
        simpa [mul_comm] using hpredecessor)
    simpa using hpredecessor'

def Result.validBool (result : Result) : Bool :=
  @decide result.IntegerNumericValid (by
    unfold IntegerNumericValid ParametersValid
    infer_instance)

theorem Result.uniqueRadius (result : Result) (h : result.ParametersValid)
    (hunique : result.unique = true) :
    2 * (result.effectiveE + result.g) < result.certificate.d := by
  rcases h with ⟨_, _, _, _, _, hroute, _⟩
  exact hroute hunique

theorem Result.numericValid_of_validBool (result : Result)
    (h : result.validBool = true) : result.NumericValid := by
  letI : Decidable result.IntegerNumericValid := by
    unfold Result.IntegerNumericValid Result.ParametersValid
    infer_instance
  apply result.numericValid_of_integerNumericValid
  apply of_decide_eq_true
  simpa [Result.validBool] using h

theorem Result.conditions (result : Result) (h : result.ParametersValid) :
    result.tightCertificate.conditions := by
  rcases h with ⟨hdirect, _hminimal, hthree, hfield, hdenominator,
    _hroute, hlocal, _⟩
  exact result.tightCertificate.conditions_of_checked hdirect hthree hfield
    hdenominator hlocal



/-- Every valid V1 rigid row turns the exact compiler coefficient into its
checked `2^-targetBits` bound. -/
theorem Result.v1_prefixBinding_ratio_le
    (result : Result) (hvalid : result.NumericValid)
    (_hvariant : result.variant = .v1)
    {F Equations Salt D Enc Output PrefixOut RunOut AlphaKey : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Inhabited Salt] [Inhabited D] [Fintype D]
    [DecidableEq D] [DecidableEq Enc] [DecidableEq AlphaKey]
    {w nw nq merkleT N prefixFuel runFuel : ℕ}
    (hrows : CoreRowsNonempty nw nq)
    (hfield : Fintype.card F = result.certificate.fieldSize)
    (C : MultiplicativeCode F result.openings w result.certificate.n)
    (hk : C.k = result.certificate.k)
    (statement : ConstraintSystem F nw nq w Equations)
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F NoMask Ligero.V1.Mask nw nq 1) D Enc)
    (family : Merkle.MH.PrefixBindingFamily
      (Out := PrefixOut) (RunOut := RunOut) codec
      (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
        (Ligero.V1.Challenge F nw nq 1 Equations)
          (QuerySet result.certificate.n result.openings))
      result.certificate.n merkleT prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec) (hprefix : prefixFuel ≤ merkleT)
    (adversary : Merkle.RandomOracle.Tree
      (Bcs.TypedFiatShamir.Query AlphaKey
        (AlphaKey × Response F result.openings w result.certificate.n 1))
      (Bcs.TypedFiatShamir.Answer
        (Ligero.V1.Challenge F nw nq 1 Equations)
          (QuerySet result.certificate.n result.openings)) Output N)
    (dflt : Bcs.TypedFiatShamir.Answer
      (Ligero.V1.Challenge F nw nq 1 Equations)
        (QuerySet result.certificate.n result.openings))
    (alphaKey : AlphaKey)
    (responseOf : Output →
      Response F result.openings w result.certificate.n 1)
    (fallback : AlphaKey ×
      Response F result.openings w result.certificate.n 1)
    (hfalse : ¬statement.Language)
    (hmin : CodingTheory.HasMinimumDistanceAtLeast C.baseCode
      result.certificate.d) :
    let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
      dflt (fun _ ↦ alphaKey) (fun output ↦ (alphaKey, responseOf output))
    let win := fun merkleAnswers tape ↦
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
      let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
      let claim := (family.game tape).claim merkleAnswers
      claim.I = query.coordinates ∧
        Merkle.MH.Accepts
          (codec.withOracle ((family.game tape).oracle merkleAnswers))
          result.certificate.n ((family.game tape).root merkleAnswers)
          claim.I claim.a claim.pf ∧
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) C Ligero.V1.scheme).accepts statement alpha
            (responseOf output) query (fun j ↦ claim.a j.1)
    ((eventSet fun value :
        (Fin merkleT → D) ×
          (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
            (Ligero.V1.Challenge F nw nq 1 Equations)
              (QuerySet result.certificate.n result.openings)) ↦
          win value.1 value.2).card : ℚ) /
        Fintype.card ((Fin merkleT → D) ×
          (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
            (Ligero.V1.Challenge F nw nq 1 Equations)
              (QuerySet result.certificate.n result.openings))) ≤
      ((((prefixFuel * (prefixFuel - 1) / 2 +
            merkleT * (2 * prefixFuel + 1)) *
          Fintype.card D ^ (merkleT - 1) : ℕ) : ℚ) /
        Fintype.card (Fin merkleT → D)) +
      (N + 2) * ((1 : ℚ) / 2 ^ result.certificate.targetBits) := by
  classical
  rcases hvalid with ⟨hparams, _hopen, hbound, _htight⟩
  rcases hparams with ⟨hdirect, hminimal, hthree, hfieldSize, hbaseList,
    hroute, hlocal, hkpos, h2k, hquery, hfloor, hfarFloor,
    hresponseRadius, hresponseDen⟩
  have hparams' : result.ParametersValid := ⟨hdirect, hminimal, hthree,
    hfieldSize, hbaseList, hroute, hlocal, hkpos, h2k, hquery, hfloor,
    hfarFloor, hresponseRadius, hresponseDen⟩
  have hn : IntegratedSelectedMCAParameterConditions
      (Fintype.card F) result.certificate.n result.effectiveE result.g
        result.certificate.d result.m
          result.tightCertificate.integratedLocalM := by
    simpa [Certificate.conditions, Certificate.fieldSize,
      Result.tightCertificate, hfield] using result.conditions hparams'
  have hlocalLine :
      (fun a ↦ SelectedMCA.directLineFailureBound
        (result.tightCertificate.integratedLocalM a)) =
        result.tightCertificate.integratedLocalLineBound := by
    funext a
    rfl
  let failureProfile := result.failureProfile
  let arithmeticProfile := result.arithmeticProfile
  let reference : Fin (N + 2) → Bcs.TypedFiatShamir.Answer
      (Ligero.V1.Challenge F nw nq 1 Equations)
        (QuerySet result.certificate.n result.openings) := fun _ ↦ dflt
  let oracle := fun merkleAnswers ↦ SchemeOracle.ofColumns
    ((family.game reference).boundMessage dec merkleAnswers)
  have hjohnson := Ligero.Examples.Grid.V1Certificate.v1JohnsonRange
    result.tightCertificate hkpos h2k C hk
  have classifier' : ∀ merkleAnswers strategy,
      PolicyDoublyProfiledSoundnessClassifier
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) C Ligero.V1.scheme)
        (SchemeOracle.ofColumns
          ((family.game (fun _ ↦ dflt)).boundMessage dec merkleAnswers))
        statement strategy failureProfile arithmeticProfile
          (Fintype.card F)
          (SchemeSelectedMCA.selectedMCAOptimizedFailureDenominator
            (Fintype.card F) result.g)
          result.effectiveE result.g := by
    intro merkleAnswers strategy
    cases hunique : result.unique with
    | false =>
        have hc := Classical.choice
          (Ligero.V1.ligerov1_profiledOptimizedIntegrated_classifier_nonempty
            hrows C statement (oracle merkleAnswers) strategy
            (NoDecodedSolution.of_not_language hfalse) hmin hn hjohnson)
        rw [hlocalLine] at hc
        simpa [oracle, reference, failureProfile, arithmeticProfile,
          Result.failureProfile, Result.arithmeticProfile,
          Result.tightCertificate, Certificate.optimizedFailureProfile,
          Certificate.fieldSize, Certificate.lineBound,
          Certificate.integratedLocalLineBound, Certificate.v1Threshold,
          Result.effectiveE, hunique, hfield, hk] using hc
    | true =>
        have hc := Classical.choice
          (Ligero.V1.ligerov1_profiledOptimizedIntegrated_unique_classifier_nonempty
            hrows C statement (oracle merkleAnswers) strategy
            (NoDecodedSolution.of_not_language hfalse) hmin hn
            (result.uniqueRadius hparams' hunique) hjohnson)
        rw [hlocalLine] at hc
        simpa [oracle, reference, failureProfile, arithmeticProfile,
          Result.failureProfile, Result.arithmeticProfile,
          Result.tightCertificate, Certificate.optimizedFailureProfile,
          Certificate.fieldSize, Certificate.lineBound,
          Certificate.integratedLocalLineBound, Certificate.v1Threshold,
          Result.effectiveE, hunique, hfield, hk] using hc
  have hfailure : 0 <
      SchemeSelectedMCA.selectedMCAOptimizedFailureDenominator
        (Fintype.card F) result.g := by
    unfold SchemeSelectedMCA.selectedMCAOptimizedFailureDenominator
    exact Nat.mul_pos Fintype.card_pos (by rw [hfield]; omega)
  have hresponse : CodingTheory.HasMinimumDistanceAtLeast C.responseCode
      result.responseDistance := by
    simpa [Result.responseDistance, Result.responseAgreementCap, hk] using
      Ligero.V1.responseCode_minimumDistance C
  have harithmeticFloor : ∀ a ≤ result.arithmeticBaselineAgreement,
      Fintype.card F ≤ arithmeticProfile.labelsAtLeast a := by
    intro a ha
    rw [hfield]
    simpa [arithmeticProfile] using result.arithmeticProfile_floor h2k a ha
  have hmaster := canonical_scheme_prefixBinding_profiled_ratio_le
    C Ligero.V1.scheme statement codec family dec hprefix adversary dflt
    alphaKey responseOf fallback failureProfile arithmeticProfile classifier'
    Fintype.card_pos hfailure hquery (by rw [hk]; exact h2k)
    result.arithmeticBaselineAgreement
    (result.arithmeticBaselineAgreement_le h2k) harithmeticFloor hresponse
    hresponseRadius hresponseDen hfloor hfarFloor
  calc
    _ ≤ ((((prefixFuel * (prefixFuel - 1) / 2 +
              merkleT * (2 * prefixFuel + 1)) *
            Fintype.card D ^ (merkleT - 1) : ℕ) : ℚ) /
          Fintype.card (Fin merkleT → D)) +
        (N + 2) * result.workNormalizedBound result.openings := by
      rw [result.workNormalizedBound_eq_compiler]
      simpa only [failureProfile, arithmeticProfile, Result.failureProfile,
        Result.arithmeticProfile, Result.responseMultiplicity,
        Result.responseAgreementProfile, Result.responseAgreementDenominator,
        Result.responseDistance,
        Result.responseAgreementCap, Result.firstListedAgreement,
        Result.failureDenominator, Result.eventBaseline,
        Result.tightCertificate, hfield, hk,
        Certificate.optimizedFailureProfile,
        Certificate.optimizedFailureDenominator, V1Certificate.v1Profile,
        Certificate.fieldSize, Certificate.lineBound,
        Certificate.integratedLocalLineBound, Certificate.listSize,
        Certificate.v1Threshold, Nat.cast_mul] using hmaster
    _ ≤ ((((prefixFuel * (prefixFuel - 1) / 2 +
              merkleT * (2 * prefixFuel + 1)) *
            Fintype.card D ^ (merkleT - 1) : ℕ) : ℚ) /
          Fintype.card (Fin merkleT → D)) +
        (N + 2) * ((1 : ℚ) / 2 ^ result.certificate.targetBits) := by
      gcongr



/-- Generated by `scripts/generate_rigid_grid.py`. -/
def results : List Result := [
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S120
    overrideE := true
    e := 490
    g := 0
    m := 1816008
    floor := 545
    overrideFloor := true
    openings := 122
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S121
    overrideE := true
    e := 490
    g := 0
    m := 1816008
    floor := 545
    overrideFloor := true
    openings := 123
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S122
    overrideE := true
    e := 490
    g := 0
    m := 1816008
    floor := 545
    overrideFloor := true
    openings := 125
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S123
    overrideE := true
    e := 490
    g := 0
    m := 1816008
    floor := 545
    overrideFloor := true
    openings := 126
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S124
    overrideE := true
    e := 490
    g := 1
    m := 907142
    floor := 546
    overrideFloor := true
    openings := 128
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S125
    overrideE := true
    e := 490
    g := 5
    m := 300048
    floor := 550
    overrideFloor := true
    openings := 132
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S120
    overrideE := true
    e := 979
    g := 0
    m := 6248382
    floor := 1092
    overrideFloor := true
    openings := 128
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S121
    overrideE := true
    e := 979
    g := 1
    m := 3122710
    floor := 1093
    overrideFloor := true
    openings := 129
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S122
    overrideE := true
    e := 979
    g := 0
    m := 6248382
    floor := 1092
    overrideFloor := true
    openings := 131
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S123
    overrideE := true
    e := 979
    g := 2
    m := 2078784
    floor := 1094
    overrideFloor := true
    openings := 132
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S124
    overrideE := true
    e := 979
    g := 4
    m := 1245475
    floor := 1096
    overrideFloor := true
    openings := 134
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S125
    overrideE := true
    e := 978
    g := 11
    m := 122716
    floor := 1103
    overrideFloor := true
    openings := 139
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S120
    overrideE := true
    e := 1220
    g := 0
    m := 4153211
    floor := 827
    overrideFloor := true
    openings := 90
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S121
    overrideE := true
    e := 1220
    g := 10
    m := 375101
    floor := 827
    overrideFloor := true
    openings := 90
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S122
    overrideE := true
    e := 1220
    g := 3
    m := 1036575
    floor := 827
    overrideFloor := true
    openings := 91
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S123
    overrideE := true
    e := 1220
    g := 5
    m := 689605
    floor := 827
    overrideFloor := true
    openings := 92
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S124
    overrideE := true
    e := 1220
    g := 15
    m := 257416
    floor := 827
    overrideFloor := true
    openings := 93
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S125
    overrideE := true
    e := 950
    g := 6
    m := 1553
    floor := 1097
    overrideFloor := true
    openings := 137
    unique := true },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S120
    overrideE := true
    e := 1468
    g := 0
    m := 12310240
    floor := 1639
    overrideFloor := true
    openings := 130
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S121
    overrideE := true
    e := 1468
    g := 0
    m := 12310240
    floor := 1639
    overrideFloor := true
    openings := 132
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S122
    overrideE := true
    e := 1468
    g := 1
    m := 6153175
    floor := 1640
    overrideFloor := true
    openings := 133
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S123
    overrideE := true
    e := 1468
    g := 2
    m := 4100820
    floor := 1641
    overrideFloor := true
    openings := 135
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S124
    overrideE := true
    e := 1468
    g := 5
    m := 2048465
    floor := 1644
    overrideFloor := true
    openings := 137
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S125
    overrideE := true
    e := 1466
    g := 18
    m := 96986
    floor := 1657
    overrideFloor := true
    openings := 141
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S120
    overrideE := true
    e := 1830
    g := 0
    m := 259269631
    floor := 1241
    overrideFloor := true
    openings := 91
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S121
    overrideE := true
    e := 1830
    g := 0
    m := 259269631
    floor := 1241
    overrideFloor := true
    openings := 92
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S122
    overrideE := true
    e := 1830
    g := 12
    m := 19829284
    floor := 1241
    overrideFloor := true
    openings := 92
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S123
    overrideE := true
    e := 1830
    g := 12
    m := 19829284
    floor := 1241
    overrideFloor := true
    openings := 93
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S124
    overrideE := true
    e := 1830
    g := 61
    m := 4041081
    floor := 1241
    overrideFloor := true
    openings := 94
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S125
    overrideE := true
    e := 1424
    g := 10
    m := 1483
    floor := 1647
    overrideFloor := true
    openings := 139
    unique := true },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S120
    overrideE := true
    e := 1956
    g := 0
    m := 43636105
    floor := 2188
    overrideFloor := true
    openings := 132
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S121
    overrideE := true
    e := 1956
    g := 0
    m := 43636105
    floor := 2188
    overrideFloor := true
    openings := 133
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S122
    overrideE := true
    e := 1956
    g := 2
    m := 14534923
    floor := 2190
    overrideFloor := true
    openings := 134
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S123
    overrideE := true
    e := 1956
    g := 3
    m := 10901271
    floor := 2191
    overrideFloor := true
    openings := 136
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S124
    overrideE := true
    e := 1956
    g := 7
    m := 5445466
    floor := 2195
    overrideFloor := true
    openings := 138
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S125
    overrideE := true
    e := 1955
    g := 22
    m := 285545
    floor := 2210
    overrideFloor := true
    openings := 143
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S120
    overrideE := true
    e := 2437
    g := 0
    m := 36211342
    floor := 1658
    overrideFloor := true
    openings := 92
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S121
    overrideE := true
    e := 2437
    g := 6
    m := 5163182
    floor := 1658
    overrideFloor := true
    openings := 92
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S122
    overrideE := true
    e := 2437
    g := 5
    m := 6020964
    floor := 1658
    overrideFloor := true
    openings := 93
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S123
    overrideE := true
    e := 2437
    g := 9
    m := 3606795
    floor := 1658
    overrideFloor := true
    openings := 94
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S124
    overrideE := true
    e := 2437
    g := 33
    m := 1051136
    floor := 1658
    overrideFloor := true
    openings := 95
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S125
    overrideE := true
    e := 1896
    g := 15
    m := 1357
    floor := 2199
    overrideFloor := true
    openings := 140
    unique := true },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S120
    overrideE := true
    e := 2445
    g := 0
    m := 54547717
    floor := 2735
    overrideFloor := true
    openings := 132
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S121
    overrideE := true
    e := 2445
    g := 3
    m := 13629174
    floor := 2738
    overrideFloor := true
    openings := 133
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S122
    overrideE := true
    e := 2445
    g := 2
    m := 18168575
    floor := 2737
    overrideFloor := true
    openings := 135
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S123
    overrideE := true
    e := 2445
    g := 3
    m := 13629174
    floor := 2738
    overrideFloor := true
    openings := 137
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S124
    overrideE := true
    e := 2445
    g := 8
    m := 6042194
    floor := 2743
    overrideFloor := true
    openings := 139
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S125
    overrideE := true
    e := 2439
    g := 33
    m := 56936
    floor := 2768
    overrideFloor := true
    openings := 143
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S120
    overrideE := true
    e := 3046
    g := 1
    m := 13904611
    floor := 2073
    overrideFloor := true
    openings := 92
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S121
    overrideE := true
    e := 3046
    g := 1
    m := 13904611
    floor := 2073
    overrideFloor := true
    openings := 93
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S122
    overrideE := true
    e := 3046
    g := 3
    m := 6949222
    floor := 2073
    overrideFloor := true
    openings := 94
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S123
    overrideE := true
    e := 3046
    g := 65
    m := 412244
    floor := 2073
    overrideFloor := true
    openings := 94
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S124
    overrideE := true
    e := 3046
    g := 19
    m := 1384911
    floor := 2073
    overrideFloor := true
    openings := 96
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S125
    overrideE := true
    e := 2374
    g := 15
    m := 1708
    floor := 2745
    overrideFloor := true
    openings := 142
    unique := true },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S120
    overrideE := true
    e := 2934
    g := 0
    m := 65459328
    floor := 3281
    overrideFloor := true
    openings := 133
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S121
    overrideE := true
    e := 2934
    g := 1
    m := 32724494
    floor := 3282
    overrideFloor := true
    openings := 134
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S122
    overrideE := true
    e := 2934
    g := 3
    m := 16357077
    floor := 3284
    overrideFloor := true
    openings := 135
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S123
    overrideE := true
    e := 2934
    g := 5
    m := 10901271
    floor := 3286
    overrideFloor := true
    openings := 137
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S124
    overrideE := true
    e := 2934
    g := 11
    m := 5445466
    floor := 3292
    overrideFloor := true
    openings := 139
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S125
    overrideE := true
    e := 2933
    g := 33
    m := 402660
    floor := 3314
    overrideFloor := true
    openings := 144
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S120
    overrideE := true
    e := 3655
    g := 2
    m := 8848382
    floor := 2488
    overrideFloor := true
    openings := 92
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S121
    overrideE := true
    e := 3655
    g := 2
    m := 8848382
    floor := 2488
    overrideFloor := true
    openings := 93
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S122
    overrideE := true
    e := 3655
    g := 4
    m := 5303609
    floor := 2488
    overrideFloor := true
    openings := 94
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S123
    overrideE := true
    e := 3655
    g := 9
    m := 2649352
    floor := 2488
    overrideFloor := true
    openings := 95
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S124
    overrideE := true
    e := 3655
    g := 28
    m := 907226
    floor := 2488
    overrideFloor := true
    openings := 96
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S125
    overrideE := true
    e := 2852
    g := 15
    m := 2058
    floor := 3291
    overrideFloor := true
    openings := 153
    unique := true },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S120
    overrideE := true
    e := 3911
    g := 1
    m := 114670762
    floor := 4378
    overrideFloor := true
    openings := 133
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S121
    overrideE := true
    e := 3911
    g := 4
    m := 45840802
    floor := 4381
    overrideFloor := true
    openings := 134
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S122
    overrideE := true
    e := 3911
    g := 3
    m := 57321796
    floor := 4380
    overrideFloor := true
    openings := 136
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S123
    overrideE := true
    e := 3911
    g := 6
    m := 32735667
    floor := 4383
    overrideFloor := true
    openings := 138
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S124
    overrideE := true
    e := 3911
    g := 14
    m := 15262154
    floor := 4391
    overrideFloor := true
    openings := 140
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S125
    overrideE := true
    e := 3911
    g := 43
    m := 5181281
    floor := 4420
    overrideFloor := true
    openings := 145
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S120
    overrideE := true
    e := 4872
    g := 1
    m := 38058109
    floor := 3319
    overrideFloor := true
    openings := 93
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S121
    overrideE := true
    e := 4872
    g := 8
    m := 8447090
    floor := 3319
    overrideFloor := true
    openings := 93
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S122
    overrideE := true
    e := 4872
    g := 10
    m := 6904269
    floor := 3319
    overrideFloor := true
    openings := 94
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S123
    overrideE := true
    e := 4872
    g := 18
    m := 3995214
    floor := 3319
    overrideFloor := true
    openings := 95
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S124
    overrideE := true
    e := 4872
    g := 67
    m := 1104747
    floor := 3319
    overrideFloor := true
    openings := 96
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S125
    overrideE := true
    e := 3808
    g := 15
    m := 2763
    floor := 4383
    overrideFloor := true
    openings := 205
    unique := true },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S120
    overrideE := true
    e := 490
    g := 0
    m := 1816008
    floor := 545
    overrideFloor := true
    openings := 122
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S121
    overrideE := true
    e := 490
    g := 0
    m := 1816008
    floor := 545
    overrideFloor := true
    openings := 123
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S122
    overrideE := true
    e := 490
    g := 0
    m := 1816008
    floor := 545
    overrideFloor := true
    openings := 124
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S123
    overrideE := true
    e := 490
    g := 0
    m := 1816008
    floor := 545
    overrideFloor := true
    openings := 125
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S124
    overrideE := true
    e := 490
    g := 0
    m := 1816008
    floor := 545
    overrideFloor := true
    openings := 126
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S125
    overrideE := true
    e := 490
    g := 0
    m := 1816008
    floor := 545
    overrideFloor := true
    openings := 127
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S126
    overrideE := true
    e := 490
    g := 0
    m := 1816008
    floor := 545
    overrideFloor := true
    openings := 128
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S127
    overrideE := true
    e := 490
    g := 0
    m := 1816008
    floor := 545
    overrideFloor := true
    openings := 129
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S128
    overrideE := true
    e := 490
    g := 0
    m := 1816008
    floor := 545
    overrideFloor := true
    openings := 129
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S120
    overrideE := true
    e := 979
    g := 0
    m := 6248382
    floor := 1092
    overrideFloor := true
    openings := 128
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S121
    overrideE := true
    e := 979
    g := 0
    m := 6248382
    floor := 1092
    overrideFloor := true
    openings := 129
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S122
    overrideE := true
    e := 979
    g := 0
    m := 6248382
    floor := 1092
    overrideFloor := true
    openings := 130
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S123
    overrideE := true
    e := 979
    g := 0
    m := 6248382
    floor := 1092
    overrideFloor := true
    openings := 131
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S124
    overrideE := true
    e := 979
    g := 0
    m := 6248382
    floor := 1092
    overrideFloor := true
    openings := 132
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S125
    overrideE := true
    e := 979
    g := 0
    m := 6248382
    floor := 1092
    overrideFloor := true
    openings := 133
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S126
    overrideE := true
    e := 979
    g := 0
    m := 6248382
    floor := 1092
    overrideFloor := true
    openings := 134
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S127
    overrideE := true
    e := 979
    g := 0
    m := 6248382
    floor := 1092
    overrideFloor := true
    openings := 135
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S128
    overrideE := true
    e := 979
    g := 0
    m := 6248382
    floor := 1092
    overrideFloor := true
    openings := 136
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S120
    overrideE := true
    e := 1220
    g := 0
    m := 4153211
    floor := 827
    overrideFloor := true
    openings := 90
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S121
    overrideE := true
    e := 1220
    g := 0
    m := 4153211
    floor := 827
    overrideFloor := true
    openings := 90
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S122
    overrideE := true
    e := 1220
    g := 0
    m := 4153211
    floor := 827
    overrideFloor := true
    openings := 91
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S123
    overrideE := true
    e := 1220
    g := 0
    m := 4153211
    floor := 827
    overrideFloor := true
    openings := 92
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S124
    overrideE := true
    e := 1220
    g := 0
    m := 4153211
    floor := 827
    overrideFloor := true
    openings := 93
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S125
    overrideE := true
    e := 1220
    g := 0
    m := 4153211
    floor := 827
    overrideFloor := true
    openings := 93
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S126
    overrideE := true
    e := 1220
    g := 0
    m := 4153211
    floor := 827
    overrideFloor := true
    openings := 94
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S127
    overrideE := true
    e := 1220
    g := 0
    m := 4153211
    floor := 827
    overrideFloor := true
    openings := 95
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S128
    overrideE := true
    e := 1220
    g := 0
    m := 4153211
    floor := 827
    overrideFloor := true
    openings := 95
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S120
    overrideE := true
    e := 1468
    g := 0
    m := 12310240
    floor := 1639
    overrideFloor := true
    openings := 130
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S121
    overrideE := true
    e := 1468
    g := 0
    m := 12310240
    floor := 1639
    overrideFloor := true
    openings := 131
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S122
    overrideE := true
    e := 1468
    g := 0
    m := 12310240
    floor := 1639
    overrideFloor := true
    openings := 132
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S123
    overrideE := true
    e := 1468
    g := 0
    m := 12310240
    floor := 1639
    overrideFloor := true
    openings := 133
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S124
    overrideE := true
    e := 1468
    g := 0
    m := 12310240
    floor := 1639
    overrideFloor := true
    openings := 134
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S125
    overrideE := true
    e := 1468
    g := 0
    m := 12310240
    floor := 1639
    overrideFloor := true
    openings := 135
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S126
    overrideE := true
    e := 1468
    g := 0
    m := 12310240
    floor := 1639
    overrideFloor := true
    openings := 136
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S127
    overrideE := true
    e := 1468
    g := 0
    m := 12310240
    floor := 1639
    overrideFloor := true
    openings := 137
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S128
    overrideE := true
    e := 1468
    g := 0
    m := 12310240
    floor := 1639
    overrideFloor := true
    openings := 138
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S120
    overrideE := true
    e := 1830
    g := 0
    m := 259269631
    floor := 1241
    overrideFloor := true
    openings := 91
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S121
    overrideE := true
    e := 1830
    g := 0
    m := 259269631
    floor := 1241
    overrideFloor := true
    openings := 92
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S122
    overrideE := true
    e := 1830
    g := 0
    m := 259269631
    floor := 1241
    overrideFloor := true
    openings := 92
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S123
    overrideE := true
    e := 1830
    g := 0
    m := 259269631
    floor := 1241
    overrideFloor := true
    openings := 93
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S124
    overrideE := true
    e := 1830
    g := 0
    m := 259269631
    floor := 1241
    overrideFloor := true
    openings := 94
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S125
    overrideE := true
    e := 1830
    g := 0
    m := 259269631
    floor := 1241
    overrideFloor := true
    openings := 94
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S126
    overrideE := true
    e := 1830
    g := 0
    m := 259269631
    floor := 1241
    overrideFloor := true
    openings := 95
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S127
    overrideE := true
    e := 1830
    g := 0
    m := 259269631
    floor := 1241
    overrideFloor := true
    openings := 96
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S128
    overrideE := true
    e := 1830
    g := 0
    m := 259269631
    floor := 1241
    overrideFloor := true
    openings := 97
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S120
    overrideE := true
    e := 1956
    g := 0
    m := 43636105
    floor := 2188
    overrideFloor := true
    openings := 131
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S121
    overrideE := true
    e := 1956
    g := 0
    m := 43636105
    floor := 2188
    overrideFloor := true
    openings := 132
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S122
    overrideE := true
    e := 1956
    g := 0
    m := 43636105
    floor := 2188
    overrideFloor := true
    openings := 133
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S123
    overrideE := true
    e := 1956
    g := 0
    m := 43636105
    floor := 2188
    overrideFloor := true
    openings := 134
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S124
    overrideE := true
    e := 1956
    g := 0
    m := 43636105
    floor := 2188
    overrideFloor := true
    openings := 136
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S125
    overrideE := true
    e := 1956
    g := 0
    m := 43636105
    floor := 2188
    overrideFloor := true
    openings := 137
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S126
    overrideE := true
    e := 1956
    g := 0
    m := 43636105
    floor := 2188
    overrideFloor := true
    openings := 138
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S127
    overrideE := true
    e := 1956
    g := 0
    m := 43636105
    floor := 2188
    overrideFloor := true
    openings := 139
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S128
    overrideE := true
    e := 1956
    g := 0
    m := 43636105
    floor := 2188
    overrideFloor := true
    openings := 140
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S120
    overrideE := true
    e := 2437
    g := 0
    m := 36211342
    floor := 1658
    overrideFloor := true
    openings := 92
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S121
    overrideE := true
    e := 2437
    g := 0
    m := 36211342
    floor := 1658
    overrideFloor := true
    openings := 92
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S122
    overrideE := true
    e := 2437
    g := 0
    m := 36211342
    floor := 1658
    overrideFloor := true
    openings := 93
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S123
    overrideE := true
    e := 2437
    g := 0
    m := 36211342
    floor := 1658
    overrideFloor := true
    openings := 94
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S124
    overrideE := true
    e := 2437
    g := 0
    m := 36211342
    floor := 1658
    overrideFloor := true
    openings := 95
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S125
    overrideE := true
    e := 2437
    g := 0
    m := 36211342
    floor := 1658
    overrideFloor := true
    openings := 95
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S126
    overrideE := true
    e := 2437
    g := 0
    m := 36211342
    floor := 1658
    overrideFloor := true
    openings := 96
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S127
    overrideE := true
    e := 2437
    g := 0
    m := 36211342
    floor := 1658
    overrideFloor := true
    openings := 97
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S128
    overrideE := true
    e := 2437
    g := 0
    m := 36211342
    floor := 1658
    overrideFloor := true
    openings := 97
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S120
    overrideE := true
    e := 2445
    g := 0
    m := 54547717
    floor := 2735
    overrideFloor := true
    openings := 132
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S121
    overrideE := true
    e := 2445
    g := 0
    m := 54547717
    floor := 2735
    overrideFloor := true
    openings := 133
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S122
    overrideE := true
    e := 2445
    g := 0
    m := 54547717
    floor := 2735
    overrideFloor := true
    openings := 134
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S123
    overrideE := true
    e := 2445
    g := 0
    m := 54547717
    floor := 2735
    overrideFloor := true
    openings := 135
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S124
    overrideE := true
    e := 2445
    g := 0
    m := 54547717
    floor := 2735
    overrideFloor := true
    openings := 136
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S125
    overrideE := true
    e := 2445
    g := 0
    m := 54547717
    floor := 2735
    overrideFloor := true
    openings := 137
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S126
    overrideE := true
    e := 2445
    g := 0
    m := 54547717
    floor := 2735
    overrideFloor := true
    openings := 138
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S127
    overrideE := true
    e := 2445
    g := 0
    m := 54547717
    floor := 2735
    overrideFloor := true
    openings := 139
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S128
    overrideE := true
    e := 2445
    g := 0
    m := 54547717
    floor := 2735
    overrideFloor := true
    openings := 140
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S120
    overrideE := true
    e := 3046
    g := 0
    m := 27815389
    floor := 2073
    overrideFloor := true
    openings := 92
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S121
    overrideE := true
    e := 3046
    g := 0
    m := 27815389
    floor := 2073
    overrideFloor := true
    openings := 93
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S122
    overrideE := true
    e := 3046
    g := 0
    m := 27815389
    floor := 2073
    overrideFloor := true
    openings := 93
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S123
    overrideE := true
    e := 3046
    g := 0
    m := 27815389
    floor := 2073
    overrideFloor := true
    openings := 94
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S124
    overrideE := true
    e := 3046
    g := 0
    m := 27815389
    floor := 2073
    overrideFloor := true
    openings := 95
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S125
    overrideE := true
    e := 3046
    g := 0
    m := 27815389
    floor := 2073
    overrideFloor := true
    openings := 96
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S126
    overrideE := true
    e := 3046
    g := 0
    m := 27815389
    floor := 2073
    overrideFloor := true
    openings := 96
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S127
    overrideE := true
    e := 3046
    g := 0
    m := 27815389
    floor := 2073
    overrideFloor := true
    openings := 97
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S128
    overrideE := true
    e := 3046
    g := 0
    m := 27815389
    floor := 2073
    overrideFloor := true
    openings := 98
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S120
    overrideE := true
    e := 2934
    g := 0
    m := 65459328
    floor := 3281
    overrideFloor := true
    openings := 132
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S121
    overrideE := true
    e := 2934
    g := 0
    m := 65459328
    floor := 3281
    overrideFloor := true
    openings := 133
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S122
    overrideE := true
    e := 2934
    g := 0
    m := 65459328
    floor := 3281
    overrideFloor := true
    openings := 134
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S123
    overrideE := true
    e := 2934
    g := 0
    m := 65459328
    floor := 3281
    overrideFloor := true
    openings := 135
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S124
    overrideE := true
    e := 2934
    g := 0
    m := 65459328
    floor := 3281
    overrideFloor := true
    openings := 136
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S125
    overrideE := true
    e := 2934
    g := 0
    m := 65459328
    floor := 3281
    overrideFloor := true
    openings := 138
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S126
    overrideE := true
    e := 2934
    g := 0
    m := 65459328
    floor := 3281
    overrideFloor := true
    openings := 139
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S127
    overrideE := true
    e := 2934
    g := 0
    m := 65459328
    floor := 3281
    overrideFloor := true
    openings := 140
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S128
    overrideE := true
    e := 2934
    g := 0
    m := 65459328
    floor := 3281
    overrideFloor := true
    openings := 141
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S120
    overrideE := true
    e := 3655
    g := 0
    m := 26554957
    floor := 2488
    overrideFloor := true
    openings := 92
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S121
    overrideE := true
    e := 3655
    g := 0
    m := 26554957
    floor := 2488
    overrideFloor := true
    openings := 93
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S122
    overrideE := true
    e := 3655
    g := 0
    m := 26554957
    floor := 2488
    overrideFloor := true
    openings := 94
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S123
    overrideE := true
    e := 3655
    g := 0
    m := 26554957
    floor := 2488
    overrideFloor := true
    openings := 94
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S124
    overrideE := true
    e := 3655
    g := 0
    m := 26554957
    floor := 2488
    overrideFloor := true
    openings := 95
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S125
    overrideE := true
    e := 3655
    g := 0
    m := 26554957
    floor := 2488
    overrideFloor := true
    openings := 96
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S126
    overrideE := true
    e := 3655
    g := 0
    m := 26554957
    floor := 2488
    overrideFloor := true
    openings := 97
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S127
    overrideE := true
    e := 3655
    g := 0
    m := 26554957
    floor := 2488
    overrideFloor := true
    openings := 97
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S128
    overrideE := true
    e := 3655
    g := 0
    m := 26554957
    floor := 2488
    overrideFloor := true
    openings := 98
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S120
    overrideE := true
    e := 3911
    g := 0
    m := 229368694
    floor := 4377
    overrideFloor := true
    openings := 133
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S121
    overrideE := true
    e := 3911
    g := 0
    m := 229368694
    floor := 4377
    overrideFloor := true
    openings := 134
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S122
    overrideE := true
    e := 3911
    g := 0
    m := 229368694
    floor := 4377
    overrideFloor := true
    openings := 135
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S123
    overrideE := true
    e := 3911
    g := 0
    m := 229368694
    floor := 4377
    overrideFloor := true
    openings := 136
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S124
    overrideE := true
    e := 3911
    g := 0
    m := 229368694
    floor := 4377
    overrideFloor := true
    openings := 137
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S125
    overrideE := true
    e := 3911
    g := 0
    m := 229368694
    floor := 4377
    overrideFloor := true
    openings := 138
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S126
    overrideE := true
    e := 3911
    g := 0
    m := 229368694
    floor := 4377
    overrideFloor := true
    openings := 139
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S127
    overrideE := true
    e := 3911
    g := 0
    m := 229368694
    floor := 4377
    overrideFloor := true
    openings := 140
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S128
    overrideE := true
    e := 3911
    g := 0
    m := 229368694
    floor := 4377
    overrideFloor := true
    openings := 141
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S120
    overrideE := true
    e := 4872
    g := 0
    m := 76126763
    floor := 3319
    overrideFloor := true
    openings := 92
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S121
    overrideE := true
    e := 4872
    g := 0
    m := 76126763
    floor := 3319
    overrideFloor := true
    openings := 93
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S122
    overrideE := true
    e := 4872
    g := 0
    m := 76126763
    floor := 3319
    overrideFloor := true
    openings := 94
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S123
    overrideE := true
    e := 4872
    g := 0
    m := 76126763
    floor := 3319
    overrideFloor := true
    openings := 95
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S124
    overrideE := true
    e := 4872
    g := 0
    m := 76126763
    floor := 3319
    overrideFloor := true
    openings := 96
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S125
    overrideE := true
    e := 4872
    g := 0
    m := 76126763
    floor := 3319
    overrideFloor := true
    openings := 96
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S126
    overrideE := true
    e := 4872
    g := 0
    m := 76126763
    floor := 3319
    overrideFloor := true
    openings := 97
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S127
    overrideE := true
    e := 4872
    g := 0
    m := 76126763
    floor := 3319
    overrideFloor := true
    openings := 98
    unique := false },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S128
    overrideE := true
    e := 4872
    g := 0
    m := 76126763
    floor := 3319
    overrideFloor := true
    openings := 99
    unique := false },
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
]

theorem v1_result_count :
    (results.filter fun result ↦ result.variant = .v1).length = 195 := by
  native_decide

end Ligero.Examples.Grid.Rigid
