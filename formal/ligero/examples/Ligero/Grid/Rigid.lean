import examples.Ligero.Grid.Tight
import Bcs.ResponseRigid
import Merkle.PrefixBinding
import LigeroFamily.Soundness.CanonicalResponse
























namespace Ligero.Examples.Grid.Rigid

open LigeroFamily

set_option maxHeartbeats 20000000

/-- Integer Johnson list bound for a word family whose distinct words agree in
at most `agreementCap` positions.  Callers check that the denominator is
positive. -/
def johnsonAgreementListBound (n agreementCap agreement : ℕ) : ℕ :=
  n * (agreement - agreementCap) /
    (agreement * agreement - n * agreementCap)

structure Result where
  certificate : Ligero.Examples.Grid.Certificate
  g : ℕ
  m : ℕ
  openings : ℕ

/-- The same protocol point with the CA parameters used by rigid accounting. -/
def Result.tightCertificate (result : Result) :
    Ligero.Examples.Grid.Certificate :=
  { result.certificate with
      g := result.g
      m := result.m
      openings := result.openings }

def Result.proximityAgreementCap (result : Result) : ℕ :=
  result.certificate.k - 1

def Result.responseAgreementCap (result : Result) : ℕ :=
  2 * result.certificate.k - 1

/-- Largest agreement that is still on the unlisted/floor side. -/
def Result.responseFloor (result : Result) : ℕ :=
  max (result.certificate.n - result.certificate.e - 1)
    (max (Nat.sqrt (result.certificate.n * result.proximityAgreementCap))
      (Nat.sqrt (result.certificate.n * result.responseAgreementCap)))

def Result.firstListedAgreement (result : Result) : ℕ :=
  result.responseFloor + 1



def Result.tupleListBound (result : Result) : ℕ :=
  johnsonAgreementListBound result.certificate.n
      result.proximityAgreementCap result.firstListedAgreement *
    johnsonAgreementListBound result.certificate.n
      result.responseAgreementCap result.firstListedAgreement *
    johnsonAgreementListBound result.certificate.n
      result.responseAgreementCap result.firstListedAgreement

/-- Product Johnson bound at an arbitrary agreement above the response
floor.  The numerical validity predicate checks positivity at the first
listed level; positivity is then monotone in the agreement parameter. -/
def Result.tupleListBoundAt (result : Result) (agreement : ℕ) : ℕ :=
  johnsonAgreementListBound result.certificate.n
      result.proximityAgreementCap agreement *
    johnsonAgreementListBound result.certificate.n
      result.responseAgreementCap agreement *
    johnsonAgreementListBound result.certificate.n
      result.responseAgreementCap agreement

def Result.goodAgreementCap (result : Result) : ℕ :=
  result.certificate.n - result.certificate.e - 1

/-- The selected-MCA agreement-tail profile for one chosen valid response. -/
def Result.failureProfile (result : Result) : AgreementProfile result.certificate.n :=
  SchemeSelectedMCA.selectedMCAFailureProfile result.certificate.n result.g
    result.certificate.d (SelectedMCA.directLineFailureBound result.m)

/-- The denominator in the selected-MCA tail-density theorem. -/
def Result.failureDenominator (result : Result) : ℕ :=
  result.certificate.fieldSize - (result.g + 1)

/-- Case-B tail with the trivial probability-one baseline installed through
the good-agreement floor.  Its contribution is exactly
`hyp(goodAgreementCap) + caseBExcess`, but its compressed form avoids
recomputing a binomial coefficient at every unchanged tail level. -/
def Result.caseBProfile (result : Result) : AgreementProfile result.certificate.n where
  labelsAtLeast agreement :=
    if agreement ≤ result.goodAgreementCap then result.failureDenominator
    else result.failureProfile.labelsAtLeast agreement

/-- Case-A tail with the trivial baseline installed through the response
floor and the agreement-dependent product list above it. -/
def Result.caseAProfile (result : Result) : AgreementProfile result.certificate.n where
  labelsAtLeast agreement :=
    if agreement ≤ result.responseFloor then result.failureDenominator
    else result.tupleListBoundAt agreement *
      result.failureProfile.labelsAtLeast agreement

/-- Audited terms (i)--(iii) of the response-rigid theorem.  The exceptional
challenge regime is integrated against the full selected-MCA agreement tail;
it is not truncated at an unsupported universal agreement cap.  This is the
coefficient of `Q + 2`, before `eps_bind`. -/
def Result.workNormalizedBound (result : Result) (queries : ℕ) : ℚ :=
  result.caseAProfile.compressedContribution result.failureDenominator
      result.certificate.n result.certificate.n 0 queries +
    result.caseBProfile.compressedContribution result.failureDenominator
      result.certificate.n result.certificate.n 0 queries

/-- Check every numerical premise consumed by the compiler theorem.  The
first five conjuncts are the selected-MCA CA certificate, including minimality
of `m` for the displayed `g`. -/
def Result.ParametersValid (result : Result) : Prop :=
  SelectedMCA.DirectCliqueCondition result.certificate.n
      result.certificate.e result.g result.certificate.d result.m ∧
    ¬SelectedMCA.DirectCliqueCondition result.certificate.n
      result.certificate.e result.g result.certificate.d (result.m - 1) ∧
    3 * result.g < result.certificate.d - result.certificate.e ∧
    result.g + 1 < result.certificate.fieldSize ∧
    0 < CodingTheory.InterleavedJohnson.denominator result.certificate.n
      result.certificate.d (result.certificate.e + result.g) ∧
    0 < result.certificate.k ∧
    2 * result.certificate.k ≤ result.certificate.n ∧
    result.responseFloor ≤ result.certificate.n ∧
    result.responseAgreementCap < result.firstListedAgreement ∧
    result.certificate.n * result.proximityAgreementCap <
      result.firstListedAgreement * result.firstListedAgreement ∧
    result.certificate.n * result.responseAgreementCap <
      result.firstListedAgreement * result.firstListedAgreement

def Result.NumericValid (result : Result) : Prop :=
  result.ParametersValid ∧
    0 < result.openings ∧
    result.workNormalizedBound result.openings ≤
      (1 : ℚ) / 2 ^ result.certificate.targetBits ∧
    (1 : ℚ) / 2 ^ result.certificate.targetBits <
      result.workNormalizedBound (result.openings - 1)

def Result.validBool (result : Result) : Bool :=
  @decide result.NumericValid (by
    unfold NumericValid ParametersValid
    infer_instance)

/-- Generated by `scripts/generate_rigid_grid.py`. -/
def results : List Result := [
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
]

/-- Exact-rational validation of every generated row and its predecessor. -/
theorem results_valid : results.all Result.validBool = true := by
  native_decide

end Ligero.Examples.Grid.Rigid
