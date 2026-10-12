import LigeroFamily.Soundness.RigidEventPartition

namespace LigeroFamily

open CodingTheory FirstOccurrenceEventLedger.TypedCounts

/-- End-to-end response-rigid compiler for a scheme verifier.  Both
first-occurrence branches are discharged by the canonical semantic theorems;
the only hypotheses are protocol/code conditions and a strategy-uniform
classifier constructor. -/
theorem canonical_scheme_prefixBinding_profiled_ratio_le
    {F Equations CheckedMask DirectMask AlphaKey Salt D Enc Output
      PrefixOut RunOut : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Fintype CheckedMask] [DecidableEq CheckedMask]
    [Inhabited Salt] [Inhabited D] [Fintype D]
    [DecidableEq D] [DecidableEq Enc] [DecidableEq AlphaKey]
    {r w n nw nq e g profileDenominator failureDenominator merkleT N
      prefixFuel runFuel floor responseDistance : ℕ}
    (code : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F CheckedMask DirectMask nw nq 1) D Enc)
    (family : Merkle.MH.PrefixBindingFamily
      (Out := PrefixOut) (RunOut := RunOut) codec
      (Fin (N + 2) →
        Bcs.TypedFiatShamir.Answer
          (SchemeChallenge F CheckedMask nw nq 1 Equations)
          (QuerySet n r)) n merkleT prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec) (hprefix : prefixFuel ≤ merkleT)
    (adversary : Merkle.RandomOracle.Tree
      (Bcs.TypedFiatShamir.Query AlphaKey
        (AlphaKey × Response F r w n 1))
      (Bcs.TypedFiatShamir.Answer
        (SchemeChallenge F CheckedMask nw nq 1 Equations)
        (QuerySet n r)) Output N)
    (dflt : Bcs.TypedFiatShamir.Answer
      (SchemeChallenge F CheckedMask nw nq 1 Equations) (QuerySet n r))
    (alphaKey : AlphaKey) (responseOf : Output → Response F r w n 1)
    (fallback : AlphaKey × Response F r w n 1)
    (failureProfile arithmeticProfile : AgreementProfile n)
    (classifier : ∀ merkleAnswers strategy,
      PolicyDoublyProfiledSoundnessClassifier
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) code scheme)
        (SchemeOracle.ofColumns
          ((family.game (fun _ ↦ dflt)).boundMessage dec merkleAnswers))
        statement strategy failureProfile arithmeticProfile
          profileDenominator failureDenominator e g)
    (hprofile : 0 < profileDenominator)
    (hfailure : 0 < failureDenominator)
    (hquery : r ≤ n) (h2k : 2 * code.k ≤ n)
    (baselineAgreement : ℕ) (hbaselineAgreement : baselineAgreement ≤ n)
    (hprofileFloor : ∀ a ≤ baselineAgreement,
      profileDenominator ≤ arithmeticProfile.labelsAtLeast a)
    (hresponse : HasMinimumDistanceAtLeast code.responseCode responseDistance)
    (hresponseRadius : n - (floor + 1) < responseDistance)
    (hresponseDen : 0 < InterleavedJohnson.denominator
      n responseDistance (n - (floor + 1)))
    (hfloor : floor < n) (hfarFloor : n - e - 1 ≤ floor) :
    let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
      dflt (fun _ ↦ alphaKey) (fun output ↦ (alphaKey, responseOf output))
    let win := fun merkleAnswers tape ↦
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
      let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
      let claim := (family.game tape).claim merkleAnswers
      claim.I = query.coordinates ∧
        Merkle.MH.Accepts
          (codec.withOracle ((family.game tape).oracle merkleAnswers)) n
          ((family.game tape).root merkleAnswers)
          claim.I claim.a claim.pf ∧
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) code scheme).accepts statement alpha
            (responseOf output) query (fun j ↦ claim.a j.1)
    ((eventSet fun value :
        (Fin merkleT → D) ×
          (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
            (SchemeChallenge F CheckedMask nw nq 1 Equations)
              (QuerySet n r)) ↦ win value.1 value.2).card : ℚ) /
        Fintype.card ((Fin merkleT → D) ×
          (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
            (SchemeChallenge F CheckedMask nw nq 1 Equations)
              (QuerySet n r))) ≤
      ((((prefixFuel * (prefixFuel - 1) / 2 +
            merkleT * (2 * prefixFuel + 1)) *
          Fintype.card D ^ (merkleT - 1) : ℕ) : ℚ) /
        Fintype.card (Fin merkleT → D)) +
      (N + 2) *
        (min 1 (hypergeometricRatio floor n r +
          (ResponseAgreement.multipliedProfile
            (fun a ↦ InterleavedJohnson.listBound n responseDistance (n - a))
            (ResponseAgreement.combinedProfile failureDenominator
              profileDenominator g failureProfile arithmeticProfile)).rawExcessContribution
                (ResponseAgreement.combinedDenominator failureDenominator
                  profileDenominator) n n 0 r floor) +
          (failureProfile.excessContribution failureDenominator n n 0 r
              (max (n - e - 1) (min n (g + baselineAgreement))) +
            arithmeticProfile.contribution profileDenominator n e g r)) := by
  classical
  letI : Nonempty (QuerySet n r) := QuerySet.nonempty hquery
  letI : Nonempty (Response F r w n 1) := ⟨⟨0, 0, 0⟩⟩
  dsimp only
  let reference : Fin (N + 2) → Bcs.TypedFiatShamir.Answer
      (SchemeChallenge F CheckedMask nw nq 1 Equations)
        (QuerySet n r) := fun _ ↦ dflt
  let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
    dflt (fun _ ↦ alphaKey) (fun output ↦ (alphaKey, responseOf output))
  let oracle := fun merkleAnswers ↦ SchemeOracle.ofColumns
    ((family.game reference).boundMessage dec merkleAnswers)
  let baseline := fun merkleAnswers alpha response ↦
    ResponseAgreement.baselineCoordinates floor
      (policyAcceptingCoordinates
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) code scheme)
        (oracle merkleAnswers) statement alpha response)
  let listed := fun merkleAnswers tape ↦
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
    let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
    ¬query.coordinates ⊆ baseline merkleAnswers alpha (responseOf output)
  let win := fun merkleAnswers tape ↦
    let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
    let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
    let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
    let claim := (family.game tape).claim merkleAnswers
    claim.I = query.coordinates ∧
      Merkle.MH.Accepts
        (codec.withOracle ((family.game tape).oracle merkleAnswers)) n
        ((family.game tape).root merkleAnswers)
        claim.I claim.a claim.pf ∧
      (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
        (repetitions := 1) code scheme).accepts statement alpha
          (responseOf output) query (fun j ↦ claim.a j.1)
  let pairTerm := failureProfile.excessContribution failureDenominator n n 0 r
      (max (n - e - 1) (min n (g + baselineAgreement))) +
    arithmeticProfile.contribution profileDenominator n e g r
  let responseExcess :=
    (ResponseAgreement.multipliedProfile
      (fun a ↦ InterleavedJohnson.listBound n responseDistance (n - a))
      (ResponseAgreement.combinedProfile failureDenominator profileDenominator g
        failureProfile arithmeticProfile)).rawExcessContribution
          (ResponseAgreement.combinedDenominator failureDenominator
            profileDenominator) n n 0 r floor
  have hcaseA : ∀ merkleAnswers i,
      ((eventSet (trace.caseA (listed merkleAnswers) (win merkleAnswers)
        (fun tape ↦ (family.game tape).Bad dec merkleAnswers) i)).card : ℚ) /
        Fintype.card (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
          (SchemeChallenge F CheckedMask nw nq 1 Equations)
            (QuerySet n r)) ≤
      min 1 (hypergeometricRatio floor n r + responseExcess) := by
    intro merkleAnswers i
    have hA := canonical_scheme_caseA_prefixBound_responseAgreement_ratio_le
      code scheme statement codec family dec merkleAnswers adversary dflt
      alphaKey responseOf reference i failureProfile arithmeticProfile
      (classifier merkleAnswers) hprofile hfailure hquery h2k hfloor hfarFloor
      hresponse hresponseRadius hresponseDen
    simpa only [trace, oracle, baseline, listed, win, reference, responseExcess]
      using hA
  have hcaseB : ∀ merkleAnswers i,
      ((eventSet (trace.caseB (win merkleAnswers)
        (fun tape ↦ (family.game tape).Bad dec merkleAnswers) i)).card : ℚ) /
        Fintype.card (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
          (SchemeChallenge F CheckedMask nw nq 1 Equations)
            (QuerySet n r)) ≤ pairTerm := by
    intro merkleAnswers i
    have hB := canonical_caseB_prefixBound_profiled_ratio_le
      code (ConstraintLayout.identity w)
      (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
        (repetitions := 1) code scheme)
      statement codec family dec merkleAnswers adversary dflt
      (fun _ ↦ alphaKey) responseOf fallback reference i failureProfile
      arithmeticProfile (fun _data ↦ classifier merkleAnswers _)
      hprofile hfailure hquery baselineAgreement hbaselineAgreement hprofileFloor
    simpa only [trace, win, reference, pairTerm] using hB
  have hcompiler := independent_prefixBinding_family_compiler_ratio_le
    codec family.game dec hprefix adversary dflt (fun _ ↦ alphaKey)
    responseOf listed win
    (min 1 (hypergeometricRatio floor n r + responseExcess)) pairTerm
    hcaseA hcaseB
  simpa only [responseExcess, pairTerm] using hcompiler


end LigeroFamily
