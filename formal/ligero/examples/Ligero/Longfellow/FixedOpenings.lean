import examples.Ligero.Grid.Rigid

set_option autoImplicit false
set_option relaxedAutoImplicit false
set_option warningAsError true

namespace Ligero.Examples.Grid.Rigid

open LigeroFamily CodingTheory FirstOccurrenceEventLedger.TypedCounts

/-- Every valid V1 rigid row turns the exact compiler coefficient into its
checked `2^-targetBits` bound. -/
theorem Result.v1_prefixBinding_ratio_le_of_bound
    (result : Result) (hparams : result.ParametersValid)
    (hbound : result.workNormalizedBound result.openings ≤
      (1 : ℚ) / 2 ^ result.certificate.targetBits)
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




/-- Fixed opening counts need a certified upper bound; they need no minimality claim. -/
theorem Result.bound_of_integer_upper_bound (result : Result)
    (hparams : result.ParametersValid)
    (hpassing : result.integerizedTotalNumerator result.openings *
      2 ^ result.certificate.targetBits ≤
        result.integerizedTotalDenominator result.openings) :
    result.workNormalizedBound result.openings ≤
      (1 : ℚ) / 2 ^ result.certificate.targetBits := by
  have hfieldLarge := hparams.2.2.2.1
  have hqueries := hparams.2.2.2.2.2.2.2.2.2.1
  have hfailure := result.failureDenominator_pos_of_field hfieldLarge
  have hfield : 0 < result.certificate.fieldSize :=
    (Nat.succ_pos result.g).trans hfieldLarge
  have hden := result.integerizedTotalDenominator_pos _ hqueries hfailure hfield
  have hpower : (0 : ℚ) < 2 ^ result.certificate.targetBits :=
    pow_pos (by norm_num) _
  rw [result.workNormalizedBound_eq_integerized _ hqueries hfailure hfield]
  unfold Result.integerizedWorkNormalizedBound
  rw [div_le_div_iff₀ (by exact_mod_cast hden) hpower]
  have hpassing' : (result.integerizedTotalNumerator result.openings : ℚ) *
      2 ^ result.certificate.targetBits ≤
        result.integerizedTotalDenominator result.openings := by
    exact_mod_cast hpassing
  simpa using hpassing'

namespace Longfellow

/-- Exact geometric and arithmetic certificate for one supported circuit component. -/
structure CertifiedResult where
  result : Result
  parameters : result.ParametersValid
  bound : result.workNormalizedBound result.openings ≤
    (1 : ℚ) / 2 ^ result.certificate.targetBits

end Longfellow

end Ligero.Examples.Grid.Rigid
