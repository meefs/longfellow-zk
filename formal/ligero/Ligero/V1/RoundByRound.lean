import Ligero.V1.Soundness.V1EndToEnd
import LigeroFamily.Soundness.RoundByRound
import LigeroFamily.Soundness.RigidCompiler









namespace Ligero.V1

open LigeroFamily CodingTheory

variable {F Equations : Type*} [Field F] [Fintype F] [DecidableEq F]
variable [Fintype Equations] [DecidableEq Equations]
variable {r w n nw nq e g d m threshold cutoff localThreshold : ℕ}

/-- V1 profiled RBR soundness with the ordinary selected-MCA profile. -/
theorem ligerov1_roundByRound_profiled
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (prover : IPCPProver
      (ConstraintSystem F nw nq w Equations)
      (Oracle F nw nq n 1)
      (Challenge F nw nq 1 Equations)
      (Response F r w n 1))
    (hfalse : NoDecodedSolution C (prover.commit statement) (e + g) statement)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : SelectedMCAParameterConditions
      (Fintype.card F) n e g d m)
    (johnson : V1JohnsonRange C threshold)
    (failureThreshold arithmeticThreshold : ℕ)
    (hfailureThreshold : failureThreshold + 1 ≤ n)
    (harithmeticThreshold : arithmeticThreshold + 1 ≤ n) :
    ∃ classifier : PolicyDoublyProfiledSoundnessClassifier
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) C scheme)
        (prover.commit statement) statement
        (fun challenge ↦ prover.respond statement (prover.commit statement) challenge)
        (SchemeSelectedMCA.selectedMCAFailureProfile n g d
          (SelectedMCA.directLineFailureBound m))
        (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1)
          (InterleavedJohnson.listBound n d (e + g)) threshold)
        (Fintype.card F) (Fintype.card F - (g + 1)) e g,
      (∀ challenge, classifier.ProfiledDoomedAfter
          failureThreshold arithmeticThreshold challenge →
        ((classifier.acceptingQueries challenge).card : ℚ) / (n.choose r) ≤
          hypergeometricRatio
            (max failureThreshold
              (max (n - e - 1) (min n (g + arithmeticThreshold)))) n r)
      ∧ ((classifier.profiledEscaping
            failureThreshold arithmeticThreshold).card : ℚ) /
            Fintype.card (Challenge F nw nq 1 Equations) ≤
          ((SchemeSelectedMCA.selectedMCAFailureProfile n g d
              (SelectedMCA.directLineFailureBound m)).labelsAtLeast
                (failureThreshold + 1) : ℚ) /
              ((Fintype.card F - (g + 1) : ℕ) : ℚ) +
            ((uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1)
              (InterleavedJohnson.listBound n d (e + g)) threshold).labelsAtLeast
                (arithmeticThreshold + 1) : ℚ) / Fintype.card F
      ∧ (∀ challenge, ¬ classifier.ProfiledDoomedAfter
            failureThreshold arithmeticThreshold challenge →
          challenge ∈ classifier.profiledEscaping
            failureThreshold arithmeticThreshold) := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let respond := fun challenge ↦
    prover.respond statement (prover.commit statement) challenge
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C scheme
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_selectedMCA
      (oracle := prover.commit statement) (respond := respond) hmin
      (conditions.lineConditions hmin)
  obtain ⟨arithmetic⟩ :=
    Ligero.V1.PolicyLiftListCertificate.v1ArithmeticCertificate_nonempty
      certificate hfalse johnson
  obtain ⟨classifier⟩ :=
    arithmetic.doublyProfiledClassifier_nonempty
      (failureProfile := SchemeSelectedMCA.selectedMCAFailureProfile n g d
        (SelectedMCA.directLineFailureBound m))
      (failureDenominator := Fintype.card F - (g + 1))
      certificate hdensity
  refine ⟨classifier, ?_, ?_, ?_⟩
  · intro challenge hdoom
    exact classifier.query_density_le_of_profiledDoomedAfter
      failureThreshold arithmeticThreshold challenge hdoom
  · refine classifier.profiledEscaping_density_le
      failureThreshold arithmeticThreshold
      hfailureThreshold harithmeticThreshold ?_ ?_
    · exact Nat.sub_pos_of_lt conditions.punctured.field_large
    · exact Fintype.card_pos
  · intro challenge hdoom
    exact classifier.not_profiledDoomedAfter_mem_profiledEscaping hdoom

/-- V1 profiled RBR soundness with an agreement-local selected-MCA tail. -/
theorem ligerov1_roundByRound_profiledRefined
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (prover : IPCPProver
      (ConstraintSystem F nw nq w Equations)
      (Oracle F nw nq n 1)
      (Challenge F nw nq 1 Equations)
      (Response F r w n 1))
    (hfalse : NoDecodedSolution C (prover.commit statement) (e + g) statement)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : RefinedSelectedMCAParameterConditions
      (Fintype.card F) n e g d m cutoff localThreshold)
    (johnson : V1JohnsonRange C threshold)
    (failureThreshold arithmeticThreshold : ℕ)
    (hfailureThreshold : failureThreshold + 1 ≤ n)
    (harithmeticThreshold : arithmeticThreshold + 1 ≤ n) :
    ∃ classifier : PolicyDoublyProfiledSoundnessClassifier
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) C scheme)
        (prover.commit statement) statement
        (fun challenge ↦ prover.respond statement (prover.commit statement) challenge)
        (SchemeSelectedMCA.selectedMCARefinedFailureProfile n g d
          (SelectedMCA.directLineFailureBound m) cutoff
          (SelectedMCA.directLineFailureBound localThreshold))
        (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1)
          (InterleavedJohnson.listBound n d (e + g)) threshold)
        (Fintype.card F) (Fintype.card F - (g + 1)) e g,
      (∀ challenge, classifier.ProfiledDoomedAfter
          failureThreshold arithmeticThreshold challenge →
        ((classifier.acceptingQueries challenge).card : ℚ) / (n.choose r) ≤
          hypergeometricRatio
            (max failureThreshold
              (max (n - e - 1) (min n (g + arithmeticThreshold)))) n r)
      ∧ ((classifier.profiledEscaping
            failureThreshold arithmeticThreshold).card : ℚ) /
            Fintype.card (Challenge F nw nq 1 Equations) ≤
          ((SchemeSelectedMCA.selectedMCARefinedFailureProfile n g d
              (SelectedMCA.directLineFailureBound m) cutoff
              (SelectedMCA.directLineFailureBound localThreshold)).labelsAtLeast
                (failureThreshold + 1) : ℚ) /
              ((Fintype.card F - (g + 1) : ℕ) : ℚ) +
            ((uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1)
              (InterleavedJohnson.listBound n d (e + g)) threshold).labelsAtLeast
                (arithmeticThreshold + 1) : ℚ) / Fintype.card F
      ∧ (∀ challenge, ¬ classifier.ProfiledDoomedAfter
            failureThreshold arithmeticThreshold challenge →
          challenge ∈ classifier.profiledEscaping
            failureThreshold arithmeticThreshold) := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let respond := fun challenge ↦
    prover.respond statement (prover.commit statement) challenge
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C scheme
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_refinedSelectedMCA
      (oracle := prover.commit statement) (respond := respond) hmin conditions
  obtain ⟨arithmetic⟩ :=
    Ligero.V1.PolicyLiftListCertificate.v1ArithmeticCertificate_nonempty
      certificate hfalse johnson
  obtain ⟨classifier⟩ :=
    arithmetic.doublyProfiledClassifier_nonempty
      (failureProfile := SchemeSelectedMCA.selectedMCARefinedFailureProfile n g d
        (SelectedMCA.directLineFailureBound m) cutoff
        (SelectedMCA.directLineFailureBound localThreshold))
      (failureDenominator := Fintype.card F - (g + 1))
      certificate hdensity
  refine ⟨classifier, ?_, ?_, ?_⟩
  · intro challenge hdoom
    exact classifier.query_density_le_of_profiledDoomedAfter
      failureThreshold arithmeticThreshold challenge hdoom
  · refine classifier.profiledEscaping_density_le
      failureThreshold arithmeticThreshold
      hfailureThreshold harithmeticThreshold ?_ ?_
    · exact Nat.sub_pos_of_lt
        conditions.toSelectedMCAParameterConditions.punctured.field_large
    · exact Fintype.card_pos
  · intro challenge hdoom
    exact classifier.not_profiledDoomedAfter_mem_profiledEscaping hdoom

/-- Threshold-free V1 classifier for an arbitrary fixed response strategy.
This is the strategy-uniform endpoint consumed by response-rigid Case A. -/
theorem ligerov1_profiledIntegrated_classifier_nonempty
    {localThreshold : ℕ → ℕ}
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : Oracle F nw nq n 1)
    (respond : Challenge F nw nq 1 Equations → Response F r w n 1)
    (hfalse : NoDecodedSolution C oracle (e + g) statement)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : IntegratedSelectedMCAParameterConditions
      (Fintype.card F) n e g d m localThreshold)
    (johnson : V1JohnsonRange C threshold) :
    Nonempty (PolicyDoublyProfiledSoundnessClassifier
      (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
        (repetitions := 1) C scheme)
      oracle statement respond
      (SchemeSelectedMCA.selectedMCAIntegratedFailureProfile n e g d
        (SelectedMCA.directLineFailureBound m)
        (fun a ↦ SelectedMCA.directLineFailureBound (localThreshold a)))
      (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1)
        (InterleavedJohnson.listBound n d (e + g)) threshold)
      (Fintype.card F) (Fintype.card F - (g + 1)) e g) := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C scheme
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_integratedLine
      (oracle := oracle) (respond := respond) hmin
      (conditions.lineConditions hmin)
  obtain ⟨arithmetic⟩ :=
    Ligero.V1.PolicyLiftListCertificate.v1ArithmeticCertificate_nonempty
      certificate hfalse johnson
  exact arithmetic.doublyProfiledClassifier_nonempty
    (failureProfile := SchemeSelectedMCA.selectedMCAIntegratedFailureProfile
      n e g d (SelectedMCA.directLineFailureBound m)
      (fun a ↦ SelectedMCA.directLineFailureBound (localThreshold a)))
    (failureDenominator := Fintype.card F - (g + 1)) certificate hdensity

/-- Endpoint-optimized threshold-free V1 classifier. -/
theorem ligerov1_profiledOptimizedIntegrated_classifier_nonempty
    {localThreshold : ℕ → ℕ}
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : Oracle F nw nq n 1)
    (respond : Challenge F nw nq 1 Equations → Response F r w n 1)
    (hfalse : NoDecodedSolution C oracle (e + g) statement)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : IntegratedSelectedMCAParameterConditions
      (Fintype.card F) n e g d m localThreshold)
    (johnson : V1JohnsonRange C threshold) :
    Nonempty (PolicyDoublyProfiledSoundnessClassifier
      (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
        (repetitions := 1) C scheme)
      oracle statement respond
      (SchemeSelectedMCA.selectedMCAOptimizedIntegratedFailureProfile
        (Fintype.card F) n e g d
        (SelectedMCA.directLineFailureBound m)
        (fun a ↦ SelectedMCA.directLineFailureBound (localThreshold a)))
      (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1)
        (InterleavedJohnson.listBound n d (e + g)) threshold)
      (Fintype.card F)
      (SchemeSelectedMCA.selectedMCAOptimizedFailureDenominator
        (Fintype.card F) g) e g) := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C scheme
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_endpointOptimizedIntegratedLine
      (oracle := oracle) (respond := respond) hmin
      (conditions.lineConditions hmin)
  obtain ⟨arithmetic⟩ :=
    Ligero.V1.PolicyLiftListCertificate.v1ArithmeticCertificate_nonempty
      certificate hfalse johnson
  exact arithmetic.doublyProfiledClassifier_nonempty
    (failureProfile :=
      SchemeSelectedMCA.selectedMCAOptimizedIntegratedFailureProfile
        (Fintype.card F) n e g d (SelectedMCA.directLineFailureBound m)
        (fun a ↦ SelectedMCA.directLineFailureBound (localThreshold a)))
    (failureDenominator :=
      SchemeSelectedMCA.selectedMCAOptimizedFailureDenominator
        (Fintype.card F) g) certificate hdensity

/-- Endpoint-optimized strategy-uniform V1 classifier in the singleton
lift-list regime. -/
theorem ligerov1_profiledOptimizedIntegrated_unique_classifier_nonempty
    {localThreshold : ℕ → ℕ}
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : Oracle F nw nq n 1)
    (respond : Challenge F nw nq 1 Equations → Response F r w n 1)
    (hfalse : NoDecodedSolution C oracle (e + g) statement)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : IntegratedSelectedMCAParameterConditions
      (Fintype.card F) n e g d m localThreshold)
    (hunique : 2 * (e + g) < d)
    (johnson : V1JohnsonRange C threshold) :
    Nonempty (PolicyDoublyProfiledSoundnessClassifier
      (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
        (repetitions := 1) C scheme)
      oracle statement respond
      (SchemeSelectedMCA.selectedMCAOptimizedIntegratedFailureProfile
        (Fintype.card F) n e g d
        (SelectedMCA.directLineFailureBound m)
        (fun a ↦ SelectedMCA.directLineFailureBound (localThreshold a)))
      (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1) 1 threshold)
      (Fintype.card F)
      (SchemeSelectedMCA.selectedMCAOptimizedFailureDenominator
        (Fintype.card F) g) e g) := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C scheme
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_endpointOptimizedIntegratedLine_unique
      (oracle := oracle) (respond := respond) hmin
      (conditions.lineConditions hmin) hunique
  obtain ⟨arithmetic⟩ :=
    Ligero.V1.PolicyLiftListCertificate.v1ArithmeticCertificate_nonempty
      certificate hfalse johnson
  exact arithmetic.doublyProfiledClassifier_nonempty
    (failureProfile :=
      SchemeSelectedMCA.selectedMCAOptimizedIntegratedFailureProfile
        (Fintype.card F) n e g d (SelectedMCA.directLineFailureBound m)
        (fun a ↦ SelectedMCA.directLineFailureBound (localThreshold a)))
    (failureDenominator :=
      SchemeSelectedMCA.selectedMCAOptimizedFailureDenominator
        (Fintype.card F) g) certificate hdensity

/-- Strategy-uniform V1 classifier in the singleton lift-list regime. -/
theorem ligerov1_profiledIntegrated_unique_classifier_nonempty
    {localThreshold : ℕ → ℕ}
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : Oracle F nw nq n 1)
    (respond : Challenge F nw nq 1 Equations → Response F r w n 1)
    (hfalse : NoDecodedSolution C oracle (e + g) statement)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : IntegratedSelectedMCAParameterConditions
      (Fintype.card F) n e g d m localThreshold)
    (hunique : 2 * (e + g) < d)
    (johnson : V1JohnsonRange C threshold) :
    Nonempty (PolicyDoublyProfiledSoundnessClassifier
      (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
        (repetitions := 1) C scheme)
      oracle statement respond
      (SchemeSelectedMCA.selectedMCAIntegratedFailureProfile n e g d
        (SelectedMCA.directLineFailureBound m)
        (fun a ↦ SelectedMCA.directLineFailureBound (localThreshold a)))
      (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1) 1 threshold)
      (Fintype.card F) (Fintype.card F - (g + 1)) e g) := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C scheme
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_integratedLine_unique
      (oracle := oracle) (respond := respond) hmin
      (conditions.lineConditions hmin) hunique
  obtain ⟨arithmetic⟩ :=
    Ligero.V1.PolicyLiftListCertificate.v1ArithmeticCertificate_nonempty
      certificate hfalse johnson
  exact arithmetic.doublyProfiledClassifier_nonempty
    (failureProfile := SchemeSelectedMCA.selectedMCAIntegratedFailureProfile
      n e g d (SelectedMCA.directLineFailureBound m)
      (fun a ↦ SelectedMCA.directLineFailureBound (localThreshold a)))
    (failureDenominator := Fintype.card F - (g + 1)) certificate hdensity

/-- Complete response-rigid Case-A semantic theorem for V1, using the
canonical verifier-defined response lists and the exact integrated
strategy-uniform classifier. -/
theorem ligerov1_profiledIntegrated_indexedListedPairs_ratio_le
    {Data : Type*} {responseDistance agreement : ℕ}
    {localThreshold : ℕ → ℕ}
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : Data → Oracle F nw nq n 1)
    (hfalse : ∀ data, NoDecodedSolution C (oracle data) (e + g) statement)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : IntegratedSelectedMCAParameterConditions
      (Fintype.card F) n e g d m localThreshold)
    (johnson : V1JohnsonRange C threshold)
    (h2k : 2 * C.k ≤ n)
    (hresponse : HasMinimumDistanceAtLeast C.responseCode responseDistance)
    (hbaseRadius : n - agreement < d)
    (hresponseRadius : n - agreement < responseDistance)
    (hbaseDen : 0 < InterleavedJohnson.denominator n d (n - agreement))
    (hresponseDen : 0 <
      InterleavedJohnson.denominator n responseDistance (n - agreement))
    (hquery : r ≤ n) :
    ∀ data,
      ((LigeroFamily.eventSet fun value :
          Response F r w n 1 ×
            (QuerySet n r × Challenge F nw nq 1 Equations) ↦
        value.1 ∈ LigeroFamily.RigidResponseList.schemeListedResponses
          C scheme statement (oracle data) value.2.2 agreement ∧
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) C scheme).accepts statement value.2.2 value.1
            value.2.1 (openSchemeOracle (oracle data) value.2.1)).card : ℚ) /
          Fintype.card (QuerySet n r × Challenge F nw nq 1 Equations) ≤
        (InterleavedJohnson.listBound n d (n - agreement) *
          InterleavedJohnson.listBound n responseDistance (n - agreement) *
          InterleavedJohnson.listBound n responseDistance (n - agreement)) *
        ((SchemeSelectedMCA.selectedMCAIntegratedFailureProfile n e g d
            (SelectedMCA.directLineFailureBound m)
            (fun a ↦ SelectedMCA.directLineFailureBound
              (localThreshold a))).contribution
              (Fintype.card F - (g + 1)) n n 0 r +
          (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1)
            (InterleavedJohnson.listBound n d (e + g)) threshold).contribution
              (Fintype.card F) n e g r) := by
  letI : Nonempty (QuerySet n r) := QuerySet.nonempty hquery
  letI : Nonempty (Response F r w n 1) := ⟨⟨0, 0, 0⟩⟩
  let listBound :=
    InterleavedJohnson.listBound n d (n - agreement) *
      InterleavedJohnson.listBound n responseDistance (n - agreement) *
      InterleavedJohnson.listBound n responseDistance (n - agreement)
  have hgeneric :=
    LigeroFamily.FirstOccurrenceEventLedger.TypedCounts.profiled_indexed_response_lists_pair_ratio_le
      (F := F) (Equations := Equations) (CheckedMask := NoMask)
      (DirectMask := Mask) (Response := Response F r w n 1)
      (Data := Data) (Alpha := Challenge F nw nq 1 Equations)
      (n := n) (r := r) (logicalWidth := w) (w := w) (nw := nw)
      (nq := nq) (e := e) (g := g)
      (profileDenominator := Fintype.card F)
      (failureDenominator := Fintype.card F - (g + 1))
      (C := C) (layout := ConstraintLayout.identity w)
      (policy := SchemeVerifier.policy (Equations := Equations)
        (nw := nw) (nq := nq) (repetitions := 1) C scheme)
      (oracle := oracle) (statement := statement)
      (failureProfile :=
        SchemeSelectedMCA.selectedMCAIntegratedFailureProfile n e g d
          (SelectedMCA.directLineFailureBound m)
          (fun a ↦ SelectedMCA.directLineFailureBound (localThreshold a)))
      (arithmeticProfile := uncheckedAgreementProfile (Fintype.card F) n
        (2 * C.k - 1) (InterleavedJohnson.listBound n d (e + g)) threshold)
      (responses := fun data challenge ↦
        LigeroFamily.RigidResponseList.schemeListedResponses C scheme statement
          (oracle data) challenge agreement)
      (listBound := listBound)
      (hlist := by
        intro data challenge
        exact LigeroFamily.RigidResponseList.schemeListedResponses_card_le
          C h2k scheme statement (oracle data) challenge agreement hmin
          hresponse hbaseRadius hresponseRadius hbaseDen hresponseDen)
      (classifier := fun data strategy ↦
        Classical.choice (ligerov1_profiledIntegrated_classifier_nonempty
          hrows C statement (oracle data) strategy (hfalse data) hmin conditions
          johnson))
      Fintype.card_pos
      (Nat.sub_pos_of_lt
        conditions.toSelectedMCAParameterConditions.punctured.field_large)
      hquery
  simpa [listBound, Nat.cast_mul] using hgeneric

/-- Threshold-free profiled V1 RBR soundness. -/
theorem ligerov1_roundByRound_profiledIntegrated
    {localThreshold : ℕ → ℕ}
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (prover : IPCPProver
      (ConstraintSystem F nw nq w Equations)
      (Oracle F nw nq n 1)
      (Challenge F nw nq 1 Equations)
      (Response F r w n 1))
    (hfalse : NoDecodedSolution C (prover.commit statement) (e + g) statement)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : IntegratedSelectedMCAParameterConditions
      (Fintype.card F) n e g d m localThreshold)
    (johnson : V1JohnsonRange C threshold)
    (failureThreshold arithmeticThreshold : ℕ)
    (hfailureThreshold : failureThreshold + 1 ≤ n)
    (harithmeticThreshold : arithmeticThreshold + 1 ≤ n) :
    ∃ classifier : PolicyDoublyProfiledSoundnessClassifier
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) C scheme)
        (prover.commit statement) statement
        (fun challenge ↦ prover.respond statement (prover.commit statement) challenge)
        (SchemeSelectedMCA.selectedMCAIntegratedFailureProfile n e g d
          (SelectedMCA.directLineFailureBound m)
          (fun a ↦ SelectedMCA.directLineFailureBound (localThreshold a)))
        (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1)
          (InterleavedJohnson.listBound n d (e + g)) threshold)
        (Fintype.card F) (Fintype.card F - (g + 1)) e g,
      (∀ challenge, classifier.ProfiledDoomedAfter
          failureThreshold arithmeticThreshold challenge →
        ((classifier.acceptingQueries challenge).card : ℚ) / (n.choose r) ≤
          hypergeometricRatio
            (max failureThreshold
              (max (n - e - 1) (min n (g + arithmeticThreshold)))) n r)
      ∧ ((classifier.profiledEscaping
            failureThreshold arithmeticThreshold).card : ℚ) /
            Fintype.card (Challenge F nw nq 1 Equations) ≤
          ((SchemeSelectedMCA.selectedMCAIntegratedFailureProfile n e g d
              (SelectedMCA.directLineFailureBound m)
              (fun a ↦ SelectedMCA.directLineFailureBound
                (localThreshold a))).labelsAtLeast
                (failureThreshold + 1) : ℚ) /
              ((Fintype.card F - (g + 1) : ℕ) : ℚ) +
            ((uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1)
              (InterleavedJohnson.listBound n d (e + g)) threshold).labelsAtLeast
                (arithmeticThreshold + 1) : ℚ) / Fintype.card F
      ∧ (∀ challenge, ¬ classifier.ProfiledDoomedAfter
            failureThreshold arithmeticThreshold challenge →
          challenge ∈ classifier.profiledEscaping
            failureThreshold arithmeticThreshold) := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let respond := fun challenge ↦
    prover.respond statement (prover.commit statement) challenge
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C scheme
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_integratedLine
      (oracle := prover.commit statement) (respond := respond) hmin
      (conditions.lineConditions hmin)
  obtain ⟨arithmetic⟩ :=
    Ligero.V1.PolicyLiftListCertificate.v1ArithmeticCertificate_nonempty
      certificate hfalse johnson
  obtain ⟨classifier⟩ :=
    arithmetic.doublyProfiledClassifier_nonempty
      (failureProfile := SchemeSelectedMCA.selectedMCAIntegratedFailureProfile
        n e g d (SelectedMCA.directLineFailureBound m)
        (fun a ↦ SelectedMCA.directLineFailureBound (localThreshold a)))
      (failureDenominator := Fintype.card F - (g + 1))
      certificate hdensity
  refine ⟨classifier, ?_, ?_, ?_⟩
  · intro challenge hdoom
    exact classifier.query_density_le_of_profiledDoomedAfter
      failureThreshold arithmeticThreshold challenge hdoom
  · refine classifier.profiledEscaping_density_le
      failureThreshold arithmeticThreshold
      hfailureThreshold harithmeticThreshold ?_ ?_
    · exact Nat.sub_pos_of_lt
        conditions.toSelectedMCAParameterConditions.punctured.field_large
    · exact Fintype.card_pos
  · intro challenge hdoom
    exact classifier.not_profiledDoomedAfter_mem_profiledEscaping hdoom

/-- Threshold-free profiled V1 RBR soundness with a singleton lift list. -/
theorem ligerov1_roundByRound_profiledIntegrated_unique
    {localThreshold : ℕ → ℕ}
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (prover : IPCPProver
      (ConstraintSystem F nw nq w Equations)
      (Oracle F nw nq n 1)
      (Challenge F nw nq 1 Equations)
      (Response F r w n 1))
    (hfalse : NoDecodedSolution C (prover.commit statement) (e + g) statement)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : IntegratedSelectedMCAParameterConditions
      (Fintype.card F) n e g d m localThreshold)
    (hunique : 2 * (e + g) < d)
    (johnson : V1JohnsonRange C threshold)
    (failureThreshold arithmeticThreshold : ℕ)
    (hfailureThreshold : failureThreshold + 1 ≤ n)
    (harithmeticThreshold : arithmeticThreshold + 1 ≤ n) :
    ∃ classifier : PolicyDoublyProfiledSoundnessClassifier
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) C scheme)
        (prover.commit statement) statement
        (fun challenge ↦ prover.respond statement (prover.commit statement) challenge)
        (SchemeSelectedMCA.selectedMCAIntegratedFailureProfile n e g d
          (SelectedMCA.directLineFailureBound m)
          (fun a ↦ SelectedMCA.directLineFailureBound (localThreshold a)))
        (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1) 1 threshold)
        (Fintype.card F) (Fintype.card F - (g + 1)) e g,
      (∀ challenge, classifier.ProfiledDoomedAfter
          failureThreshold arithmeticThreshold challenge →
        ((classifier.acceptingQueries challenge).card : ℚ) / (n.choose r) ≤
          hypergeometricRatio
            (max failureThreshold
              (max (n - e - 1) (min n (g + arithmeticThreshold)))) n r)
      ∧ ((classifier.profiledEscaping
            failureThreshold arithmeticThreshold).card : ℚ) /
            Fintype.card (Challenge F nw nq 1 Equations) ≤
          ((SchemeSelectedMCA.selectedMCAIntegratedFailureProfile n e g d
              (SelectedMCA.directLineFailureBound m)
              (fun a ↦ SelectedMCA.directLineFailureBound
                (localThreshold a))).labelsAtLeast
                (failureThreshold + 1) : ℚ) /
              ((Fintype.card F - (g + 1) : ℕ) : ℚ) +
            ((uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1) 1
              threshold).labelsAtLeast (arithmeticThreshold + 1) : ℚ) /
              Fintype.card F
      ∧ (∀ challenge, ¬ classifier.ProfiledDoomedAfter
            failureThreshold arithmeticThreshold challenge →
          challenge ∈ classifier.profiledEscaping
            failureThreshold arithmeticThreshold) := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let respond := fun challenge ↦
    prover.respond statement (prover.commit statement) challenge
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C scheme
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_integratedLine_unique
      (oracle := prover.commit statement) (respond := respond) hmin
      (conditions.lineConditions hmin) hunique
  obtain ⟨arithmetic⟩ :=
    Ligero.V1.PolicyLiftListCertificate.v1ArithmeticCertificate_nonempty
      certificate hfalse johnson
  obtain ⟨classifier⟩ :=
    arithmetic.doublyProfiledClassifier_nonempty
      (failureProfile := SchemeSelectedMCA.selectedMCAIntegratedFailureProfile
        n e g d (SelectedMCA.directLineFailureBound m)
        (fun a ↦ SelectedMCA.directLineFailureBound (localThreshold a)))
      (failureDenominator := Fintype.card F - (g + 1))
      certificate hdensity
  refine ⟨classifier, ?_, ?_, ?_⟩
  · intro challenge hdoom
    exact classifier.query_density_le_of_profiledDoomedAfter
      failureThreshold arithmeticThreshold challenge hdoom
  · refine classifier.profiledEscaping_density_le
      failureThreshold arithmeticThreshold
      hfailureThreshold harithmeticThreshold ?_ ?_
    · exact Nat.sub_pos_of_lt
        conditions.toSelectedMCAParameterConditions.punctured.field_large
    · exact Fintype.card_pos
  · intro challenge hdoom
    exact classifier.not_profiledDoomedAfter_mem_profiledEscaping hdoom

end Ligero.V1
