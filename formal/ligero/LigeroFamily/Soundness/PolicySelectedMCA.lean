import LigeroFamily.Soundness.PolicyLiftList
import LigeroFamily.Soundness.SchemeSelectedMCA
import LigeroFamily.Soundness.FiniteCounting
import LigeroFamily.Soundness.SelectedMCAParameters









namespace LigeroFamily

open CodingTheory MultiplicativeCode

variable {F Equations CheckedMask DirectMask Challenge Response Tail : Type*}
variable [Field F] [Fintype F] [DecidableEq F]
variable [Fintype Equations] [DecidableEq Equations]
variable [Fintype CheckedMask] [DecidableEq CheckedMask]
variable [Fintype Challenge] [DecidableEq Challenge]
variable [Fintype Tail] [DecidableEq Tail]
variable {q r w n nw nq e g d threshold : ℕ}

variable {C : MultiplicativeCode F r w n}
variable {layout : ConstraintLayout F q w}
variable {policy : SchemeProtocolPolicy (Equations := Equations) C layout
  Challenge Response CheckedMask DirectMask nw nq 1}
variable {oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1}
variable {respond : Challenge → Response}

/-- Split one simultaneous challenge into its opaque arithmetic tail and the
proximity weights consumed by selected-MCA. -/
structure SchemeExtractorPolicy
    (policy : SchemeProtocolPolicy (Equations := Equations) C layout
      Challenge Response CheckedMask DirectMask nw nq 1)
    (Tail : Type*) where
  challengeProductEquiv : Challenge ≃
    Tail × SchemeSelectedMCA.Weights F CheckedMask nw nq
  weights_eq : ∀ challenge,
    (challengeProductEquiv challenge).2 = policy.proximityWeights challenge 0

namespace SchemeExtractorPolicy

variable (extractor : SchemeExtractorPolicy policy Tail)

noncomputable def responseAtTail
    (tail : Tail) (weights : SchemeSelectedMCA.Weights F CheckedMask nw nq) :
    EvaluationRow F r w n :=
  policy.proximityResponse
    (respond (extractor.challengeProductEquiv.symm (tail, weights))) 0

noncomputable def badChallengePairs :
    Finset (Tail × SchemeSelectedMCA.Weights F CheckedMask nw nq) := by
  classical
  exact Finset.univ.filter fun pair => pair.2 ∈
    SchemeSelectedMCA.badWeights (C := C) (oracle := oracle) (e := e) (g := g)
      (extractor.responseAtTail (respond := respond) pair.1)

noncomputable def badChallenges : Finset Challenge := by
  classical
  exact (extractor.badChallengePairs (oracle := oracle) (respond := respond)
    (e := e) (g := g)).map extractor.challengeProductEquiv.symm.toEmbedding

noncomputable def failureAgreement (challenge : Challenge) : ℕ :=
  (schemeProximityAgreement oracle (policy.proximityWeights challenge 0)
    (policy.proximityResponse (respond challenge) 0)).card

noncomputable def badChallengePairsAtAgreement (a : ℕ) :
    Finset (Tail × SchemeSelectedMCA.Weights F CheckedMask nw nq) := by
  classical
  exact Finset.univ.filter fun pair => pair.2 ∈
    SchemeSelectedMCA.badWeightsAtAgreement
      (C := C) (oracle := oracle) (e := e) (g := g)
      (extractor.responseAtTail (respond := respond) pair.1) a

noncomputable def badChallengesAtAgreement (a : ℕ) : Finset Challenge := by
  classical
  exact (extractor.badChallengePairsAtAgreement (oracle := oracle)
    (respond := respond) (e := e) (g := g) a).map
      extractor.challengeProductEquiv.symm.toEmbedding

omit [Fintype Equations] [DecidableEq Equations] [Fintype Challenge]
    [DecidableEq Challenge] in
theorem badChallengePairsAtAgreement_card_eq_sum (a : ℕ) :
    (extractor.badChallengePairsAtAgreement (oracle := oracle)
      (respond := respond) (e := e) (g := g) a).card =
      ∑ tail : Tail,
        (SchemeSelectedMCA.badWeightsAtAgreement
          (C := C) (oracle := oracle) (e := e) (g := g)
          (extractor.responseAtTail (respond := respond) tail) a).card := by
  classical
  simpa [badChallengePairsAtAgreement] using
    (Internal.card_filter_product_eq_sum
      (First := Tail)
      (Second := SchemeSelectedMCA.Weights F CheckedMask nw nq)
      (fun tail weights => weights ∈
        SchemeSelectedMCA.badWeightsAtAgreement
          (C := C) (oracle := oracle) (e := e) (g := g)
          (extractor.responseAtTail (respond := respond) tail) a))

omit [Fintype Equations] [DecidableEq Equations] [Fintype Challenge]
    [DecidableEq Challenge] [DecidableEq Tail] in
theorem badChallengesAtAgreement_eq_restrictedTailSet (a : ℕ) :
    extractor.badChallengesAtAgreement (oracle := oracle)
        (respond := respond) (e := e) (g := g) a =
      AgreementProfile.restrictedTailSet
        (extractor.badChallenges (oracle := oracle)
          (respond := respond) (e := e) (g := g))
        (failureAgreement (policy := policy) (oracle := oracle)
          (respond := respond)) a := by
  classical
  ext challenge
  simp [badChallengesAtAgreement, badChallengePairsAtAgreement,
    badChallenges, badChallengePairs, SchemeSelectedMCA.badWeightsAtAgreement,
    AgreementProfile.restrictedTailSet, failureAgreement, responseAtTail]
  intro _hbad
  rw [extractor.weights_eq]

omit [Fintype Equations] [DecidableEq Equations] [DecidableEq Challenge] in
theorem badChallenges_agreement_density
    [Nonempty (SchemeTestedRow CheckedMask nw nq 1)]
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : SelectedMCAParameterConditions
      (Fintype.card F) n e g d threshold)
    (a : ℕ) :
    (Fintype.card F - (g + 1)) *
        (AgreementProfile.restrictedTailSet
          (extractor.badChallenges (oracle := oracle)
            (respond := respond) (e := e) (g := g))
          (failureAgreement (policy := policy) (oracle := oracle)
            (respond := respond)) a).card ≤
      (SchemeSelectedMCA.selectedMCAFailureProfile n g d
        (SelectedMCA.directLineFailureBound threshold)).labelsAtLeast a *
        Fintype.card Challenge := by
  classical
  have hfiber (tail : Tail) :=
    SchemeSelectedMCA.badWeightsAtAgreement_density
      (C := C) (oracle := oracle)
      (extractor.responseAtTail (respond := respond) tail) hmin
      conditions.direct.directClique
      conditions.punctured.punctured_three_radius
      conditions.punctured.field_large a
  have hpairDensity :
      (Fintype.card F - (g + 1)) *
          (extractor.badChallengePairsAtAgreement (oracle := oracle)
            (respond := respond) (e := e) (g := g) a).card ≤
        (SchemeSelectedMCA.selectedMCAFailureProfile n g d
          (SelectedMCA.directLineFailureBound threshold)).labelsAtLeast a *
          Fintype.card
            (Tail × SchemeSelectedMCA.Weights F CheckedMask nw nq) := by
    rw [extractor.badChallengePairsAtAgreement_card_eq_sum]
    simpa [Fintype.card_prod, Nat.mul_comm] using
      SelectedMCA.fiberwise_density_sum
        (fun tail : Tail =>
          SchemeSelectedMCA.badWeightsAtAgreement
            (C := C) (oracle := oracle) (e := e) (g := g)
            (extractor.responseAtTail (respond := respond) tail) a)
        ((SchemeSelectedMCA.selectedMCAFailureProfile n g d
          (SelectedMCA.directLineFailureBound threshold)).labelsAtLeast a)
        (Fintype.card F - (g + 1)) hfiber
  rw [← extractor.badChallengesAtAgreement_eq_restrictedTailSet
    (oracle := oracle) (respond := respond) (e := e) (g := g) a]
  have hcard :
      (extractor.badChallengesAtAgreement (oracle := oracle)
        (respond := respond) (e := e) (g := g) a).card =
      (extractor.badChallengePairsAtAgreement (oracle := oracle)
        (respond := respond) (e := e) (g := g) a).card := by
    simp [badChallengesAtAgreement]
  rw [hcard]
  rw [show Fintype.card Challenge =
      Fintype.card (Tail × SchemeSelectedMCA.Weights F CheckedMask nw nq) from
    Fintype.card_congr extractor.challengeProductEquiv]
  exact hpairDensity

omit [Fintype Equations] [DecidableEq Equations] [Fintype Challenge]
    [DecidableEq Challenge] [DecidableEq Tail] in
/-- The common selected-MCA extractor constructs the fixed lift list for any
arithmetic policy admitting the challenge split above. -/
theorem exists_policyLiftList_of_selectedMCA
    [Nonempty (SchemeTestedRow CheckedMask nw nq 1)]
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (hradius : e + g < d)
    (hden : 0 < CodingTheory.InterleavedJohnson.denominator n d (e + g)) :
    ∃ certificate : PolicyLiftListCertificate policy oracle respond e g (e + g)
      (CodingTheory.InterleavedJohnson.listBound n d (e + g)),
      certificate.failure = extractor.badChallenges (oracle := oracle)
        (respond := respond) (e := e) (g := g) := by
  classical
  let failure := extractor.badChallenges (oracle := oracle)
    (respond := respond) (e := e) (g := g)
  have hwitness (challenge : Challenge)
      (hnotFailure : challenge ∉ failure)
      (hresponse : policy.proximityResponse (respond challenge) 0 ∈ C.base)
      (hsmall : (schemeProximityDisagreement oracle
        (policy.proximityWeights challenge 0)
        (policy.proximityResponse (respond challenge) 0)).card ≤ e) :
      Nonempty (SchemeGLiftWitness C oracle
        (policy.proximityWeights challenge 0)
        (policy.proximityResponse (respond challenge) 0) g) := by
    let pair := extractor.challengeProductEquiv challenge
    have hweights : pair.2 = policy.proximityWeights challenge 0 :=
      extractor.weights_eq challenge
    have hresponseEq :
        extractor.responseAtTail (respond := respond) pair.1 pair.2 =
          policy.proximityResponse (respond challenge) 0 := by
      unfold responseAtTail
      rw [show (pair.1, pair.2) = pair from Prod.eta pair]
      change policy.proximityResponse
        (respond (extractor.challengeProductEquiv.symm
          (extractor.challengeProductEquiv challenge))) 0 = _
      rw [extractor.challengeProductEquiv.symm_apply_apply]
    have hnotBadWeight : pair.2 ∉
        SchemeSelectedMCA.badWeights
          (C := C) (oracle := oracle) (e := e) (g := g)
          (extractor.responseAtTail (respond := respond) pair.1) := by
      intro hbadWeight
      apply hnotFailure
      apply Finset.mem_map.mpr
      refine ⟨pair, ?_, extractor.challengeProductEquiv.symm_apply_apply challenge⟩
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, hbadWeight⟩
    have hwitnessPair :=
      SchemeSelectedMCA.gLiftWitness_nonempty_of_not_mem_badWeights
        (respond := extractor.responseAtTail (respond := respond) pair.1)
        pair.2 hnotBadWeight
        (by rw [hresponseEq]; exact hresponse)
        (by rw [hresponseEq, hweights]; exact hsmall)
    rw [hresponseEq, hweights] at hwitnessPair
    exact hwitnessPair
  obtain ⟨certificate, hcertificate⟩ :=
    PolicyLiftListCertificate.exists_of_gLiftWitnesses hmin hradius
      hden failure hwitness
  refine ⟨certificate, ?_⟩
  simpa [failure] using hcertificate

omit [Fintype Equations] [DecidableEq Equations] [DecidableEq Challenge] in
/-- Construct the fixed lift list together with the selected-MCA density
bound consumed by the profiled soundness theorem. -/
theorem exists_profiledPolicyLiftList_of_selectedMCA
    (extractor : SchemeExtractorPolicy policy Tail)
    [Nonempty (SchemeTestedRow CheckedMask nw nq 1)]
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : SelectedMCAParameterConditions
      (Fintype.card F) n e g d threshold) :
    ∃ certificate : PolicyLiftListCertificate policy oracle respond e g (e + g)
        (CodingTheory.InterleavedJohnson.listBound n d (e + g)),
      ∀ a ≤ n,
        (Fintype.card F - (g + 1)) *
            (AgreementProfile.restrictedTailSet certificate.failure
              (fun challenge =>
                (schemeProximityAgreement oracle
                  (policy.proximityWeights challenge 0)
                  (policy.proximityResponse (respond challenge) 0)).card) a).card ≤
          (SchemeSelectedMCA.selectedMCAFailureProfile n g d
            (SelectedMCA.directLineFailureBound threshold)).labelsAtLeast a *
            Fintype.card Challenge := by
  obtain ⟨certificate, hfailure⟩ :=
    exists_policyLiftList_of_selectedMCA (extractor := extractor)
      (oracle := oracle) (respond := respond) hmin
      (by have := conditions.punctured.punctured_three_radius; omega)
      conditions.johnson.list_denominator_positive
  refine ⟨certificate, ?_⟩
  intro a _ha
  rw [hfailure]
  exact extractor.badChallenges_agreement_density
    (oracle := oracle) (respond := respond) hmin conditions a

end SchemeExtractorPolicy

end LigeroFamily
