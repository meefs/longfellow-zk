import Ligero.V1.Soundness.V1EndToEnd
import Ligero.V1.ZeroKnowledge.ResponseAdaptive

/-!
# Collected V1 guarantees

This module owns the end-to-end statement for the V1 masking scheme. Shared
protocol mechanics and extraction remain in `LigeroFamily`; no sibling
protocol is imported here.
-/

namespace Ligero.V1

open LigeroFamily CodingTheory

variable {F Equations VerifierCoins : Type*}
variable [Field F] [Fintype F] [DecidableEq F]
variable [Fintype Equations] [DecidableEq Equations]
variable {r w n nw nq e g d m threshold : ℕ}

noncomputable local instance endToEndViewDecidableEq :
    DecidableEq
      (LigeroFamily.ZeroKnowledge.ResponseAdaptiveVerifierView VerifierCoins
        (Challenge F nw nq 1 Equations) (Response F r w n 1)
        (QuerySet n r) (Opening F nw nq 1 n r)) :=
  Classical.decEq _

/-- The selected-MCA soundness expression for V1 masking. -/
def selectedMCASoundnessBound (C : MultiplicativeCode F r w n)
    (e g d m threshold : ℕ) : ℚ :=
  (SchemeSelectedMCA.selectedMCAFailureProfile n g d
    (SelectedMCA.directLineFailureBound m)).contribution
      (Fintype.card F - (g + 1)) n n 0 r +
  (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1)
    (CodingTheory.InterleavedJohnson.listBound n d (e + g))
    threshold).contribution (Fintype.card F) n e g r






/-- **V1 extraction, sharp form.** -/
theorem candidate_of_acceptance
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (oracle : Oracle F nw nq n 1)
    (statement : ConstraintSystem F nw nq w Equations)
    (prover : IPCPProver
      (ConstraintSystem F nw nq w Equations) (Oracle F nw nq n 1)
      (Challenge F nw nq 1 Equations) (Response F r w n 1))
    (horacle : prover.commit statement = oracle)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : SelectedMCAParameterConditions (Fintype.card F) n e g d m)
    (johnson : V1JohnsonRange C threshold)
    (hrate : selectedMCASoundnessBound C e g d m threshold
      < (SchemeVerifier.protocol C scheme).acceptanceRate prover statement) :
    ∃ candidate : SchemeLiftCandidate C oracle (e + g),
      statement.Satisfies candidate.decodedMessages := by
  subst horacle
  by_contra hcon
  exact absurd (v1_ligero_soundness_selectedMCA hrows C statement prover
    (fun candidate hsat ↦ hcon ⟨candidate, hsat⟩) hmin conditions johnson)
    (not_le.mpr hrate)

/-- **V1 extraction, packaged.** -/
theorem witness_extractor
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : SelectedMCAParameterConditions (Fintype.card F) n e g d m)
    (johnson : V1JohnsonRange C threshold) :
    ∃ Ext : Oracle F nw nq n 1 →
        Fin (CodingTheory.InterleavedJohnson.listBound n d (e + g)) →
        CoreMessages F nw nq w,
      ∀ (oracle : Oracle F nw nq n 1)
        (statement : ConstraintSystem F nw nq w Equations)
        (prover : IPCPProver
          (ConstraintSystem F nw nq w Equations) (Oracle F nw nq n 1)
          (Challenge F nw nq 1 Equations) (Response F r w n 1)),
        prover.commit statement = oracle →
        selectedMCASoundnessBound C e g d m threshold
          < (SchemeVerifier.protocol C scheme).acceptanceRate prover statement →
        ∃ i, statement.Satisfies (Ext oracle i) := by
  refine ⟨fun oracle ↦ liftListIndex C oracle (e + g) _
      SchemeLiftCandidate.decodedMessages (zeroMessages F nw nq w), ?_⟩
  intro oracle statement prover horacle hrate
  refine exists_liftListIndex ?_
    (candidate_of_acceptance hrows C oracle statement prover horacle hmin
      conditions johnson hrate)
  have hdist : e + g < d := by
    have := conditions.punctured.punctured_three_radius; omega
  exact SchemeLiftCandidate.univ_card_le_listBound C oracle hmin
    (le_trans (le_of_lt hdist) hmin.distance_le_length) hdist
    conditions.johnson.list_denominator_positive

/-- Completeness, malicious-prover soundness, and exact response-adaptive
zero knowledge for one V1 protocol. -/
structure EndToEndGuarantee [Fintype VerifierCoins]
    (C : MultiplicativeCode F r w n) (e g d m threshold : ℕ) : Prop where
  perfectCompleteness : ∀ (statement : ConstraintSystem F nw nq w Equations)
      (messages : CoreMessages F nw nq w)
      (hsatisfies : statement.Satisfies messages),
    ∀ (seed : V1ProverRandomness C nw nq 1)
      (coins : Challenge F nw nq 1 Equations × QuerySet n r),
      (SchemeVerifier.protocol C scheme).accepts
        (seed.prover messages hsatisfies) statement coins = true
  soundness : ∀ (statement : ConstraintSystem F nw nq w Equations),
    ¬statement.Language →
    ∀ prover : IPCPProver
        (ConstraintSystem F nw nq w Equations) (Oracle F nw nq n 1)
        (Challenge F nw nq 1 Equations) (Response F r w n 1),
      (SchemeVerifier.protocol C scheme).acceptanceRate prover statement ≤
        selectedMCASoundnessBound C e g d m threshold
  
  extraction : ∃ Ext : Oracle F nw nq n 1 →
      Fin (CodingTheory.InterleavedJohnson.listBound n d (e + g)) →
      CoreMessages F nw nq w,
    ∀ (oracle : Oracle F nw nq n 1)
      (statement : ConstraintSystem F nw nq w Equations)
      (prover : IPCPProver
        (ConstraintSystem F nw nq w Equations) (Oracle F nw nq n 1)
        (Challenge F nw nq 1 Equations) (Response F r w n 1)),
      prover.commit statement = oracle →
      selectedMCASoundnessBound C e g d m threshold
        < (SchemeVerifier.protocol C scheme).acceptanceRate prover statement →
      ∃ i, statement.Satisfies (Ext oracle i)
  zeroKnowledge :
    LigeroFamily.ZeroKnowledge.UnboundedPerfectResponseAdaptiveZeroKnowledge
      (SchemeVerifier.protocol (nw := nw) (nq := nq) (repetitions := 1)
        (Equations := Equations) C scheme)
      (fun statement messages ↦ statement.Satisfies messages)
      (ZeroKnowledge.v1HonestProver (nw := nw) (nq := nq)
        (repetitions := 1) (Equations := Equations) C)
      (ZeroKnowledge.v1ResponseAdaptiveSimulator (C := C)
        (VerifierCoins := VerifierCoins))

/-- The collected V1 guarantee from the common selected-MCA extractor. -/
theorem end_to_end_selectedMCA
    [Fintype VerifierCoins]
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : SelectedMCAParameterConditions
      (Fintype.card F) n e g d m)
    (johnson : V1JohnsonRange C threshold) :
    EndToEndGuarantee (F := F) (Equations := Equations)
      (VerifierCoins := VerifierCoins) (nw := nw) (nq := nq)
      C e g d m threshold := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  refine {
    perfectCompleteness := ?_
    soundness := ?_
    extraction := witness_extractor hrows C hmin conditions johnson
    zeroKnowledge :=
      ZeroKnowledge.v1_unbounded_perfect_response_adaptive_zero_knowledge }
  · intro statement messages hsatisfies seed coins
    exact v1_ligero_perfect_completeness messages hsatisfies seed coins
  · intro statement hfalse prover
    exact v1_ligero_soundness_selectedMCA hrows C statement prover
      (NoDecodedSolution.of_not_language hfalse) hmin conditions johnson

end Ligero.V1
