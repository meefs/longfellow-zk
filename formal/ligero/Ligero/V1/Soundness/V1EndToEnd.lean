import LigeroFamily.Soundness.SchemePolicyExtractor
import Ligero.V1.Soundness.V1Profile

/-!
# End-to-end V1 soundness from selected MCA

This is the non-semantic public entry point: arbitrary-code extraction
supplies punctured selected-MCA witnesses, the common architecture
builds the fixed Johnson list, and the V1 mask profile completes the proof.
-/

namespace Ligero.V1

open LigeroFamily

open CodingTheory

variable {F Equations : Type*} [Field F] [Fintype F] [DecidableEq F]
variable [Fintype Equations] [DecidableEq Equations]
variable {r w n nw nq e g d bound threshold : ℕ}





theorem v1_ligero_soundness_selectedMCA
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
    (conditions : LigeroFamily.SelectedMCALineConditions C.baseCode
      (Fintype.card F) e g d bound)
    (johnson : V1JohnsonRange C threshold) :
    (SchemeVerifier.protocol C scheme).acceptanceRate prover statement ≤
      (SchemeSelectedMCA.selectedMCAFailureProfile n g d
        (bound)).excessContribution
          (Fintype.card F - (g + 1)) n n 0 r
          (max (n - e - 1) (min n (g + (threshold - 1)))) +
      (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1)
        (CodingTheory.InterleavedJohnson.listBound n d (e + g))
        threshold).contribution (Fintype.card F) n e g r := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let respond := fun challenge ↦
    prover.respond statement (prover.commit statement) challenge
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C scheme
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_selectedMCA
      (oracle := prover.commit statement) (respond := respond)
      hmin conditions
  exact v1_ligero_soundness_of_eventPartition certificate
    (SchemeSelectedMCA.selectedMCAFailureProfile n g d
      (bound)) hdensity hfalse johnson
    prover rfl (fun _ ↦ rfl)
      (Nat.sub_pos_of_lt conditions.punctured.field_large)

/-- Public V1 soundness endpoint with an agreement-local failure profile.
The underlying selected-MCA extraction is confined to the policy module; the
protocol and grid surfaces consume only this refined line interface. -/
theorem v1_ligero_soundness_refined
    {outerBound cutoff localBound : ℕ}
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
    (conditions : RefinedSelectedMCALineConditions C.baseCode
      (Fintype.card F) e g d outerBound cutoff localBound)
    (johnson : V1JohnsonRange C threshold) :
    (SchemeVerifier.protocol C scheme).acceptanceRate prover statement ≤
      (SchemeSelectedMCA.selectedMCARefinedFailureProfile n g d
        outerBound cutoff localBound).excessContribution
          (Fintype.card F - (g + 1)) n n 0 r
          (max (n - e - 1) (min n (g + (threshold - 1)))) +
      (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1)
        (CodingTheory.InterleavedJohnson.listBound n d (e + g))
        threshold).contribution (Fintype.card F) n e g r := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let respond := fun challenge ↦
    prover.respond statement (prover.commit statement) challenge
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C scheme
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_refinedLine
      (oracle := prover.commit statement) (respond := respond)
      hmin conditions
  exact v1_ligero_soundness_of_eventPartition certificate
    (SchemeSelectedMCA.selectedMCARefinedFailureProfile n g d
      outerBound cutoff localBound) hdensity hfalse johnson
    prover rfl (fun _ ↦ rfl)
      (Nat.sub_pos_of_lt conditions.outer.punctured.field_large)

/-- Threshold-free V1 endpoint using the exact pointwise MCA integral. -/
theorem v1_ligero_soundness_integrated
    {outerBound : ℕ} {localBound : ℕ → ℕ}
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
    (conditions : IntegratedSelectedMCALineConditions C.baseCode
      (Fintype.card F) e g d outerBound localBound)
    (johnson : V1JohnsonRange C threshold) :
    (SchemeVerifier.protocol C scheme).acceptanceRate prover statement ≤
      (SchemeSelectedMCA.selectedMCAIntegratedFailureProfile n e g d
        outerBound localBound).excessContribution
          (Fintype.card F - (g + 1)) n n 0 r
          (max (n - e - 1) (min n (g + (threshold - 1)))) +
      (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1)
        (CodingTheory.InterleavedJohnson.listBound n d (e + g))
        threshold).contribution (Fintype.card F) n e g r := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let respond := fun challenge ↦
    prover.respond statement (prover.commit statement) challenge
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C scheme
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_integratedLine
      (oracle := prover.commit statement) (respond := respond)
      hmin conditions
  exact v1_ligero_soundness_of_eventPartition certificate
    (SchemeSelectedMCA.selectedMCAIntegratedFailureProfile n e g d
      outerBound localBound) hdensity hfalse johnson
    prover rfl (fun _ ↦ rfl)
      (Nat.sub_pos_of_lt conditions.outer.punctured.field_large)

/-- Threshold-free V1 endpoint with a singleton oracle-fixed lift list. -/
theorem v1_ligero_soundness_integrated_unique
    {outerBound : ℕ} {localBound : ℕ → ℕ}
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (prover : IPCPProver
      (ConstraintSystem F nw nq w Equations)
      (Oracle F nw nq n 1) (Challenge F nw nq 1 Equations)
      (Response F r w n 1))
    (hfalse : NoDecodedSolution C (prover.commit statement) (e + g) statement)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : IntegratedSelectedMCALineConditions C.baseCode
      (Fintype.card F) e g d outerBound localBound)
    (hunique : 2 * (e + g) < d)
    (johnson : V1JohnsonRange C threshold) :
    (SchemeVerifier.protocol C scheme).acceptanceRate prover statement ≤
      (SchemeSelectedMCA.selectedMCAIntegratedFailureProfile n e g d
        outerBound localBound).excessContribution
          (Fintype.card F - (g + 1)) n n 0 r
          (max (n - e - 1) (min n (g + (threshold - 1)))) +
      (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1) 1
        threshold).contribution (Fintype.card F) n e g r := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let respond := fun challenge ↦
    prover.respond statement (prover.commit statement) challenge
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C scheme
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_integratedLine_unique
      (oracle := prover.commit statement) (respond := respond)
      hmin conditions hunique
  exact v1_ligero_soundness_of_eventPartition certificate
    (SchemeSelectedMCA.selectedMCAIntegratedFailureProfile n e g d
      outerBound localBound) hdensity hfalse johnson
    prover rfl (fun _ ↦ rfl)
      (Nat.sub_pos_of_lt conditions.outer.punctured.field_large)

/-- Public threshold-free V1 endpoint with exact full-agreement
normalization. -/
theorem v1_ligero_soundness_optimizedIntegrated
    {outerBound : ℕ} {localBound : ℕ → ℕ}
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (prover : IPCPProver
      (ConstraintSystem F nw nq w Equations) (Oracle F nw nq n 1)
      (Challenge F nw nq 1 Equations) (Response F r w n 1))
    (hfalse : NoDecodedSolution C (prover.commit statement) (e + g) statement)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : IntegratedSelectedMCALineConditions C.baseCode
      (Fintype.card F) e g d outerBound localBound)
    (johnson : V1JohnsonRange C threshold) :
    (SchemeVerifier.protocol C scheme).acceptanceRate prover statement ≤
      (SchemeSelectedMCA.selectedMCAOptimizedIntegratedFailureProfile
        (Fintype.card F) n e g d outerBound localBound).excessContribution
          (SchemeSelectedMCA.selectedMCAOptimizedFailureDenominator
            (Fintype.card F) g) n n 0 r
          (max (n - e - 1) (min n (g + (threshold - 1)))) +
      (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1)
        (CodingTheory.InterleavedJohnson.listBound n d (e + g))
        threshold).contribution (Fintype.card F) n e g r := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let respond := fun challenge ↦
    prover.respond statement (prover.commit statement) challenge
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C scheme
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_endpointOptimizedIntegratedLine
      (oracle := prover.commit statement) (respond := respond) hmin conditions
  exact v1_ligero_soundness_of_eventPartition certificate
    (SchemeSelectedMCA.selectedMCAOptimizedIntegratedFailureProfile
      (Fintype.card F) n e g d outerBound localBound)
    hdensity hfalse johnson prover rfl (fun _ ↦ rfl)
      (Nat.mul_pos Fintype.card_pos
        (Nat.sub_pos_of_lt conditions.outer.punctured.field_large))

/-- Singleton-list form of the optimized threshold-free V1 endpoint. -/
theorem v1_ligero_soundness_optimizedIntegrated_unique
    {outerBound : ℕ} {localBound : ℕ → ℕ}
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (prover : IPCPProver
      (ConstraintSystem F nw nq w Equations) (Oracle F nw nq n 1)
      (Challenge F nw nq 1 Equations) (Response F r w n 1))
    (hfalse : NoDecodedSolution C (prover.commit statement) (e + g) statement)
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : IntegratedSelectedMCALineConditions C.baseCode
      (Fintype.card F) e g d outerBound localBound)
    (hunique : 2 * (e + g) < d)
    (johnson : V1JohnsonRange C threshold) :
    (SchemeVerifier.protocol C scheme).acceptanceRate prover statement ≤
      (SchemeSelectedMCA.selectedMCAOptimizedIntegratedFailureProfile
        (Fintype.card F) n e g d outerBound localBound).excessContribution
          (SchemeSelectedMCA.selectedMCAOptimizedFailureDenominator
            (Fintype.card F) g) n n 0 r
          (max (n - e - 1) (min n (g + (threshold - 1)))) +
      (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1) 1
        threshold).contribution (Fintype.card F) n e g r := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let respond := fun challenge ↦
    prover.respond statement (prover.commit statement) challenge
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C scheme
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_endpointOptimizedIntegratedLine_unique
      (oracle := prover.commit statement) (respond := respond)
      hmin conditions hunique
  exact v1_ligero_soundness_of_eventPartition certificate
    (SchemeSelectedMCA.selectedMCAOptimizedIntegratedFailureProfile
      (Fintype.card F) n e g d outerBound localBound)
    hdensity hfalse johnson prover rfl (fun _ ↦ rfl)
      (Nat.mul_pos Fintype.card_pos
        (Nat.sub_pos_of_lt conditions.outer.punctured.field_large))

/-- V1 in the unique-decoding lift-list regime.  Selected MCA still proves
the bad-challenge profile; `2 * (e + g) < d` sharpens only the oracle-fixed
lift list to one member. -/
theorem v1_ligero_soundness_selectedMCA_unique
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
    (conditions : LigeroFamily.SelectedMCALineConditions C.baseCode
      (Fintype.card F) e g d bound)
    (hunique : 2 * (e + g) < d)
    (johnson : V1JohnsonRange C threshold) :
    (SchemeVerifier.protocol C scheme).acceptanceRate prover statement ≤
      (SchemeSelectedMCA.selectedMCAFailureProfile n g d bound).excessContribution
          (Fintype.card F - (g + 1)) n n 0 r
          (max (n - e - 1) (min n (g + (threshold - 1)))) +
      (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1) 1
        threshold).contribution (Fintype.card F) n e g r := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let respond := fun challenge ↦
    prover.respond statement (prover.commit statement) challenge
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C scheme
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_selectedMCA_unique
      (oracle := prover.commit statement) (respond := respond)
      hmin conditions hunique
  exact v1_ligero_soundness_of_eventPartition certificate
    (SchemeSelectedMCA.selectedMCAFailureProfile n g d bound) hdensity
    hfalse johnson prover rfl (fun _ ↦ rfl)
    (Nat.sub_pos_of_lt conditions.punctured.field_large)

end Ligero.V1
