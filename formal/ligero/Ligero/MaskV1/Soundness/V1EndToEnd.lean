import Ligero.Common.Soundness.SchemePolicyExtractor
import Ligero.MaskV1.Soundness.V1Profile

/-!
# End-to-end V1 soundness from selected MCA

This is the non-semantic public entry point: arbitrary-code extraction
supplies punctured selected-MCA witnesses, the common architecture
builds the fixed Johnson list, and the V1 mask profile completes the proof.
-/

namespace Ligero.MaskV1

open Ligero.Common

open CodingTheory

variable {F Equations : Type*} [Field F] [Fintype F] [DecidableEq F]
variable [Fintype Equations] [DecidableEq Equations]
variable {r w n nw nq e g d m threshold : ℕ}





theorem v1_ligero_soundness_selectedMCA
    (hrows : CoreRowsNonempty nw nq)
    (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (hfalse : ¬statement.Language)
    (prover : IPCPProver
      (ConstraintSystem F nw nq w Equations)
      (V1Oracle F nw nq n 1)
      (V1Challenge F nw nq 1 Equations)
      (Response F r w n 1))
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (conditions : Ligero.Common.SelectedMCAParameterConditions
      (Fintype.card F) n e g d m)
    (johnson : V1JohnsonRange C threshold) :
    (SchemeVerifier.protocol C MaskScheme.v1).acceptanceRate prover statement ≤
      (SchemeSelectedMCA.selectedMCAFailureProfile n g d
        (SelectedMCA.directLineFailureBound m)).contribution
          (Fintype.card F - (g + 1)) n n 0 r +
      (uncheckedAgreementProfile (Fintype.card F) n (2 * C.k - 1)
        (CodingTheory.InterleavedJohnson.listBound n d (e + g))
        threshold).contribution (Fintype.card F) n e g r := by
  letI : Nonempty (SchemeTestedRow NoMask nw nq 1) :=
    schemeTestedRowNonemptyOfCoreRows hrows
  let respond := fun challenge ↦
    prover.respond statement (prover.commit statement) challenge
  let extractor := schemeExtractorPolicy (Equations := Equations)
    (nw := nw) (nq := nq) C MaskScheme.v1
  obtain ⟨certificate, hdensity⟩ :=
    extractor.exists_profiledPolicyLiftList_of_selectedMCA
      (oracle := prover.commit statement) (respond := respond)
      hmin conditions
  exact v1_ligero_soundness_of_profiledFailure certificate
    (SchemeSelectedMCA.selectedMCAFailureProfile n g d
      (SelectedMCA.directLineFailureBound m)) hdensity hfalse johnson
    prover rfl (fun _ ↦ rfl)
      (Nat.sub_pos_of_lt conditions.punctured.field_large)

end Ligero.MaskV1
