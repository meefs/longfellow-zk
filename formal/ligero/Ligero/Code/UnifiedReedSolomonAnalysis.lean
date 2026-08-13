import Ligero.Common.Code.ReedSolomon
import Ligero.UnifiedAnalysis









namespace Ligero.Common.ReedSolomon

open CodingTheory
open Ligero.MaskV1
variable {F Equations VerifierCoins : Type*}
variable [Field F] [Fintype F] [DecidableEq F]
variable [Fintype Equations] [DecidableEq Equations]
variable {r w n nw nq e g m threshold : ℕ}



/-- Concrete Reed--Solomon V1 collected guarantee over the identical base
rows. -/
theorem v1_end_to_end_selectedMCA
    [Fintype VerifierCoins]
    (hrows : CoreRowsNonempty nw nq)
    (D : Domain F r w n) (hkpos : 1 ≤ r + w) (hk : r + w ≤ n)
    (conditions : Ligero.Common.SelectedMCAParameterConditions
      (Fintype.card F) n e g (n - (r + w) + 1) m)
    (johnson : V1JohnsonRange (multiplicativeCode D hk) threshold) :
    let C := multiplicativeCode D hk
    V1EndToEndGuarantee (F := F) (Equations := Equations)
      (VerifierCoins := VerifierCoins) (nw := nw) (nq := nq)
      C e g (n - (r + w) + 1) m threshold := by
  dsimp only
  exact v1_ligero_end_to_end_selectedMCA hrows (multiplicativeCode D hk)
    (baseCode_minimum_distance D hkpos hk) conditions johnson

end Ligero.Common.ReedSolomon
