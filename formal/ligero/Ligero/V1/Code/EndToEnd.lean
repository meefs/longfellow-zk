import LigeroFamily.Code.ReedSolomon
import Ligero.V1.EndToEnd

/-! # Reed–Solomon instantiation of Ligero V1 -/

namespace Ligero.V1.ReedSolomon

open LigeroFamily CodingTheory

variable {F Equations VerifierCoins : Type*}
variable [Field F] [Fintype F] [DecidableEq F]
variable [Fintype Equations] [DecidableEq Equations]
variable {r w n nw nq e g m threshold : ℕ}

/-- The V1 collected guarantee for a concrete Reed–Solomon base code. -/
theorem end_to_end_selectedMCA
    [Fintype VerifierCoins]
    (hrows : CoreRowsNonempty nw nq)
    (D : LigeroFamily.ReedSolomon.Domain F r w n)
    (hkpos : 1 ≤ r + w) (hk : r + w ≤ n)
    (conditions : SelectedMCAParameterConditions
      (Fintype.card F) n e g (n - (r + w) + 1) m)
    (johnson : V1JohnsonRange
      (LigeroFamily.ReedSolomon.multiplicativeCode D hk) threshold) :
    let C := LigeroFamily.ReedSolomon.multiplicativeCode D hk
    EndToEndGuarantee (F := F) (Equations := Equations)
      (VerifierCoins := VerifierCoins) (nw := nw) (nq := nq)
      C e g (n - (r + w) + 1) m threshold := by
  dsimp only
  exact Ligero.V1.end_to_end_selectedMCA hrows
    (LigeroFamily.ReedSolomon.multiplicativeCode D hk)
    (LigeroFamily.ReedSolomon.baseCode_minimum_distance D hkpos hk)
    conditions johnson

end Ligero.V1.ReedSolomon
