import AffineAgreement.Basic

/-!
# Basic correlated-agreement definition

Only the correlated conclusion is specific to CA. The affine-word vocabulary
used to state it lives in `AffineAgreement` and is shared with selected MCA.
-/

namespace CorrelatedAgreement

open AffineAgreement

variable {F : Type*} [Field F] [DecidableEq F]

/-- Two codewords explain the received pair outside one common set of at most
`e` coordinates. -/
def Correlated {n e : ℕ} (C : LinearCode F n)
    (u v : Word F n) : Prop :=
  ∃ a c : Word F n, a ∈ C ∧ c ∈ C ∧
    (jointSupport (u - a) (v - c)).card ≤ e

end CorrelatedAgreement
