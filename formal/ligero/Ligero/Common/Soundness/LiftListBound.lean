import Ligero.Common.Soundness.Hypergeometric

/-!
# Lift-list soundness bounds

This lightweight module contains only the numerical expressions shared by
the semantic lift-list theorem and concrete parameter audits.
-/

namespace Ligero.Common

/-- The larger of the two alternative uniform query covers available on each
nonexceptional challenge. -/
def liftListQueryCoverBound (n e g k : ℕ) : ℕ :=
  max (n - e - 1) (2 * k + g - 1)

/-- The exact rational lift-list bound. The query-cover cases are
alternative, so their common worst-case contribution is their maximum. -/
def liftListSoundnessBound
    (q n e g k queryCount failureNumerator failureDenominator L : ℕ) : ℚ :=
  (failureNumerator : ℚ) / failureDenominator + (L : ℚ) / q +
    hypergeometricRatio (liftListQueryCoverBound n e g k) n queryCount

end Ligero.Common
