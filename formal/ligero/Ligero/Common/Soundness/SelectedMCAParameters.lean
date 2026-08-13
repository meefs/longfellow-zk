import SelectedMCA.Parameters
import CodingTheory.ListDecoding.InterleavedJohnson

/-!
# Ligero selected-MCA parameter bundle

This protocol-facing structure deliberately bundles independent selected-MCA
extraction hypotheses with the interleaved Johnson-list denominator needed by
the final lift-list certificate.
-/

namespace Ligero.Common

/-- Combinatorial hypotheses for direct selected-MCA extraction. -/
structure DirectMCAConditions (n e g d threshold : ℕ) : Prop where
  directClique : SelectedMCA.DirectCliqueCondition n e g d threshold

/-- Hypotheses used only when punctured directional lifts are globalized. -/
structure PuncturedGlobalizationConditions (q e g d : ℕ) : Prop where
  punctured_three_radius : 3 * g < d - e
  field_large : g + 1 < q

/-- Hypothesis used only to bound the fixed interleaved lift list. -/
structure JohnsonListConditions (n e g d : ℕ) : Prop where
  list_denominator_positive :
    0 < CodingTheory.InterleavedJohnson.denominator n d (e + g)

/-- Protocol composition of the three independent numerical interfaces. -/
structure SelectedMCAParameterConditions
    (q n e g d threshold : ℕ) : Prop where
  direct : DirectMCAConditions n e g d threshold
  punctured : PuncturedGlobalizationConditions q e g d
  johnson : JohnsonListConditions n e g d

end Ligero.Common
