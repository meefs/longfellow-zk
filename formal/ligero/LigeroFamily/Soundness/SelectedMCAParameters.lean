import SelectedMCA.LineFailure
import CodingTheory.ListDecoding.InterleavedJohnson

/-!
# Ligero selected-MCA parameter bundle

This protocol-facing structure deliberately bundles independent selected-MCA
extraction hypotheses with the interleaved Johnson-list denominator needed by
the final lift-list certificate.
-/

namespace LigeroFamily

/-- Combinatorial hypotheses for direct selected-MCA extraction. -/
structure DirectMCAConditions (n e g d threshold : ℕ) : Prop where
  directClique : SelectedMCA.DirectCliqueCondition n e g d threshold

/-- The clique bundle supplies the per-line selected-MCA interface, which is what
the density argument consumes.  A certificate using a different proximity theorem
supplies `SelectedMCA.LineFailureBound` directly instead. -/
theorem DirectMCAConditions.lineFailure {F : Type*} [Field F] [DecidableEq F]
    {n e g d threshold : ℕ} {C : CodingTheory.LinearCode F n}
    (conditions : DirectMCAConditions n e g d threshold)
    (hmin : CodingTheory.HasMinimumDistanceAtLeast C d) :
    SelectedMCA.LineFailureBound C e g
      (SelectedMCA.directLineFailureBound threshold) :=
  SelectedMCA.lineFailureBound_of_directClique hmin conditions.directClique

/-- Hypotheses used only when punctured directional lifts are globalized. -/
structure PuncturedGlobalizationConditions (q e g d : ℕ) : Prop where
  punctured_three_radius : 3 * g < d - e
  field_large : g + 1 < q

/-- Hypothesis used only to bound the fixed interleaved lift list. -/
structure JohnsonListConditions (n e g d : ℕ) : Prop where
  list_denominator_positive :
    0 < CodingTheory.InterleavedJohnson.denominator n d (e + g)

/-- **The route-agnostic composition.**  Identical to
`SelectedMCAParameterConditions` except that the clique condition is replaced by
the per-line bound it exists to provide, so a certificate can reach this bundle
through any proximity theorem.  `bound` is the line-failure count.

The masters take this; a committed clique certificate reaches it through
`SelectedMCAParameterConditions.lineConditions`, and a Johnson certificate
through `JBAgreement.lineFailureBound_of_johnsonConditions`. -/
structure SelectedMCALineConditions {F : Type*} [Field F] [DecidableEq F]
    {n : ℕ} (C : CodingTheory.LinearCode F n) (q e g d bound : ℕ) : Prop where
  line : SelectedMCA.LineFailureBound C e g bound
  punctured : PuncturedGlobalizationConditions q e g d
  johnson : JohnsonListConditions n e g d

/-- Protocol composition of the three independent numerical interfaces. -/
structure SelectedMCAParameterConditions
    (q n e g d threshold : ℕ) : Prop where
  direct : DirectMCAConditions n e g d threshold
  punctured : PuncturedGlobalizationConditions q e g d
  johnson : JohnsonListConditions n e g d

/-- The clique bundle reaches the route-agnostic bundle, so every committed
certificate keeps working unchanged. -/
theorem SelectedMCAParameterConditions.lineConditions
    {F : Type*} [Field F] [DecidableEq F] {n : ℕ}
    {C : CodingTheory.LinearCode F n} {q e g d threshold : ℕ}
    (conditions : SelectedMCAParameterConditions q n e g d threshold)
    (hmin : CodingTheory.HasMinimumDistanceAtLeast C d) :
    SelectedMCALineConditions C q e g d
      (SelectedMCA.directLineFailureBound threshold) where
  line := conditions.direct.lineFailure hmin
  punctured := conditions.punctured
  johnson := conditions.johnson

/-- Parameters for the agreement-local selected-MCA refinement.  The outer
certificate still constructs the lift list.  The local certificate is applied
only to selected responses whose actual agreement is at least `cutoff`, where
their decoding radius is at most `n - cutoff`. -/
structure RefinedSelectedMCAParameterConditions
    (q n e g d threshold cutoff localThreshold : ℕ) : Prop extends
    SelectedMCAParameterConditions q n e g d threshold where
  radius_le_cutoff : n - e ≤ cutoff
  cutoff_le_length : cutoff ≤ n
  localDirect : SelectedMCA.DirectCliqueCondition
    n (n - cutoff) g d localThreshold
  local_three_radius : 3 * g < d - (n - cutoff)

end LigeroFamily
