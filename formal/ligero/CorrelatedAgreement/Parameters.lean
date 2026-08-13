import AffineAgreement.Moments
import Mathlib.Algebra.Order.Field.Rat
import Mathlib.Tactic.Ring
import Lean.Elab.Tactic.Omega

/-!
# Correlated-agreement extraction parameters

These bounds belong to the CA extraction and consolidation pipeline. The
balanced occupancy moments they use are shared through `AffineAgreement`.
-/

namespace CorrelatedAgreement

open AffineAgreement

/-- The exact rational lower bound for the mean size of a triple agreement
intersection. -/
abbrev triple_intersection_mean (n e m : ℕ) : ℚ :=
  tripleIntersectionMean n (n - e) m

/-- The number of radius-`e` points that an affine word with support greater
than `h` can contain, without using the code distance. -/
def directLineOccupancyBound (e h : ℕ) : ℕ :=
  (h + 1) / (h + 1 - e)

/-- The least possible active support of a nontrivial affine codeword line
whose support is greater than `h`. -/
def nontrivialSupportLowerBound (e h d : ℕ) : ℕ :=
  max (h + 1) (d - e)

/-- The number of radius-`e` points that can follow a nontrivial affine
codeword line with active support greater than `h`. -/
def nontrivialLineOccupancyBound (e h d : ℕ) : ℕ :=
  let L := nontrivialSupportLowerBound e h d
  L / (L - e)

/-- Maximum number of radius-`e` points on an affine received-word line that
does not have a common radius-`h` explanation. -/
def agreementBound (e h d : ℕ) : ℕ :=
  max (directLineOccupancyBound e h) (2 * nontrivialLineOccupancyBound e h d)

/-- Number of selected decoders used to contradict `agreementBound`. -/
def selectedDecoderCount (e h d : ℕ) : ℕ :=
  agreementBound e h d + 1

/-- The zero-slack selected family is always large enough for the
field-avoidance step used by interleaved globalization. -/
theorem commonRadius_succ_lt_selectedDecoderCount (h d : ℕ) :
    h + 1 < selectedDecoderCount h h d := by
  have hdirect : h + 1 ≤ agreementBound h h d := by
    have : directLineOccupancyBound h h = h + 1 := by
      simp [directLineOccupancyBound]
    rw [← this]
    exact Nat.le_max_left _ _
  dsimp [selectedDecoderCount]
  omega

/-- At zero slack, the selected family never needs more than `2h+3`
parameters. -/
theorem selectedDecoderCount_zeroSlack_le (h d : ℕ) (hud : 2 * h < d) :
    selectedDecoderCount h h d ≤ 2 * h + 3 := by
  have hud' : 2 * h < d := hud
  let L := nontrivialSupportLowerBound h h d
  have hhL : h < L := by
    dsimp [L, nontrivialSupportLowerBound]
    omega
  have hR : nontrivialLineOccupancyBound h h d ≤ h + 1 := by
    change L / (L - h) ≤ h + 1
    apply Nat.div_le_of_le_mul
    have ht : 1 ≤ L - h := by omega
    have hmul : h ≤ h * (L - h) := by
      simpa using Nat.mul_le_mul_left h ht
    have hsplit : h + (L - h) = L := by omega
    calc
      L = h + (L - h) := hsplit.symm
      _ ≤ h * (L - h) + (L - h) :=
        Nat.add_le_add_right hmul _
      _ = (L - h) * (h + 1) := by ring
  have hdirect : directLineOccupancyBound h h ≤ h + 1 := by
    simp [directLineOccupancyBound]
  have hagreement : agreementBound h h d ≤ 2 * (h + 1) := by
    apply max_le
    · omega
    · exact Nat.mul_le_mul_left 2 hR
  dsimp [selectedDecoderCount]
  omega

/-- Closed form for the agreement threshold at the maximal unique-decoding
boundary `d = 2h+1`.  This is a specialization of `agreementBound`, not its
general value at an arbitrary distance. -/
def uniqueRadiusAgreementBound (h s : ℕ) : ℕ :=
  2 * ((h + s + 1) / (2 * s + 1))

/-- At `d = 2h+1`, the general two-radius threshold equals the specialized
unique-radius bound. -/
theorem agreementBound_eq_uniqueRadiusAgreementBound
    (h s : ℕ) (hs : s ≤ h) :
    agreementBound (h - s) h (2 * h + 1) =
      uniqueRadiusAgreementBound h s := by
  let quotient := (h + 1) / (s + 1)
  let lineOccupancy := (h + s + 1) / (2 * s + 1)
  have hlineOccupancyPos : 1 ≤ lineOccupancy := by
    apply Nat.div_pos
    · omega
    · omega
  have hquotientMul : quotient * (s + 1) ≤ h + 1 := by
    exact Nat.div_mul_le_self _ _
  have hlineOccupancyUpper :
      h + s + 1 < (2 * s + 1) * (lineOccupancy + 1) := by
    exact Nat.lt_mul_div_succ _ (by omega)
  have hquotientLine : quotient ≤ 2 * lineOccupancy := by
    apply Nat.le_of_not_lt
    intro hlt
    have hlower : (2 * lineOccupancy + 1) * (s + 1) ≤ h + 1 := by
      calc
        (2 * lineOccupancy + 1) * (s + 1) ≤ quotient * (s + 1) :=
          Nat.mul_le_mul_right _ hlt
        _ ≤ h + 1 := hquotientMul
    have hleftExpand : (2 * lineOccupancy + 1) * (s + 1) =
        2 * lineOccupancy * s + 2 * lineOccupancy + s + 1 := by ring
    have hrightExpand : (2 * s + 1) * (lineOccupancy + 1) =
        2 * lineOccupancy * s + lineOccupancy + 2 * s + 1 := by ring
    rw [hleftExpand] at hlower
    rw [hrightExpand] at hlineOccupancyUpper
    omega
  have hdirect : directLineOccupancyBound (h - s) h = quotient := by
    dsimp [directLineOccupancyBound, quotient]
    congr 1
    omega
  have hsupport : nontrivialSupportLowerBound (h - s) h (2 * h + 1) =
      h + s + 1 := by
    dsimp [nontrivialSupportLowerBound]
    omega
  have hnontrivial :
      nontrivialLineOccupancyBound (h - s) h (2 * h + 1) = lineOccupancy := by
    dsimp [nontrivialLineOccupancyBound, lineOccupancy]
    rw [hsupport]
    congr 1
    omega
  rw [agreementBound, hdirect, hnontrivial, max_eq_right hquotientLine]
  rfl

/-- Minimal numerical hypotheses for affine-codeword-line extraction and
candidate-line consolidation. Radius `e` is used by the proximity test;
`h` bounds the common support in the conclusion. -/
structure NumericalHypotheses (n e h d b : ℕ) : Prop where
  testRadius_le_commonRadius : e ≤ h
  line_card_lower : 3 ≤ b
  extraction_bound :
    ((((selectedDecoderCount e h d) - 2 : ℕ) : ℚ)) *
      (triple_intersection_mean n e (selectedDecoderCount e h d) -
        (n - d : ℕ)) >
    (b - 3 : ℕ) * (d - e : ℕ)
  consolidation_bound : 4 * d > n + 5 * e + 2 * (e / (b - 1))

end CorrelatedAgreement
