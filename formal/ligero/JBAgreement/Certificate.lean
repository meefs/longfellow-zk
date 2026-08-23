import JBAgreement.SelectedLine

/-!
# Decidable certificates for the Johnson-regime line bound

`JBAgreement.lineFailureBound_of_johnson` asks for real-valued hypotheses about
`η`.  A grid certificate has to *check* them, which means arithmetic a kernel can
evaluate.  Fixing `η = 1 / 2 ^ etaBits` makes every hypothesis rational, and
clearing denominators makes each one a statement about naturals.

`JohnsonConditions` is that cleared form: a decidable `Prop` about
`(n, k, e, etaBits, bound, fieldSize)`, and `lineFailureBound_of_johnsonConditions`
turns it into the per-line interface Ligero's density argument consumes.
`johnsonThresholdQ` is the rational value of `johnsonThreshold` at such an `η`,
equal to it on the nose rather than bounding it.
-/

namespace JBAgreement

open Polynomial

/-- `johnsonThreshold` at `η = 1 / 2 ^ etaBits`, over `ℚ`.  The shape is copied
from `johnsonThreshold` term by term so the cast lemma below is a `ring`
identity. -/
def johnsonThresholdQ (k n e etaBits : ℕ) : ℚ :=
  let η : ℚ := (2 ^ etaBits)⁻¹
  3 * n / (4 * k * η) * ((e : ℚ) + 2) +
    ((n - k : ℕ) : ℚ) * (4 * k * (3 * n / (4 * k * η) * (n / (k * η ^ 2)))
      + 3 * n / (4 * k * η)) / ((n - e - k : ℕ) : ℚ)
    + n / (k * η ^ 2) + 3 * (3 * n / (4 * k * η) * (n / (k * η ^ 2))) + 1

/-- The rational mirror is exact: no slack is introduced by leaving `ℝ`. -/
theorem johnsonThresholdQ_cast (k n e etaBits : ℕ) :
    ((johnsonThresholdQ k n e etaBits : ℚ) : ℝ)
      = johnsonThreshold k n e ((2 ^ etaBits : ℝ)⁻¹) := by
  unfold johnsonThresholdQ johnsonThreshold
  push_cast
  ring

/-- **The cleared numeric hypotheses of the Johnson route.**  Each conjunct is
one hypothesis of `lineFailureBound_of_johnson` with `η = 1 / 2 ^ etaBits` and
denominators cleared:

* `hk` — `1 ≤ k`;
* `hquarter` — `η ≤ 1/4`;
* `hlength` — `1 ≤ η · n`;
* `hslack` — `4 · η · n ≤ n - e`, and `k` still fits below the radius;
* `hjohnson` — the Johnson condition `k · n ≤ (n - e - 4 η n)²`;
* `hfield` — `9 n² / (8 k η²) < |F|`;
* `hthreshold` — the certificate's `bound` dominates the threshold. -/
structure JohnsonConditions (n k e etaBits bound fieldSize : ℕ) : Prop where
  hk : 1 ≤ k
  hquarter : 4 ≤ 2 ^ etaBits
  hlength : 2 ^ etaBits ≤ n
  hslack : 4 * n ≤ (n - e) * 2 ^ etaBits
  hroom : k + 1 ≤ n - e
  hjohnson : k * n * (2 ^ etaBits) ^ 2 ≤ ((n - e) * 2 ^ etaBits - 4 * n) ^ 2
  hfield : 9 * n ^ 2 * (2 ^ etaBits) ^ 2 < 8 * k * fieldSize
  hthreshold : johnsonThresholdQ k n e etaBits ≤ (bound : ℚ) + 1

/-- Decidable mirror of `JohnsonConditions`, for certificates the kernel checks.
Every conjunct is a `Nat` or `Rat` comparison, so `decide` evaluates it. -/
def johnsonConditionsBool (n k e etaBits bound fieldSize : ℕ) : Bool :=
  (1 ≤ k) && (4 ≤ 2 ^ etaBits) && (2 ^ etaBits ≤ n) &&
    (4 * n ≤ (n - e) * 2 ^ etaBits) && (k + 1 ≤ n - e) &&
    (k * n * (2 ^ etaBits) ^ 2 ≤ ((n - e) * 2 ^ etaBits - 4 * n) ^ 2) &&
    (9 * n ^ 2 * (2 ^ etaBits) ^ 2 < 8 * k * fieldSize) &&
    decide (johnsonThresholdQ k n e etaBits ≤ (bound : ℚ) + 1)

theorem johnsonConditions_of_bool {n k e etaBits bound fieldSize : ℕ}
    (h : johnsonConditionsBool n k e etaBits bound fieldSize = true) :
    JohnsonConditions n k e etaBits bound fieldSize := by
  simp only [johnsonConditionsBool, Bool.and_eq_true, decide_eq_true_eq] at h
  exact ⟨h.1.1.1.1.1.1.1, h.1.1.1.1.1.1.2, h.1.1.1.1.1.2, h.1.1.1.1.2,
    h.1.1.1.2, h.1.1.2, h.1.2, h.2⟩

namespace JohnsonConditions

variable {n k e etaBits bound fieldSize : ℕ}

theorem eta_pos (etaBits : ℕ) : (0 : ℝ) < (2 ^ etaBits : ℝ)⁻¹ := by positivity

theorem eta_le_quarter (h : JohnsonConditions n k e etaBits bound fieldSize) :
    ((2 ^ etaBits : ℝ))⁻¹ ≤ 1 / 4 := by
  have h4 : (4 : ℝ) ≤ (2 ^ etaBits : ℝ) := by exact_mod_cast h.hquarter
  rw [inv_le_comm₀ (by positivity) (by norm_num)]
  linarith

theorem one_le_eta_mul (h : JohnsonConditions n k e etaBits bound fieldSize) :
    (1 : ℝ) ≤ (2 ^ etaBits : ℝ)⁻¹ * n := by
  have hn : ((2 : ℝ) ^ etaBits) ≤ (n : ℝ) := by exact_mod_cast h.hlength
  rw [inv_mul_eq_div, le_div_iff₀ (by positivity)]
  linarith

theorem four_mul_le_sub (h : JohnsonConditions n k e etaBits bound fieldSize) :
    4 * ((2 ^ etaBits : ℝ))⁻¹ * n ≤ ((n - e : ℕ) : ℝ) := by
  have hslack : (4 * n : ℝ) ≤ ((n - e : ℕ) : ℝ) * (2 ^ etaBits : ℝ) := by
    exact_mod_cast h.hslack
  rw [mul_comm 4 ((2 ^ etaBits : ℝ))⁻¹, ← div_eq_inv_mul, div_mul_eq_mul_div,
    div_le_iff₀ (by positivity)]
  linarith

theorem johnson_real (h : JohnsonConditions n k e etaBits bound fieldSize) :
    (k : ℝ) * n ≤ (((n - e : ℕ) : ℝ) - 4 * ((2 ^ etaBits : ℝ))⁻¹ * n) ^ 2 := by
  have hpow : (0 : ℝ) < (2 ^ etaBits : ℝ) := by positivity
  have hslack : (4 * n : ℕ) ≤ (n - e) * 2 ^ etaBits := h.hslack
  have hcast : (((n - e) * 2 ^ etaBits - 4 * n : ℕ) : ℝ)
      = ((n - e : ℕ) : ℝ) * (2 ^ etaBits : ℝ) - 4 * (n : ℝ) := by
    push_cast [Nat.cast_sub hslack]
    ring
  have hJ : ((k * n * (2 ^ etaBits) ^ 2 : ℕ) : ℝ)
      ≤ ((((n - e) * 2 ^ etaBits - 4 * n) ^ 2 : ℕ) : ℝ) := by
    exact_mod_cast h.hjohnson
  rw [Nat.cast_pow, hcast] at hJ
  have hscaled : (k : ℝ) * n * (2 ^ etaBits : ℝ) ^ 2
      ≤ (((n - e : ℕ) : ℝ) * (2 ^ etaBits : ℝ) - 4 * (n : ℝ)) ^ 2 := by
    push_cast at hJ
    linarith
  have hexpand : (((n - e : ℕ) : ℝ) - 4 * ((2 ^ etaBits : ℝ))⁻¹ * n) ^ 2
      * (2 ^ etaBits : ℝ) ^ 2
      = (((n - e : ℕ) : ℝ) * (2 ^ etaBits : ℝ) - 4 * (n : ℝ)) ^ 2 := by
    field_simp
  have hsq : (0 : ℝ) < (2 ^ etaBits : ℝ) ^ 2 := by positivity
  rw [← hexpand] at hscaled
  exact le_of_mul_le_mul_right (by linarith) hsq

theorem field_real (h : JohnsonConditions n k e etaBits bound fieldSize) :
    9 * ((n : ℝ)) ^ 2 / (8 * k * ((2 ^ etaBits : ℝ))⁻¹ ^ 2) < (fieldSize : ℝ) := by
  have hk : (1 : ℝ) ≤ (k : ℝ) := by exact_mod_cast h.hk
  have hfield : (9 * n ^ 2 * (2 ^ etaBits) ^ 2 : ℕ) < 8 * k * fieldSize := h.hfield
  have hcast : (9 : ℝ) * (n : ℝ) ^ 2 * (2 ^ etaBits : ℝ) ^ 2
      < 8 * (k : ℝ) * (fieldSize : ℝ) := by
    have := (Nat.cast_lt (α := ℝ)).mpr hfield
    push_cast at this
    linarith
  rw [div_lt_iff₀ (by positivity)]
  have hrewrite : 8 * (k : ℝ) * ((2 ^ etaBits : ℝ))⁻¹ ^ 2
      * (2 ^ etaBits : ℝ) ^ 2 = 8 * (k : ℝ) := by
    field_simp
  nlinarith [hcast, hrewrite, sq_nonneg ((2 ^ etaBits : ℝ))⁻¹]

end JohnsonConditions

variable {F : Type*} [Field F] [Fintype F] [DecidableEq F]

/-- **A checked Johnson certificate supplies the per-line interface.**  Every
hypothesis of `lineFailureBound_of_johnson` is discharged from the decidable
`JohnsonConditions`, so a grid row can carry its Johnson witness and have the
kernel check it. -/
theorem lineFailureBound_of_johnsonConditions
    {n k e g bound fieldSize etaBits : ℕ} {C : CodingTheory.LinearCode F n}
    (P : RSPresentation n k C)
    (hcard : Fintype.card F = fieldSize)
    (h : JohnsonConditions n k e etaBits bound fieldSize) :
    SelectedMCA.LineFailureBound C e g bound := by
  refine lineFailureBound_of_johnson P ((2 ^ etaBits : ℝ))⁻¹ h.hk
    (JohnsonConditions.eta_pos etaBits) h.eta_le_quarter h.one_le_eta_mul
    h.four_mul_le_sub h.johnson_real ?_ ?_
  · rw [hcard]
    exact h.field_real
  · rw [← johnsonThresholdQ_cast]
    have := h.hthreshold
    exact_mod_cast this

end JBAgreement
