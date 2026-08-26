import AffineAgreement.Moments

/-!
# Audited parameters for general selected agreement

This module records the exact numerical quantities from the paper-level
selected-response argument.  It deliberately contains only arithmetic:
semantic theorems must not infer selected MCA merely from these definitions.
-/

namespace SelectedMCA

open AffineAgreement

/-- Exact lower bound `Xi` for the mean intersection of three `s`-subsets of
an `N`-element universe. -/
abbrev cliqueIntersectionMean (N s m : ℕ) : ℚ :=
  AffineAgreement.tripleIntersectionMean N s m

/-- Pair-budget upper bound for triples covered by pairwise blocks of
occupancy at most `R`.  The factor `(R - 2) / 3` is exact on an `R`-block:
`3 * choose(R, 3) = (R - 2) * choose(R, 2)`. -/
def simpleCliqueUpperNat (m R : ℕ) : ℕ :=
  (R - 2) * m.choose 2 / 3

/-- Rational view of `simpleCliqueUpperNat`. -/
def simpleCliqueUpper (m R : ℕ) : ℚ := simpleCliqueUpperNat m R

/-- Triple-count lower bound on the number of affine triples.  `a₀` and
`a₁` are respectively the nonaffine and affine intersection caps. -/
def affineCliqueLower (N s m a₀ a₁ : ℕ) : ℚ :=
  (m.choose 3 : ℚ) *
    (cliqueIntersectionMean N s m - a₀) / ((a₁ - a₀ : ℕ) : ℚ)

/-- Number of parameters on a support of size `h` at which more than `g`
active coordinates can cancel. -/
def cancellationBound (h g : ℕ) : ℕ := h / (g + 1)

/-- Every directionally nonliftable point following one affine codeword line
uses at least `g+1` disjoint active coordinates.  This is therefore a uniform
occupancy bound for a line, without choosing an intermediate support radius. -/
def directLineOccupancyBound (n g : ℕ) : ℕ :=
  n / (g + 1)

theorem directLineOccupancyBound_antitone {n g g' : ℕ} (hgg' : g ≤ g') :
    directLineOccupancyBound n g' ≤ directLineOccupancyBound n g := by
  unfold directLineOccupancyBound
  exact Nat.div_le_div_left (Nat.add_le_add_right hgg' 1) (Nat.succ_pos g)

theorem simpleCliqueUpperNat_mono_right {m R R' : ℕ} (hRR' : R ≤ R') :
    simpleCliqueUpperNat m R ≤ simpleCliqueUpperNat m R' := by
  unfold simpleCliqueUpperNat
  exact Nat.div_le_div_right
    (Nat.mul_le_mul_right _ (Nat.sub_le_sub_right hRR' 2))

/-- Denominator-cleared single-clique selected-MCA condition.  Keeping this
predicate entirely in `ℕ` makes generated certificates fast and transparent.
The three conjuncts assert that triples exist, the two score caps separate,
and the pair budget is strictly smaller than the marked-triple excess. -/
abbrev DirectCliqueCondition (n e g d m : ℕ) : Prop :=
  3 ≤ m ∧ n - d < n - e ∧
    simpleCliqueUpperNat m (directLineOccupancyBound n g) *
        ((n - e) - (n - d)) + m.choose 3 * (n - d) <
      balanced_choose_three n (m * (n - e))

/-- Per-line failure coefficient supplied by the direct clique theorem. -/
def directLineFailureBound (m : ℕ) : ℕ := m - 1

/-- The denominator-cleared certificate explicitly records that triples
exist. -/
theorem DirectCliqueCondition.card_ge_three {n e g d m : ℕ}
    (condition : DirectCliqueCondition n e g d m) : 3 ≤ m := condition.1

/-- The denominator-cleared certificate explicitly records the cap gap. -/
theorem DirectCliqueCondition.cap_lt {n e g d m : ℕ}
    (condition : DirectCliqueCondition n e g d m) : n - d < n - e :=
  condition.2.1

/-- The natural certificate implies the paper's rational clique inequality. -/
theorem DirectCliqueCondition.clique_lt {n e g d m : ℕ}
    (condition : DirectCliqueCondition n e g d m) :
    simpleCliqueUpper m (directLineOccupancyBound n g) <
      affineCliqueLower n (n - e) m (n - d) (n - e) := by
  let upper := simpleCliqueUpperNat m (directLineOccupancyBound n g)
  let gap := (n - e) - (n - d)
  let base := m.choose 3 * (n - d)
  let total := balanced_choose_three n (m * (n - e))
  have hgap : 0 < gap := Nat.sub_pos_of_lt condition.cap_lt
  have hchoose : 0 < m.choose 3 := Nat.choose_pos condition.card_ge_three
  have hstrict : upper * gap + base < total := condition.2.2
  have hstrictQ : (upper : ℚ) * gap + base < total := by
    exact_mod_cast hstrict
  have hgapQ : (0 : ℚ) < gap := by exact_mod_cast hgap
  have hchooseQ : (m.choose 3 : ℚ) ≠ 0 := by exact_mod_cast hchoose.ne'
  unfold simpleCliqueUpper affineCliqueLower cliqueIntersectionMean
    AffineAgreement.tripleIntersectionMean
  change (upper : ℚ) <
    (m.choose 3 : ℚ) *
      ((total : ℚ) / m.choose 3 - ((n - d : ℕ) : ℚ)) / (gap : ℕ)
  rw [lt_div_iff₀ hgapQ]
  calc
    (upper : ℚ) * gap < (total : ℚ) - base :=
      (lt_sub_iff_add_lt).2 hstrictQ
    _ = (m.choose 3 : ℚ) *
        ((total : ℚ) / m.choose 3 - ((n - d : ℕ) : ℚ)) := by
      rw [mul_sub, mul_div_cancel₀ _ hchooseQ]
      simp [base]

/-- The cap gap implies the usual radius ordering. -/
theorem DirectCliqueCondition.radius_lt_distance {n e g d m : ℕ}
    (condition : DirectCliqueCondition n e g d m) : e < d := by
  have := condition.cap_lt
  omega

/-- Increasing the residual budget can only decrease the line-occupancy
upper bound.  This is the monotonicity used by the exact grid generator: after
finding the first valid threshold at a larger `g`, every smaller threshold is
known invalid at a smaller `g`, without assuming that the rounded predicate is
monotone in `m`. -/
theorem DirectCliqueCondition.mono_g {n e g g' d m : ℕ}
    (condition : DirectCliqueCondition n e g d m) (hgg' : g ≤ g') :
    DirectCliqueCondition n e g' d m := by
  refine ⟨condition.1, condition.2.1, ?_⟩
  apply lt_of_le_of_lt _ condition.2.2
  gcongr
  exact simpleCliqueUpperNat_mono_right
    (directLineOccupancyBound_antitone hgg')

end SelectedMCA
