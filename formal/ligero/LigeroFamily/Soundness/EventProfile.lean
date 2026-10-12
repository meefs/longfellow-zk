import LigeroFamily.Soundness.AgreementProfile

/-!
# Agreement-tail excess above a shared query baseline

The ordinary profiled master bounds a selected class by its full average query
cover.  A disjoint event ledger can do better: every nonexceptional branch
already receives one common baseline, so selected-MCA failures should pay only
their agreement-dependent excess above that baseline.  This module proves the
corresponding layer-cake inequality.
-/

namespace LigeroFamily

open Finset

namespace AgreementProfile

variable {n : ℕ}

/-! ## Integer executable layer cakes

These numerators expose the integer arithmetic used by concrete optimizers.
The semantic expressions remain the rational-valued definitions below; the
equality theorems in this section are the bridge between the two.
-/

/-- Forward difference of the binomial query-cover numerator. -/
def coverIncrementNumerator (n e g queryCount agreement : ℕ) : ℕ :=
  (max (n - e - 1) (min n (g + agreement))).choose queryCount -
    if agreement = 0 then 0 else
      (max (n - e - 1) (min n (g + (agreement - 1)))).choose queryCount

theorem coverIncrement_eq_numerator_div (n e g queryCount agreement : ℕ)
    (hquery : queryCount ≤ n) :
    coverIncrement n e g queryCount agreement =
      (coverIncrementNumerator n e g queryCount agreement : ℚ) /
        n.choose queryCount := by
  have hden : ((n.choose queryCount : ℕ) : ℚ) ≠ 0 := by
    exact_mod_cast Nat.ne_of_gt (Nat.choose_pos hquery)
  by_cases hagreement : agreement = 0
  · subst agreement
    simp [coverIncrement, coverIncrementNumerator, coverRatio,
      hypergeometricRatio]
  · have hlevel : agreement - 1 ≤ agreement := Nat.sub_le agreement 1
    have hcover :
        max (n - e - 1) (min n (g + (agreement - 1))) ≤
          max (n - e - 1) (min n (g + agreement)) := by
      exact max_le_max_left _
        (min_le_min_left n (Nat.add_le_add_left hlevel g))
    have hchoose := Nat.choose_le_choose queryCount hcover
    unfold coverIncrement coverIncrementNumerator coverRatio
    simp only [hagreement, ↓reduceIte]
    unfold hypergeometricRatio
    rw [Nat.cast_sub hchoose]
    field_simp

/-- Integer numerator for the ordinary, probability-clipped profile layer
cake. -/
def contributionNumerator (profile : AgreementProfile n)
    (denominator e g queryCount : ℕ) : ℕ :=
  ∑ agreement ∈ Finset.range (n + 1),
    coverIncrementNumerator n e g queryCount agreement *
      min denominator (profile.labelsAtLeast agreement)

theorem min_one_nat_div_eq (numerator denominator : ℕ)
    (hdenominator : 0 < denominator) :
    min (1 : ℚ) ((numerator : ℚ) / denominator) =
      (min denominator numerator : ℕ) / denominator := by
  have hden : (0 : ℚ) < denominator := by exact_mod_cast hdenominator
  by_cases hnumerator : numerator ≤ denominator
  · rw [min_eq_right ((div_le_one hden).2 (by exact_mod_cast hnumerator)),
      Nat.min_eq_right hnumerator]
  · have hreverse : denominator ≤ numerator := Nat.le_of_not_ge hnumerator
    rw [min_eq_left ((one_le_div hden).2 (by exact_mod_cast hreverse)),
      Nat.min_eq_left hreverse]
    exact (div_self (ne_of_gt hden)).symm

theorem tail_eq_min_labels_div (profile : AgreementProfile n)
    (denominator agreement : ℕ) (hdenominator : 0 < denominator) :
    profile.tail denominator agreement =
      (min denominator (profile.labelsAtLeast agreement) : ℕ) / denominator := by
  unfold tail
  exact min_one_nat_div_eq _ _ hdenominator

theorem contribution_eq_numerator_div
    (profile : AgreementProfile n) (denominator e g queryCount : ℕ)
    (hdenominator : 0 < denominator) (hquery : queryCount ≤ n) :
    profile.contribution denominator n e g queryCount =
      (profile.contributionNumerator denominator e g queryCount : ℚ) /
        (n.choose queryCount * denominator) := by
  have hchoose : ((n.choose queryCount : ℕ) : ℚ) ≠ 0 := by
    exact_mod_cast Nat.ne_of_gt (Nat.choose_pos hquery)
  have hden : (denominator : ℚ) ≠ 0 := by exact_mod_cast Nat.ne_of_gt hdenominator
  unfold contribution contributionNumerator
  calc
    (∑ agreement ∈ Finset.range (n + 1),
      coverIncrement n e g queryCount agreement *
        profile.tail denominator agreement) =
        ∑ agreement ∈ Finset.range (n + 1),
          ((coverIncrementNumerator n e g queryCount agreement *
            min denominator (profile.labelsAtLeast agreement) : ℕ) : ℚ) /
              (n.choose queryCount * denominator) := by
        apply Finset.sum_congr rfl
        intro agreement _
        rw [coverIncrement_eq_numerator_div n e g queryCount agreement hquery,
          tail_eq_min_labels_div profile denominator agreement hdenominator]
        push_cast
        field_simp
    _ = ((∑ agreement ∈ Finset.range (n + 1),
          coverIncrementNumerator n e g queryCount agreement *
            min denominator (profile.labelsAtLeast agreement) : ℕ) : ℚ) /
            (n.choose queryCount * denominator) := by
        push_cast
        simp only [div_eq_mul_inv]
        rw [Finset.sum_mul]

/-- Query-cover excess above the common agreement baseline `baseline`. -/
def coverExcess (n e g queryCount baseline agreement : ℕ) : ℚ :=
  coverRatio n e g queryCount (max baseline agreement) -
    coverRatio n e g queryCount baseline

/-- Tail-integrated query-cover excess above a shared baseline. -/
def excessContribution (q n e g queryCount baseline : ℕ)
    (profile : AgreementProfile n) : ℚ :=
  ∑ a ∈ Finset.range (n + 1),
    if baseline < a then
      coverIncrement n e g queryCount a * profile.tail q a
    else 0

/-- Unclipped excess contribution for many-response incidence counts.  At
this intermediate stage several responses may lie over one challenge, so a
pointwise probability-one cap is not generally sound. -/
def rawExcessContribution (q n e g queryCount baseline : ℕ)
    (profile : AgreementProfile n) : ℚ :=
  ∑ a ∈ Finset.range (n + 1),
    if baseline < a then
      coverIncrement n e g queryCount a *
        ((profile.labelsAtLeast a : ℚ) / q)
    else 0

/-- Integer numerator of the unclipped excess layer cake. -/
def rawExcessNumerator (profile : AgreementProfile n)
    (queryCount baseline : ℕ) : ℕ :=
  ∑ agreement ∈ Finset.range (n + 1),
    if baseline < agreement then
      coverIncrementNumerator n n 0 queryCount agreement *
        profile.labelsAtLeast agreement
    else 0

theorem rawExcessContribution_eq_numerator_div
    (profile : AgreementProfile n) (denominator queryCount baseline : ℕ)
    (hdenominator : 0 < denominator) (hquery : queryCount ≤ n) :
    profile.rawExcessContribution denominator n n 0 queryCount baseline =
      (profile.rawExcessNumerator queryCount baseline : ℚ) /
        (n.choose queryCount * denominator) := by
  have hchoose : ((n.choose queryCount : ℕ) : ℚ) ≠ 0 := by
    exact_mod_cast Nat.ne_of_gt (Nat.choose_pos hquery)
  have hden : (denominator : ℚ) ≠ 0 := by exact_mod_cast Nat.ne_of_gt hdenominator
  unfold rawExcessContribution rawExcessNumerator
  calc
    (∑ agreement ∈ Finset.range (n + 1),
      if baseline < agreement then
        coverIncrement n n 0 queryCount agreement *
          ((profile.labelsAtLeast agreement : ℚ) / denominator)
      else 0) =
        ∑ agreement ∈ Finset.range (n + 1),
          (((if baseline < agreement then
              coverIncrementNumerator n n 0 queryCount agreement *
                profile.labelsAtLeast agreement
            else 0 : ℕ) : ℚ) /
              (n.choose queryCount * denominator)) := by
        apply Finset.sum_congr rfl
        intro agreement _
        by_cases hbaseline : baseline < agreement
        · simp only [hbaseline, ↓reduceIte]
          rw [coverIncrement_eq_numerator_div n n 0 queryCount agreement hquery]
          push_cast
          field_simp
        · simp [hbaseline]
    _ = ((∑ agreement ∈ Finset.range (n + 1),
          if baseline < agreement then
            coverIncrementNumerator n n 0 queryCount agreement *
              profile.labelsAtLeast agreement
          else 0 : ℕ) : ℚ) /
            (n.choose queryCount * denominator) := by
        push_cast
        simp only [div_eq_mul_inv]
        rw [Finset.sum_mul]

theorem excessContribution_nonnegative
    (q n e g queryCount baseline : ℕ) (profile : AgreementProfile n) :
    0 ≤ profile.excessContribution q n e g queryCount baseline := by
  unfold excessContribution
  apply Finset.sum_nonneg
  intro a _ha
  split
  · exact mul_nonneg (coverIncrement_nonnegative n e g queryCount a)
      (tail_nonnegative q profile a)
  · positivity

theorem rawExcessContribution_nonnegative
    (q n e g queryCount baseline : ℕ) (profile : AgreementProfile n) :
    0 ≤ profile.rawExcessContribution q n e g queryCount baseline := by
  unfold rawExcessContribution
  apply Finset.sum_nonneg
  intro a _ha
  split
  · exact mul_nonneg (coverIncrement_nonnegative n e g queryCount a)
      (div_nonneg (by positivity) (by positivity))
  · positivity

/-- Agreement profile obtained by removing the already-paid baseline range. -/
def excessProfile (baseline : ℕ) (profile : AgreementProfile n) :
    AgreementProfile n where
  labelsAtLeast agreement :=
    if baseline < agreement then profile.labelsAtLeast agreement else 0

theorem excessContribution_eq_contribution
    (q n e g queryCount baseline : ℕ) (profile : AgreementProfile n) :
    profile.excessContribution q n e g queryCount baseline =
      (profile.excessProfile baseline).contribution q n e g queryCount := by
  unfold excessContribution contribution
  apply Finset.sum_congr rfl
  intro agreement _hagreement
  by_cases hbaseline : baseline < agreement
  · simp [excessProfile, tail, hbaseline]
  · simp [excessProfile, tail, hbaseline]

/-- Integer numerator for the clipped excess after removing a shared
baseline. -/
def excessContributionNumerator (profile : AgreementProfile n)
    (denominator queryCount baseline : ℕ) : ℕ :=
  ∑ agreement ∈ Finset.range (n + 1),
    if baseline < agreement then
      coverIncrementNumerator n n 0 queryCount agreement *
        min denominator (profile.labelsAtLeast agreement)
    else 0

theorem excessContribution_eq_numerator_div
    (profile : AgreementProfile n) (denominator queryCount baseline : ℕ)
    (hdenominator : 0 < denominator) (hquery : queryCount ≤ n) :
    profile.excessContribution denominator n n 0 queryCount baseline =
      (profile.excessContributionNumerator denominator queryCount baseline : ℚ) /
        (n.choose queryCount * denominator) := by
  rw [excessContribution_eq_contribution,
    contribution_eq_numerator_div _ _ _ _ _ hdenominator hquery]
  congr 1
  norm_cast
  unfold contributionNumerator excessContributionNumerator excessProfile
  apply Finset.sum_congr rfl
  intro agreement _
  by_cases hbaseline : baseline < agreement <;> simp [hbaseline]

/-- Sparse executable form of `excessContribution`. -/
def compressedExcessContribution (q n e g queryCount baseline : ℕ)
    (profile : AgreementProfile n) : ℚ :=
  (profile.excessProfile baseline).compressedContribution q n e g queryCount

theorem compressedExcessContribution_eq
    (q n e g queryCount baseline : ℕ) (profile : AgreementProfile n) :
    profile.compressedExcessContribution q n e g queryCount baseline =
      profile.excessContribution q n e g queryCount baseline := by
  rw [compressedExcessContribution, ← contribution_eq_compressedContribution,
    ← excessContribution_eq_contribution]

/-- Subtracting the common query baseline can only improve the old full
agreement-profile charge. -/
theorem excessContribution_le_contribution
    (q n e g queryCount baseline : ℕ) (profile : AgreementProfile n) :
    profile.excessContribution q n e g queryCount baseline ≤
      profile.contribution q n e g queryCount := by
  unfold excessContribution contribution
  apply Finset.sum_le_sum
  intro a _ha
  by_cases hba : baseline < a
  · simp [hba]
  · simp only [hba, ↓reduceIte]
    exact mul_nonneg (coverIncrement_nonnegative n e g queryCount a) (by
      unfold tail
      positivity)

theorem coverExcess_nonnegative (n e g queryCount baseline agreement : ℕ) :
    0 ≤ coverExcess n e g queryCount baseline agreement := by
  unfold coverExcess
  exact sub_nonneg.mpr
    (coverRatio_mono n e g queryCount (le_max_left _ _))

private theorem coverExcess_eq_increment_sum
    (n e g queryCount baseline agreement : ℕ)
    (hbaseline : baseline ≤ n) (hagreement : agreement ≤ n) :
    coverExcess n e g queryCount baseline agreement =
      ∑ a ∈ Finset.range (n + 1),
        if baseline < a ∧ a ≤ agreement then
          coverIncrement n e g queryCount a else 0 := by
  by_cases hle : agreement ≤ baseline
  · have hmax : max baseline agreement = baseline := max_eq_left hle
    have hempty : ∀ a, ¬(baseline < a ∧ a ≤ agreement) := by
      intro a ha
      omega
    simp [coverExcess, hmax, hempty]
  · have hlt : baseline < agreement := Nat.lt_of_not_ge hle
    have hmax : max baseline agreement = agreement := max_eq_right hlt.le
    have hagreementSum := coverRatio_eq_increment_sum n e g queryCount
      (fun _ : Unit => agreement) () hagreement
    have hbaselineSum := coverRatio_eq_increment_sum n e g queryCount
      (fun _ : Unit => baseline) () hbaseline
    have hdecomp :
        (∑ a ∈ Finset.range (n + 1),
          if a ≤ agreement then coverIncrement n e g queryCount a else 0) =
        (∑ a ∈ Finset.range (n + 1),
          if a ≤ baseline then coverIncrement n e g queryCount a else 0) +
        ∑ a ∈ Finset.range (n + 1),
          if baseline < a ∧ a ≤ agreement then
            coverIncrement n e g queryCount a else 0 := by
      rw [← Finset.sum_add_distrib]
      apply Finset.sum_congr rfl
      intro a _ha
      by_cases hab : a ≤ baseline
      · have haa : a ≤ agreement := hab.trans hlt.le
        simp [hab, haa]
      · have hba : baseline < a := Nat.lt_of_not_ge hab
        by_cases haa : a ≤ agreement
        · simp [hab, hba, haa]
        · simp [hab, hba, haa]
    rw [coverExcess, hmax, hagreementSum, hbaselineSum, hdecomp]
    ring

section TailCounting

variable {X : Type*} [Fintype X]

/-- Restricted layer-cake theorem after subtracting a shared query baseline.

Only selected labels whose agreement rises above `baseline` contribute.  This
is the formal form of the nonoverlapping flat ledger's `Psi_F` term.
-/
theorem restricted_average_coverExcess_le_excessContribution
    (q n e g queryCount baseline : ℕ) (profile : AgreementProfile n)
    (selected : Finset X) (agreement : X → ℕ) (hq : 0 < q) [Nonempty X]
    (hbaseline : baseline ≤ n)
    (hagreement : ∀ x ∈ selected, agreement x ≤ n)
    (hdensity : ∀ a ≤ n,
      q * (restrictedTailSet selected agreement a).card ≤
        profile.labelsAtLeast a * Fintype.card X) :
    (∑ x ∈ selected,
        coverExcess n e g queryCount baseline (agreement x)) /
          Fintype.card X ≤
      profile.excessContribution q n e g queryCount baseline := by
  classical
  have htotal : 0 < Fintype.card X := Fintype.card_pos
  have htail (a : ℕ) (ha : a ≤ n) :
      ((restrictedTailSet selected agreement a).card : ℚ) /
          Fintype.card X ≤ profile.tail q a := by
    apply le_min
    · apply (div_le_one (by exact_mod_cast htotal)).mpr
      exact_mod_cast Finset.card_le_card
        ((Finset.filter_subset _ _).trans (Finset.subset_univ selected))
    · rw [div_le_div_iff₀ (by exact_mod_cast htotal) (by exact_mod_cast hq)]
      exact_mod_cast (by simpa [Nat.mul_comm] using hdensity a ha)
  have hsum :
      (∑ x ∈ selected,
          coverExcess n e g queryCount baseline (agreement x)) =
        ∑ a ∈ Finset.range (n + 1),
          if baseline < a then
            coverIncrement n e g queryCount a *
              (restrictedTailSet selected agreement a).card
          else 0 := by
    calc
      (∑ x ∈ selected,
          coverExcess n e g queryCount baseline (agreement x)) =
          ∑ x ∈ selected, ∑ a ∈ Finset.range (n + 1),
            if baseline < a ∧ a ≤ agreement x then
              coverIncrement n e g queryCount a else 0 := by
        apply Finset.sum_congr rfl
        intro x hx
        exact coverExcess_eq_increment_sum n e g queryCount baseline
          (agreement x) hbaseline (hagreement x hx)
      _ = ∑ a ∈ Finset.range (n + 1), ∑ x ∈ selected,
            if baseline < a ∧ a ≤ agreement x then
              coverIncrement n e g queryCount a else 0 := by
        rw [Finset.sum_comm]
      _ = _ := by
        apply Finset.sum_congr rfl
        intro a _ha
        by_cases hba : baseline < a
        · simp only [hba, true_and, ↓reduceIte]
          rw [← Finset.sum_filter]
          simp [restrictedTailSet, mul_comm]
        · simp [hba]
  rw [hsum, div_eq_mul_inv, Finset.sum_mul]
  unfold excessContribution
  apply Finset.sum_le_sum
  intro a ha
  have han : a ≤ n := by
    have := Finset.mem_range.mp ha
    omega
  by_cases hba : baseline < a
  · simp only [hba, ↓reduceIte]
    calc
      (coverIncrement n e g queryCount a *
          (restrictedTailSet selected agreement a).card) *
            (Fintype.card X : ℚ)⁻¹ =
        coverIncrement n e g queryCount a *
          ((restrictedTailSet selected agreement a).card /
            Fintype.card X) := by
          rw [div_eq_mul_inv]
          ring
      _ ≤ coverIncrement n e g queryCount a * profile.tail q a :=
        mul_le_mul_of_nonneg_left (htail a han)
          (coverIncrement_nonnegative n e g queryCount a)
  · simp [hba]

omit [Fintype X] in
/-- Restricted layer cake with an explicit normalizing population.  This is
the form needed for response incidence: `X` is the response/challenge pair
space, while probabilities are normalized only by the challenge population.
The density premise correspondingly uses that same `population`. -/
theorem restricted_sum_coverExcess_div_le_excessContribution
    (q population n e g queryCount baseline : ℕ)
    (profile : AgreementProfile n)
    (selected : Finset X) (agreement : X → ℕ)
    (hq : 0 < q) (hpopulation : 0 < population)
    (hselected : selected.card ≤ population)
    (hbaseline : baseline ≤ n)
    (hagreement : ∀ x ∈ selected, agreement x ≤ n)
    (hdensity : ∀ a, baseline < a → a ≤ n →
      q * (restrictedTailSet selected agreement a).card ≤
        profile.labelsAtLeast a * population) :
    (∑ x ∈ selected,
        coverExcess n e g queryCount baseline (agreement x)) /
          population ≤
      profile.excessContribution q n e g queryCount baseline := by
  classical
  have htail (a : ℕ) (hba : baseline < a) (ha : a ≤ n) :
      ((restrictedTailSet selected agreement a).card : ℚ) / population ≤
        profile.tail q a := by
    apply le_min
    · rw [div_le_one (by exact_mod_cast hpopulation)]
      exact_mod_cast (Finset.card_le_card (Finset.filter_subset _ _)).trans
        hselected
    · rw [div_le_div_iff₀ (by exact_mod_cast hpopulation)
          (by exact_mod_cast hq)]
      exact_mod_cast (by simpa [Nat.mul_comm] using hdensity a hba ha)
  have hsum :
      (∑ x ∈ selected,
          coverExcess n e g queryCount baseline (agreement x)) =
        ∑ a ∈ Finset.range (n + 1),
          if baseline < a then
            coverIncrement n e g queryCount a *
              (restrictedTailSet selected agreement a).card
          else 0 := by
    calc
      (∑ x ∈ selected,
          coverExcess n e g queryCount baseline (agreement x)) =
          ∑ x ∈ selected, ∑ a ∈ Finset.range (n + 1),
            if baseline < a ∧ a ≤ agreement x then
              coverIncrement n e g queryCount a else 0 := by
        apply Finset.sum_congr rfl
        intro x hx
        exact coverExcess_eq_increment_sum n e g queryCount baseline
          (agreement x) hbaseline (hagreement x hx)
      _ = ∑ a ∈ Finset.range (n + 1), ∑ x ∈ selected,
            if baseline < a ∧ a ≤ agreement x then
              coverIncrement n e g queryCount a else 0 := by
        rw [Finset.sum_comm]
      _ = _ := by
        apply Finset.sum_congr rfl
        intro a _ha
        by_cases hba : baseline < a
        · simp only [hba, true_and, ↓reduceIte]
          rw [← Finset.sum_filter]
          simp [restrictedTailSet, mul_comm]
        · simp [hba]
  rw [hsum, div_eq_mul_inv, Finset.sum_mul]
  unfold excessContribution
  apply Finset.sum_le_sum
  intro a ha
  have han : a ≤ n := by
    have := Finset.mem_range.mp ha
    omega
  by_cases hba : baseline < a
  · simp only [hba, ↓reduceIte]
    calc
      (coverIncrement n e g queryCount a *
          (restrictedTailSet selected agreement a).card) *
            (population : ℚ)⁻¹ =
        coverIncrement n e g queryCount a *
          ((restrictedTailSet selected agreement a).card / population) := by
          rw [div_eq_mul_inv]
          ring
      _ ≤ coverIncrement n e g queryCount a * profile.tail q a :=
        mul_le_mul_of_nonneg_left (htail a hba han)
          (coverIncrement_nonnegative n e g queryCount a)
  · simp [hba]

omit [Fintype X] in
/-- Raw incidence layer cake.  It uses the structural density directly and
therefore does not require the selected response/challenge pairs to fit inside
the challenge population. -/
theorem restricted_sum_coverExcess_div_le_rawExcessContribution
    (q population n e g queryCount baseline : ℕ)
    (profile : AgreementProfile n)
    (selected : Finset X) (agreement : X → ℕ)
    (hq : 0 < q) (hpopulation : 0 < population)
    (hbaseline : baseline ≤ n)
    (hagreement : ∀ x ∈ selected, agreement x ≤ n)
    (hdensity : ∀ a, baseline < a → a ≤ n →
      q * (restrictedTailSet selected agreement a).card ≤
        profile.labelsAtLeast a * population) :
    (∑ x ∈ selected,
        coverExcess n e g queryCount baseline (agreement x)) /
          population ≤
      profile.rawExcessContribution q n e g queryCount baseline := by
  classical
  have htail (a : ℕ) (hba : baseline < a) (ha : a ≤ n) :
      ((restrictedTailSet selected agreement a).card : ℚ) / population ≤
        (profile.labelsAtLeast a : ℚ) / q := by
    rw [div_le_div_iff₀ (by exact_mod_cast hpopulation)
      (by exact_mod_cast hq)]
    exact_mod_cast (by simpa [Nat.mul_comm] using hdensity a hba ha)
  have hsum :
      (∑ x ∈ selected,
          coverExcess n e g queryCount baseline (agreement x)) =
        ∑ a ∈ Finset.range (n + 1),
          if baseline < a then
            coverIncrement n e g queryCount a *
              (restrictedTailSet selected agreement a).card
          else 0 := by
    calc
      (∑ x ∈ selected,
          coverExcess n e g queryCount baseline (agreement x)) =
          ∑ x ∈ selected, ∑ a ∈ Finset.range (n + 1),
            if baseline < a ∧ a ≤ agreement x then
              coverIncrement n e g queryCount a else 0 := by
        apply Finset.sum_congr rfl
        intro x hx
        exact coverExcess_eq_increment_sum n e g queryCount baseline
          (agreement x) hbaseline (hagreement x hx)
      _ = ∑ a ∈ Finset.range (n + 1), ∑ x ∈ selected,
            if baseline < a ∧ a ≤ agreement x then
              coverIncrement n e g queryCount a else 0 := by
        rw [Finset.sum_comm]
      _ = _ := by
        apply Finset.sum_congr rfl
        intro a _ha
        by_cases hba : baseline < a
        · simp only [hba, true_and, ↓reduceIte]
          rw [← Finset.sum_filter]
          simp [restrictedTailSet, mul_comm]
        · simp [hba]
  rw [hsum, div_eq_mul_inv, Finset.sum_mul]
  unfold rawExcessContribution
  apply Finset.sum_le_sum
  intro a ha
  have han : a ≤ n := by
    have := Finset.mem_range.mp ha
    omega
  by_cases hba : baseline < a
  · simp only [hba, ↓reduceIte]
    calc
      (coverIncrement n e g queryCount a *
          (restrictedTailSet selected agreement a).card) *
            (population : ℚ)⁻¹ =
        coverIncrement n e g queryCount a *
          ((restrictedTailSet selected agreement a).card / population) := by
          rw [div_eq_mul_inv]
          ring
      _ ≤ coverIncrement n e g queryCount a *
          ((profile.labelsAtLeast a : ℚ) / q) :=
        mul_le_mul_of_nonneg_left (htail a hba han)
          (coverIncrement_nonnegative n e g queryCount a)
  · simp [hba]

end TailCounting

end AgreementProfile

end LigeroFamily
