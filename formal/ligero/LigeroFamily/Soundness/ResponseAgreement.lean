import LigeroFamily.Soundness.EventProfile
import LigeroFamily.Soundness.PolicyProfiledMaster
import Bcs.Counting

/-!
# Threshold-free response-agreement profiles

Response-rigid Case A must not choose one response-list threshold and charge
its list size against the whole accepting-pair probability.  The correct
object is the response/query/challenge incidence tail at every response-
agreement level.  This intermediate incidence is not a probability over
challenges: several response targets may lie over one challenge, so its
profile is deliberately left unclipped.  The actual tape event is clipped
only after the lazy-target argument has returned to a genuine probability.

This file contains only the finite layer-cake part of that argument.  The
operational random-oracle theorem is responsible for proving the levelwise
density premise for the actual Case-A tapes; no probabilistic independence is
assumed here.
-/

namespace LigeroFamily

namespace ResponseAgreement

private theorem exists_indexedStrategies
    {Alpha Response : Type*} [Fintype Response] [DecidableEq Response]
    [Nonempty Response]
    (responses : Alpha → Finset Response) (listBound : ℕ)
    (hlist : ∀ alpha, (responses alpha).card ≤ listBound) :
    ∃ strategy : Fin listBound → Alpha → Response,
      ∀ alpha response, response ∈ responses alpha →
        ∃ rank, strategy rank alpha = response := by
  classical
  let fallback : Response := Classical.choice inferInstance
  let strategy : Fin listBound → Alpha → Response := fun rank alpha ↦
    if h : rank.val < (responses alpha).card then
      ((responses alpha).equivFin.symm ⟨rank.val, h⟩).1
    else fallback
  refine ⟨strategy, ?_⟩
  intro alpha response hresponse
  let small : Fin (responses alpha).card :=
    (responses alpha).equivFin ⟨response, hresponse⟩
  let rank : Fin listBound :=
    ⟨small.val, small.isLt.trans_le (hlist alpha)⟩
  refine ⟨rank, ?_⟩
  simp only [strategy, rank, small, dif_pos small.isLt]
  exact congrArg Subtype.val
    ((responses alpha).equivFin.symm_apply_apply ⟨response, hresponse⟩)

/-- Pointwise list multiplicity times a strategy-uniform challenge tail,
proved as a raw finite cardinality inequality.  The list is re-enumerated at
each level, which is what removes the endpoint loss. -/
theorem indexedLists_tail_density
    {Alpha Response : Type*} [Fintype Alpha] [DecidableEq Alpha]
    [Fintype Response] [DecidableEq Response] [Nonempty Response]
    (responses : Alpha → Finset Response) (listBound q labels : ℕ)
    (hlist : ∀ alpha, (responses alpha).card ≤ listBound)
    (hstrategy : ∀ strategy : Alpha → Response,
      q * (Finset.univ.filter fun alpha ↦
        strategy alpha ∈ responses alpha).card ≤
          labels * Fintype.card Alpha) :
    q * (Finset.univ.filter fun pair : Response × Alpha ↦
        pair.1 ∈ responses pair.2).card ≤
      listBound * labels * Fintype.card Alpha := by
  classical
  obtain ⟨strategy, hcoverStrategy⟩ :=
    exists_indexedStrategies responses listBound hlist
  let full : Finset (Response × Alpha) :=
    Finset.univ.filter fun pair ↦ pair.1 ∈ responses pair.2
  let piece (rank : Fin listBound) : Finset (Response × Alpha) :=
    Finset.univ.filter fun pair ↦
      pair.1 = strategy rank pair.2 ∧ pair.1 ∈ responses pair.2
  have hcover : full ⊆ Finset.univ.biUnion piece := by
    intro pair hpair
    have hmem := (Finset.mem_filter.mp hpair).2
    obtain ⟨rank, hrank⟩ := hcoverStrategy pair.2 pair.1 hmem
    exact Finset.mem_biUnion.mpr ⟨rank, Finset.mem_univ _,
      Finset.mem_filter.mpr ⟨Finset.mem_univ _, hrank.symm, hmem⟩⟩
  have hpiece (rank : Fin listBound) :
      (piece rank).card = (Finset.univ.filter fun alpha ↦
        strategy rank alpha ∈ responses alpha).card := by
    dsimp [piece]
    rw [Bcs.card_filter_prod_snd]
    have hrhs :
        (Finset.univ.filter fun alpha ↦
          strategy rank alpha ∈ responses alpha).card =
        ∑ alpha : Alpha,
          if strategy rank alpha ∈ responses alpha then 1 else 0 := by
      rw [← Finset.sum_filter]
      simp
    rw [hrhs]
    apply Finset.sum_congr rfl
    intro alpha _
    by_cases hmem : strategy rank alpha ∈ responses alpha
    · have heq : (Finset.univ.filter fun response : Response ↦
          response = strategy rank alpha ∧
            response ∈ responses alpha).card = 1 := by
        rw [show (Finset.univ.filter fun response : Response ↦
            response = strategy rank alpha ∧
              response ∈ responses alpha) = {strategy rank alpha} by
          ext response
          constructor
          · intro hresponse
            have := (Finset.mem_filter.mp hresponse).2.1
            simpa using this
          · intro hresponse
            have heq : response = strategy rank alpha := by simpa using hresponse
            subst response
            exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, rfl, hmem⟩]
        simp
      rw [heq, if_pos hmem]
    · have heq : (Finset.univ.filter fun response : Response ↦
          response = strategy rank alpha ∧
            response ∈ responses alpha).card = 0 := by
        rw [show (Finset.univ.filter fun response : Response ↦
            response = strategy rank alpha ∧
              response ∈ responses alpha) = ∅ by
          ext response
          constructor
          · intro hresponse
            have h := (Finset.mem_filter.mp hresponse).2
            exact (hmem (h.1 ▸ h.2)).elim
          · simp]
        simp
      rw [heq, if_neg hmem]
  have hcard : full.card ≤ ∑ rank : Fin listBound, (piece rank).card :=
    (Finset.card_le_card hcover).trans Finset.card_biUnion_le
  change q * full.card ≤ _
  calc
    q * full.card ≤ q * ∑ rank : Fin listBound, (piece rank).card :=
      Nat.mul_le_mul_left _ hcard
    _ = ∑ rank : Fin listBound, q * (piece rank).card := by
      rw [Finset.mul_sum]
    _ = ∑ rank : Fin listBound, q *
        (Finset.univ.filter fun alpha ↦
          strategy rank alpha ∈ responses alpha).card := by
      apply Finset.sum_congr rfl
      intro rank _
      rw [hpiece]
    _ ≤ ∑ _rank : Fin listBound, labels * Fintype.card Alpha :=
      Finset.sum_le_sum fun rank _ ↦ hstrategy (strategy rank)
    _ = listBound * labels * Fintype.card Alpha := by
      simp [Nat.mul_assoc]

/-- The `listBound` multiplier in `indexedLists_tail_density` is sharp under
its generic premises.  With one challenge and all `listBound` responses
available, every response strategy meets the same one-challenge density
bound, while the joint response/challenge incidence contains all
`listBound` pairs.  Thus a smaller joint-incidence theorem must use an
additional acceptance- or code-specific premise; it cannot follow from the
strategy-uniform tail and pointwise list cardinality alone. -/
theorem indexedLists_tail_density_factor_sharp
    (listBound : ℕ) :
    let responses : PUnit → Finset (Fin listBound) := fun _ ↦ Finset.univ
    (∀ alpha, (responses alpha).card = listBound) ∧
      (∀ strategy : PUnit → Fin listBound,
        (Finset.univ.filter fun alpha ↦
          strategy alpha ∈ responses alpha).card = 1) ∧
      (Finset.univ.filter fun pair : Fin listBound × PUnit ↦
        pair.1 ∈ responses pair.2).card = listBound := by
  dsimp only
  constructor
  · intro alpha
    simp
  constructor
  · intro strategy
    simp
  · simp

/-- Joint response/query/challenge incidence theorem after a single shared
query baseline has been removed.  `selected` contains the possible
response/challenge pairs.  Its level sets are bounded by `profile`, while
`success` contributes at most the hypergeometric excess of that pair's
actual response agreement. -/
theorem responseQueryChallenge_incidence_ratio_le
    {Alpha Response : Type*} [Fintype Alpha] [Nonempty Alpha]
    [Fintype Response] [DecidableEq Response]
    {n r : ℕ}
    (q floor : ℕ) (profile : AgreementProfile n)
    (selected : Finset (Response × Alpha))
    (agreement : Response × Alpha → ℕ)
    (success : (Response × Alpha) → QuerySet n r → Prop)
    [∀ pair, DecidablePred (success pair)]
    (hq : 0 < q) (hquery : r ≤ n) (hfloor : floor ≤ n)
    (hagreement : ∀ pair ∈ selected,
      floor < agreement pair ∧ agreement pair ≤ n)
    (hdensity : ∀ a, floor < a → a ≤ n →
      q * (AgreementProfile.restrictedTailSet selected agreement a).card ≤
        profile.labelsAtLeast a * Fintype.card Alpha)
    (hmember : ∀ pair query, success pair query → pair ∈ selected)
    (hqueries : ∀ pair ∈ selected,
      (Finset.univ.filter (success pair)).card ≤
        (agreement pair).choose r - floor.choose r) :
    ((Finset.univ.filter fun value : (Response × Alpha) × QuerySet n r ↦
        success value.1 value.2).card : ℚ) /
          (Fintype.card (QuerySet n r) * Fintype.card Alpha) ≤
      profile.rawExcessContribution q n n 0 r floor := by
  classical
  have hqueryCard : 0 < n.choose r := Nat.choose_pos hquery
  have hAlpha : 0 < Fintype.card Alpha := Fintype.card_pos
  have hden : (0 : ℚ) < n.choose r * Fintype.card Alpha := by
    exact_mod_cast Nat.mul_pos hqueryCard hAlpha
  have hcard :
      (Finset.univ.filter fun value : (Response × Alpha) × QuerySet n r ↦
        success value.1 value.2).card ≤
      ∑ pair ∈ selected, ((agreement pair).choose r - floor.choose r) := by
    rw [Bcs.card_filter_prod_fst]
    calc
      ∑ pair : Response × Alpha,
          (Finset.univ.filter (success pair)).card ≤
        ∑ pair : Response × Alpha,
          if pair ∈ selected then
            (agreement pair).choose r - floor.choose r else 0 := by
          apply Finset.sum_le_sum
          intro pair _
          by_cases hp : pair ∈ selected
          · simp only [hp, ↓reduceIte]
            exact hqueries pair hp
          · simp only [hp, ↓reduceIte]
            have hempty : Finset.univ.filter (success pair) = ∅ := by
              ext query
              constructor
              · intro hs
                exact (hp (hmember pair query (Finset.mem_filter.mp hs).2)).elim
              · simp
            rw [hempty]
            exact Nat.zero_le _
      _ = ∑ pair ∈ selected,
          ((agreement pair).choose r - floor.choose r) := by
        rw [← Finset.sum_filter]
        rw [show (Finset.univ.filter fun pair : Response × Alpha ↦
          pair ∈ selected) = selected by
            ext pair
            simp]
  have hratio (pair : Response × Alpha) (hpair : pair ∈ selected) :
      (((agreement pair).choose r - floor.choose r : ℕ) : ℚ) /
          n.choose r =
        AgreementProfile.coverExcess n n 0 r floor (agreement pair) := by
    have hs := (hagreement pair hpair).2
    have hfs : floor ≤ agreement pair := (hagreement pair hpair).1.le
    have hchoose : floor.choose r ≤ (agreement pair).choose r :=
      Nat.choose_le_choose r hfs
    unfold AgreementProfile.coverExcess AgreementProfile.coverRatio
      hypergeometricRatio
    simp only [Nat.sub_self, zero_tsub, zero_add,
      max_eq_right (Nat.zero_le _), max_eq_right hfs]
    rw [min_eq_right hs, min_eq_right hfloor]
    push_cast [hchoose]
    ring
  have hsumCast :
      (((∑ pair ∈ selected,
          ((agreement pair).choose r - floor.choose r)) : ℕ) : ℚ) /
            (n.choose r * Fintype.card Alpha) =
        (∑ pair ∈ selected,
          AgreementProfile.coverExcess n n 0 r floor (agreement pair)) /
            Fintype.card Alpha := by
    push_cast
    calc
      (∑ pair ∈ selected,
          (((agreement pair).choose r - floor.choose r : ℕ) : ℚ)) /
            (n.choose r * Fintype.card Alpha) =
        ((∑ pair ∈ selected,
          (((agreement pair).choose r - floor.choose r : ℕ) : ℚ)) /
            n.choose r) / Fintype.card Alpha := by ring
      _ = (∑ pair ∈ selected,
          (((agreement pair).choose r - floor.choose r : ℕ) : ℚ) /
            n.choose r) / Fintype.card Alpha := by
        simp only [div_eq_mul_inv, Finset.sum_mul]
      _ = (∑ pair ∈ selected,
          AgreementProfile.coverExcess n n 0 r floor (agreement pair)) /
            Fintype.card Alpha := by
        congr 1
        apply Finset.sum_congr rfl
        intro pair hp
        exact hratio pair hp
  rw [QuerySet.fintype_card]
  calc
    ((Finset.univ.filter fun value : (Response × Alpha) × QuerySet n r ↦
        success value.1 value.2).card : ℚ) /
          (n.choose r * Fintype.card Alpha)
      ≤ (((∑ pair ∈ selected,
          ((agreement pair).choose r - floor.choose r)) : ℕ) : ℚ) /
            (n.choose r * Fintype.card Alpha) :=
        div_le_div_of_nonneg_right (by exact_mod_cast hcard) hden.le
    _ = (∑ pair ∈ selected,
          AgreementProfile.coverExcess n n 0 r floor (agreement pair)) /
            Fintype.card Alpha := hsumCast
    _ ≤ profile.rawExcessContribution q n n 0 r floor :=
      AgreementProfile.restricted_sum_coverExcess_div_le_rawExcessContribution
        q (Fintype.card Alpha) n n 0 r floor profile selected agreement
          hq hAlpha hfloor (fun pair hp ↦ (hagreement pair hp).2)
            hdensity

noncomputable def finiteEventSet {X : Type*} [Fintype X]
    (event : X → Prop) : Finset X := by
  classical
  exact Finset.univ.filter event

/-- Reorder the semantic incidence set into the response-first product shape
used by the lazy response-target deletion theorem. -/
theorem responseFirst_ratio_le_of_pairFirst
    {Alpha Response : Type*} [Fintype Alpha] [Fintype Response]
    {n r : ℕ}
    (success : Response → QuerySet n r → Alpha → Prop)
    (epsilon : ℚ)
    (hpairFirst :
      ((finiteEventSet fun value :
          (Response × Alpha) × QuerySet n r ↦
        success value.1.1 value.2 value.1.2).card : ℚ) /
          (Fintype.card (QuerySet n r) * Fintype.card Alpha) ≤ epsilon) :
    ((finiteEventSet fun value :
        Response × (QuerySet n r × Alpha) ↦
      success value.1 value.2.1 value.2.2).card : ℚ) /
        Fintype.card (QuerySet n r × Alpha) ≤ epsilon := by
  classical
  let left := finiteEventSet fun value :
      Response × (QuerySet n r × Alpha) ↦
    success value.1 value.2.1 value.2.2
  let right := finiteEventSet fun value :
      (Response × Alpha) × QuerySet n r ↦
    success value.1.1 value.2 value.1.2
  let swap : (↑left) ≃ (↑right) := {
    toFun := fun value ↦ ⟨((value.1.1, value.1.2.2), value.1.2.1), by
      have h := (Finset.mem_filter.mp value.2).2
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, h⟩⟩
    invFun := fun value ↦ ⟨(value.1.1.1, (value.1.2, value.1.1.2)), by
      have h := (Finset.mem_filter.mp value.2).2
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, h⟩⟩
    left_inv := fun _ ↦ rfl
    right_inv := fun _ ↦ rfl }
  have hcard : left.card = right.card := by
    calc
      left.card = Fintype.card ↑left := by simp
      _ = Fintype.card ↑right := Fintype.card_congr swap
      _ = right.card := by simp
  simpa [left, right, Fintype.card_prod, Nat.cast_mul, hcard] using hpairFirst

/-- Put the failure and arithmetic agreement tails over their common product
denominator.  An accepting-coordinate level `a` requires arithmetic agreement
at least `a - g` on the nonfailure branch. -/
def combinedProfile {n : ℕ} (failureDenominator profileDenominator g : ℕ)
    (failureProfile arithmeticProfile : AgreementProfile n) :
    AgreementProfile n where
  labelsAtLeast a :=
    profileDenominator * failureProfile.labelsAtLeast a +
      failureDenominator * arithmeticProfile.labelsAtLeast (a - g)

def combinedDenominator
    (failureDenominator profileDenominator : ℕ) : ℕ :=
  failureDenominator * profileDenominator

theorem combinedDenominator_pos
    {failureDenominator profileDenominator : ℕ}
    (hfailure : 0 < failureDenominator) (hprofile : 0 < profileDenominator) :
    0 < combinedDenominator failureDenominator profileDenominator := by
  exact Nat.mul_pos hfailure hprofile

/-- Above the far-proximity floor, the doubly profiled classifier gives a
single response-agreement tail.  This theorem performs the failure/nonfailure
union and the denominator conversion exactly.

`score` may be any concrete accepting-coordinate count.  The two domination
hypotheses are the protocol bridge: failures are covered by
`failureAgreement`; nonfailures are covered either by the far-proximity floor
or by `g + agreement`. -/
theorem combined_score_density_above_floor
    {F Equations CheckedMask DirectMask Challenge Response : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Fintype CheckedMask] [DecidableEq CheckedMask]
    [Fintype Challenge]
    {r w n logicalWidth nw nq e g profileDenominator failureDenominator : ℕ}
    {C : MultiplicativeCode F r w n}
    {layout : ConstraintLayout F logicalWidth w}
    {policy : SchemeProtocolPolicy (Equations := Equations) C layout
      Challenge Response CheckedMask DirectMask nw nq 1}
    {oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1}
    {statement : ConstraintSystem F nw nq logicalWidth Equations}
    {respond : Challenge → Response}
    {failureProfile arithmeticProfile : AgreementProfile n}
    (classifier : PolicyDoublyProfiledSoundnessClassifier policy oracle statement
      respond failureProfile arithmeticProfile profileDenominator
        failureDenominator e g)
    (score : Challenge → ℕ)
    (hfailureScore : ∀ challenge, challenge ∈ classifier.failure →
      score challenge ≤ classifier.failureAgreement challenge)
    (hgoodScore : ∀ challenge, challenge ∉ classifier.failure →
      score challenge ≤
        max (n - e - 1) (min n (g + classifier.agreement challenge)))
    (floor : ℕ) (hfarFloor : n - e - 1 ≤ floor) :
    ∀ a, floor < a → a ≤ n →
      combinedDenominator failureDenominator profileDenominator *
          (AgreementProfile.tailSet score a).card ≤
        (combinedProfile failureDenominator profileDenominator g
          failureProfile arithmeticProfile).labelsAtLeast a *
            Fintype.card Challenge := by
  classical
  intro a hfloor ha
  let failureTail := AgreementProfile.restrictedTailSet classifier.failure
    classifier.failureAgreement a
  let goodChallenges := (Finset.univ : Finset Challenge) \ classifier.failure
  let arithmeticTail := AgreementProfile.restrictedTailSet goodChallenges
    classifier.agreement (a - g)
  have hsubset : AgreementProfile.tailSet score a ⊆
      failureTail ∪ arithmeticTail := by
    intro challenge hchallenge
    have hscoreHigh : a ≤ score challenge :=
      (Finset.mem_filter.mp hchallenge).2
    by_cases hfailureMem : challenge ∈ classifier.failure
    · apply Finset.mem_union_left
      exact Finset.mem_filter.mpr
        ⟨hfailureMem, hscoreHigh.trans (hfailureScore challenge hfailureMem)⟩
    · apply Finset.mem_union_right
      apply Finset.mem_filter.mpr
      refine ⟨Finset.mem_sdiff.mpr ⟨Finset.mem_univ _, hfailureMem⟩, ?_⟩
      have hcoverHigh : a ≤
          max (n - e - 1)
            (min n (g + classifier.agreement challenge)) :=
        hscoreHigh.trans (hgoodScore challenge hfailureMem)
      have hnotFar : ¬a ≤ n - e - 1 := by omega
      have harithmetic : a ≤ g + classifier.agreement challenge := by
        rw [le_max_iff] at hcoverHigh
        have : a ≤ min n (g + classifier.agreement challenge) :=
          hcoverHigh.resolve_left hnotFar
        exact this.trans (Nat.min_le_right _ _)
      omega
  have hdisjoint : Disjoint failureTail arithmeticTail := by
    rw [Finset.disjoint_left]
    intro challenge hfailureTail harithmeticTail
    have hfailureMem := (Finset.mem_filter.mp hfailureTail).1
    have hgoodMem := (Finset.mem_filter.mp harithmeticTail).1
    exact (Finset.mem_sdiff.mp hgoodMem).2 hfailureMem
  have hcard : (AgreementProfile.tailSet score a).card ≤
      failureTail.card + arithmeticTail.card := by
    rw [← Finset.card_union_of_disjoint hdisjoint]
    exact Finset.card_le_card hsubset
  have hfailureDensity := classifier.failureAgreement_density a ha
  have harithmeticDensity := classifier.agreement_density (a - g)
    (Nat.sub_le a g |>.trans ha)
  have harithmeticSubset : arithmeticTail ⊆
      AgreementProfile.tailSet classifier.agreement (a - g) := by
    intro challenge hchallenge
    exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
      (Finset.mem_filter.mp hchallenge).2⟩
  dsimp only [combinedDenominator, combinedProfile]
  calc
    failureDenominator * profileDenominator *
          (AgreementProfile.tailSet score a).card
      ≤ failureDenominator * profileDenominator *
          (failureTail.card + arithmeticTail.card) :=
        Nat.mul_le_mul_left _ hcard
    _ = profileDenominator *
          (failureDenominator * failureTail.card) +
        failureDenominator *
          (profileDenominator * arithmeticTail.card) := by ring
    _ ≤ profileDenominator *
          (failureProfile.labelsAtLeast a * Fintype.card Challenge) +
        failureDenominator *
          (arithmeticProfile.labelsAtLeast (a - g) *
            Fintype.card Challenge) :=
      Nat.add_le_add
        (Nat.mul_le_mul_left _ (by simpa [failureTail] using hfailureDensity))
        (Nat.mul_le_mul_left _ (by
          exact (Nat.mul_le_mul_left _
            (Finset.card_le_card harithmeticSubset)).trans
              (by simpa using harithmeticDensity)))
    _ = (profileDenominator * failureProfile.labelsAtLeast a +
          failureDenominator * arithmeticProfile.labelsAtLeast (a - g)) *
            Fintype.card Challenge := by ring

/-- Fully instantiated response-agreement tail for the actual accepting
coordinate union carried by a profiled classifier. -/
theorem classifier_responseAgreement_density_above_floor
    {F Equations CheckedMask DirectMask Challenge Response : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Fintype CheckedMask] [DecidableEq CheckedMask]
    [Fintype Challenge]
    {r w n logicalWidth nw nq e g profileDenominator failureDenominator : ℕ}
    {C : MultiplicativeCode F r w n}
    {layout : ConstraintLayout F logicalWidth w}
    {policy : SchemeProtocolPolicy (Equations := Equations) C layout
      Challenge Response CheckedMask DirectMask nw nq 1}
    {oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1}
    {statement : ConstraintSystem F nw nq logicalWidth Equations}
    {respond : Challenge → Response}
    {failureProfile arithmeticProfile : AgreementProfile n}
    (classifier : PolicyDoublyProfiledSoundnessClassifier policy oracle statement
      respond failureProfile arithmeticProfile profileDenominator
        failureDenominator e g)
    (floor : ℕ) (hfarFloor : n - e - 1 ≤ floor) :
    ∀ a, floor < a → a ≤ n →
      combinedDenominator failureDenominator profileDenominator *
          (AgreementProfile.tailSet classifier.responseAgreement a).card ≤
        (combinedProfile failureDenominator profileDenominator g
          failureProfile arithmeticProfile).labelsAtLeast a *
            Fintype.card Challenge := by
  exact combined_score_density_above_floor classifier
    classifier.responseAgreement
    classifier.responseAgreement_le_failureAgreement
    classifier.responseAgreement_le_goodCap floor hfarFloor

/-- Strategy-uniform tail statement in the exact response-list membership
form consumed by `indexedLists_tail_density`. -/
theorem classifier_policyResponseAgreementList_density_above_floor
    {F Equations CheckedMask DirectMask Challenge Response : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Fintype CheckedMask] [DecidableEq CheckedMask]
    [Fintype Challenge] [DecidableEq Challenge]
    [Fintype Response] [DecidableEq Response]
    {r w n logicalWidth nw nq e g profileDenominator failureDenominator : ℕ}
    {C : MultiplicativeCode F r w n}
    {layout : ConstraintLayout F logicalWidth w}
    {policy : SchemeProtocolPolicy (Equations := Equations) C layout
      Challenge Response CheckedMask DirectMask nw nq 1}
    {oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1}
    {statement : ConstraintSystem F nw nq logicalWidth Equations}
    {respond : Challenge → Response}
    {failureProfile arithmeticProfile : AgreementProfile n}
    (classifier : PolicyDoublyProfiledSoundnessClassifier policy oracle statement
      respond failureProfile arithmeticProfile profileDenominator
        failureDenominator e g)
    (floor : ℕ) (hfarFloor : n - e - 1 ≤ floor) :
    ∀ a, floor < a → a ≤ n →
      combinedDenominator failureDenominator profileDenominator *
          (Finset.univ.filter fun challenge ↦
            respond challenge ∈ policyResponseAgreementList
              policy oracle statement challenge a).card ≤
        (combinedProfile failureDenominator profileDenominator g
          failureProfile arithmeticProfile).labelsAtLeast a *
            Fintype.card Challenge := by
  classical
  intro a hfloor ha
  have hsubset : (Finset.univ.filter fun challenge ↦
      respond challenge ∈ policyResponseAgreementList
        policy oracle statement challenge a) ⊆
      AgreementProfile.tailSet classifier.responseAgreement a := by
    intro challenge hchallenge
    have hmem := (Finset.mem_filter.mp hchallenge).2
    have hagreement : a ≤ classifier.responseAgreement challenge := by
      simpa [policyResponseAgreementList,
        PolicyDoublyProfiledSoundnessClassifier.responseAgreement] using
          (Finset.mem_filter.mp hmem).2.2
    exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, hagreement⟩
  have hcard := Finset.card_le_card hsubset
  exact (Nat.mul_le_mul_left _ hcard).trans
    (classifier_responseAgreement_density_above_floor classifier floor
      hfarFloor a hfloor ha)

/-- Multiply a strategy-uniform agreement-label tail by the response-list
multiplicity valid at that same agreement level. -/
def multipliedProfile {n : ℕ} (multiplicity : ℕ → ℕ)
    (profile : AgreementProfile n) : AgreementProfile n where
  labelsAtLeast a := multiplicity a * profile.labelsAtLeast a

/-- A deterministic (classically chosen) baseline of size
`min floor coordinates.card`. -/
noncomputable def baselineCoordinates {n : ℕ} (floor : ℕ)
    (coordinates : Finset (Fin n)) : Finset (Fin n) :=
  Classical.choose (Finset.exists_subset_card_eq
    (Nat.min_le_right floor coordinates.card))

theorem baselineCoordinates_subset {n floor : ℕ}
    (coordinates : Finset (Fin n)) :
    baselineCoordinates floor coordinates ⊆ coordinates := by
  exact (Classical.choose_spec (Finset.exists_subset_card_eq
    (Nat.min_le_right floor coordinates.card))).1

theorem baselineCoordinates_card {n floor : ℕ}
    (coordinates : Finset (Fin n)) :
    (baselineCoordinates floor coordinates).card =
      min floor coordinates.card := by
  exact (Classical.choose_spec (Finset.exists_subset_card_eq
    (Nat.min_le_right floor coordinates.card))).2

private theorem card_le_card_sub_of_disjoint_subset
    {X : Type*} [DecidableEq X] (small baseline total : Finset X)
    (hsmall : small ⊆ total) (hbaseline : baseline ⊆ total)
    (hdisjoint : Disjoint small baseline) :
    small.card ≤ total.card - baseline.card := by
  have hunion : small ∪ baseline ⊆ total := Finset.union_subset hsmall hbaseline
  have hcard := Finset.card_le_card hunion
  rw [Finset.card_union_of_disjoint hdisjoint] at hcard
  omega

noncomputable def responseExcessSet
    {Alpha Response : Type*} [Fintype Alpha] [Fintype Response]
    {n r : ℕ}
    (success : (Response × Alpha) × QuerySet n r → Prop) :
    Finset ((Response × Alpha) × QuerySet n r) := by
  classical
  exact Finset.univ.filter success

/-- Complete semantic response/query/challenge layer cake for a profiled
policy.  The response/challenge incidence is deliberately left unclipped:
several response targets may lie over one challenge, so clipping becomes
sound only after the lazy-target argument returns to an actual tape event. -/
theorem profiled_policyResponseExcess_ratio_le
    {F Equations CheckedMask DirectMask Challenge Response : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Fintype CheckedMask] [DecidableEq CheckedMask]
    [Fintype Challenge] [DecidableEq Challenge] [Nonempty Challenge]
    [Fintype Response] [DecidableEq Response] [Nonempty Response]
    {r w n logicalWidth nw nq e g profileDenominator failureDenominator : ℕ}
    {C : MultiplicativeCode F r w n}
    {layout : ConstraintLayout F logicalWidth w}
    (policy : SchemeProtocolPolicy (Equations := Equations) C layout
      Challenge Response CheckedMask DirectMask nw nq 1)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (statement : ConstraintSystem F nw nq logicalWidth Equations)
    (failureProfile arithmeticProfile : AgreementProfile n)
    (classifier : ∀ strategy : Challenge → Response,
      PolicyDoublyProfiledSoundnessClassifier policy oracle statement strategy
        failureProfile arithmeticProfile profileDenominator
          failureDenominator e g)
    (floor : ℕ) (multiplicity : ℕ → ℕ)
    (baseline : Response × Challenge → Finset (Fin n))
    (hprofile : 0 < profileDenominator)
    (hfailure : 0 < failureDenominator)
    (hquery : r ≤ n) (hfloorLt : floor < n)
    (hfarFloor : n - e - 1 ≤ floor)
    (hlist : ∀ a, floor < a → a ≤ n → ∀ challenge,
      (policyResponseAgreementList policy oracle statement challenge a).card ≤
        multiplicity a)
    (hbaselineSubset : ∀ pair,
      baseline pair ⊆ policyAcceptingCoordinates policy oracle statement
        pair.2 pair.1)
    (hbaselineCard : ∀ pair, (baseline pair).card = min floor
      (policyAcceptingCoordinates policy oracle statement pair.2 pair.1).card) :
    ((responseExcessSet fun value :
        (Response × Challenge) × QuerySet n r ↦
      policy.accepts statement value.1.2 value.1.1 value.2
          (openSchemeOracle oracle value.2) ∧
        ¬value.2.coordinates ⊆ baseline value.1).card : ℚ) /
        (Fintype.card (QuerySet n r) * Fintype.card Challenge) ≤
        (multipliedProfile multiplicity
        (combinedProfile failureDenominator profileDenominator g
          failureProfile arithmeticProfile)).rawExcessContribution
            (combinedDenominator failureDenominator profileDenominator)
              n n 0 r floor := by
  classical
  let combined := combinedProfile failureDenominator profileDenominator g
    failureProfile arithmeticProfile
  let denominator := combinedDenominator failureDenominator profileDenominator
  let selected : Finset (Response × Challenge) :=
    Finset.univ.filter fun pair ↦
      pair.1 ∈ policyResponseAgreementList policy oracle statement
        pair.2 (floor + 1)
  let agreement : Response × Challenge → ℕ := fun pair ↦
    (policyAcceptingCoordinates policy oracle statement pair.2 pair.1).card
  let success : (Response × Challenge) → QuerySet n r → Prop :=
    fun pair query ↦
      policy.accepts statement pair.2 pair.1 query
          (openSchemeOracle oracle query) ∧
        ¬query.coordinates ⊆ baseline pair
  letI : ∀ pair, DecidablePred (success pair) := fun _ ↦ Classical.decPred _
  have hdenominator : 0 < denominator :=
    combinedDenominator_pos hfailure hprofile
  have hagreementLe : ∀ pair ∈ selected, agreement pair ≤ n := by
    intro pair _
    exact policyAcceptingCoordinates_card_le policy oracle statement pair.2 pair.1
  have hagreementFloor : ∀ pair ∈ selected, floor < agreement pair := by
    intro pair hpair
    have hmem := (Finset.mem_filter.mp hpair).2
    have := (Finset.mem_filter.mp hmem).2.2
    simpa [agreement] using this
  have hdensity : ∀ a, floor < a → a ≤ n →
      denominator *
          (AgreementProfile.restrictedTailSet selected agreement a).card ≤
        (multipliedProfile multiplicity combined).labelsAtLeast a *
          Fintype.card Challenge := by
    intro a hfa han
    let lists := fun challenge ↦
      policyResponseAgreementList policy oracle statement challenge a
    have hraw := indexedLists_tail_density lists (multiplicity a) denominator
      (combined.labelsAtLeast a) (fun challenge ↦ hlist a hfa han challenge)
      (fun strategy ↦ by
        simpa [lists, denominator, combined] using
          classifier_policyResponseAgreementList_density_above_floor
            (classifier strategy) floor hfarFloor a hfa han)
    have htailSubset :
        AgreementProfile.restrictedTailSet selected agreement a ⊆
          Finset.univ.filter fun pair : Response × Challenge ↦
            pair.1 ∈ lists pair.2 := by
      intro pair hpair
      have hhigh := (Finset.mem_filter.mp hpair).2
      have hselectedMem := (Finset.mem_filter.mp hpair).1
      have haccept := (Finset.mem_filter.mp
        ((Finset.mem_filter.mp hselectedMem).2)).2.1
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
        Finset.mem_filter.mpr ⟨Finset.mem_univ _, haccept, by
          simpa [agreement] using hhigh⟩⟩
    exact (Nat.mul_le_mul_left _ (Finset.card_le_card htailSubset)).trans
      (by simpa [multipliedProfile, combined] using hraw)
  have hsuccessMember : ∀ pair query,
      success pair query → pair ∈ selected := by
    intro pair query hs
    have hcoords := query_subset_policyAcceptingCoordinates_of_accepts
      policy oracle statement pair.2 pair.1 query hs.1
    have hlarge : floor + 1 ≤ agreement pair := by
      have hnot := hs.2
      by_contra hsmall
      have hscoreLe : agreement pair ≤ floor := by omega
      have heq : baseline pair =
          policyAcceptingCoordinates policy oracle statement pair.2 pair.1 := by
        apply Finset.eq_of_subset_of_card_le (hbaselineSubset pair)
        rw [hbaselineCard pair, min_eq_right]
        simpa [agreement] using hscoreLe
      exact hnot (by simpa [heq] using hcoords)
    exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, by
      apply Finset.mem_filter.mpr
      exact ⟨Finset.mem_univ _, ⟨⟨query, hs.1⟩, by
        simpa [agreement] using hlarge⟩⟩⟩
  have hqueryCount : ∀ pair ∈ selected,
      (Finset.univ.filter (success pair)).card ≤
        (agreement pair).choose r - floor.choose r := by
    intro pair hp
    let allQueries := queriesWithin (r := r)
      (policyAcceptingCoordinates policy oracle statement pair.2 pair.1)
    let baseQueries := queriesWithin (r := r) (baseline pair)
    let successful := Finset.univ.filter (success pair)
    have hsmall : successful ⊆ allQueries := by
      intro query hqmem
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
        query_subset_policyAcceptingCoordinates_of_accepts policy oracle
          statement pair.2 pair.1 query (Finset.mem_filter.mp hqmem).2.1⟩
    have hbase : baseQueries ⊆ allQueries := by
      intro query hqmem
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
        (Finset.mem_filter.mp hqmem).2.trans
          (hbaselineSubset pair)⟩
    have hdisjoint : Disjoint successful baseQueries := by
      rw [Finset.disjoint_left]
      intro query hs hb
      exact (Finset.mem_filter.mp hs).2.2 (Finset.mem_filter.mp hb).2
    have hcard := card_le_card_sub_of_disjoint_subset successful baseQueries
      allQueries hsmall hbase hdisjoint
    rw [card_queriesWithin, card_queriesWithin,
      hbaselineCard pair, min_eq_left (hagreementFloor pair hp).le] at hcard
    simpa [successful, agreement] using hcard
  simpa only [responseExcessSet, success, selected, agreement, combined,
    denominator] using
    responseQueryChallenge_incidence_ratio_le denominator floor
      (multipliedProfile multiplicity combined) selected agreement success
      hdenominator hquery hfloorLt.le
      (fun pair hp ↦ ⟨hagreementFloor pair hp, hagreementLe pair hp⟩)
      hdensity hsuccessMember hqueryCount

/-- Install the probability-one baseline through `floor`, and use the exact
pointwise response-list/agreement product strictly above it.  Consequently
the contribution is

`H(floor) + Σ_{a>floor} ΔH(a) min(1, multiplicity(a) * tailLabels(a) / q)`

without selecting a threshold. -/
def caseAProfile {n : ℕ} (q floor : ℕ) (multiplicity : ℕ → ℕ)
    (profile : AgreementProfile n) : AgreementProfile n where
  labelsAtLeast a :=
    if a ≤ floor then q else multiplicity a * profile.labelsAtLeast a

theorem caseAProfile_labelsAtLeast_of_le {n q floor a : ℕ}
    (multiplicity : ℕ → ℕ) (profile : AgreementProfile n)
    (ha : a ≤ floor) :
    (caseAProfile q floor multiplicity profile).labelsAtLeast a = q := by
  simp [caseAProfile, ha]

theorem caseAProfile_labelsAtLeast_of_lt {n q floor a : ℕ}
    (multiplicity : ℕ → ℕ) (profile : AgreementProfile n)
    (ha : floor < a) :
    (caseAProfile q floor multiplicity profile).labelsAtLeast a =
      multiplicity a * profile.labelsAtLeast a := by
  simp [caseAProfile, Nat.not_le.mpr ha]

theorem caseAProfile_tail_of_le {n q floor a : ℕ}
    (multiplicity : ℕ → ℕ) (profile : AgreementProfile n)
    (hq : 0 < q) (ha : a ≤ floor) :
    (caseAProfile q floor multiplicity profile).tail q a = 1 := by
  rw [AgreementProfile.tail, caseAProfile_labelsAtLeast_of_le _ _ ha]
  norm_num [hq.ne']

theorem caseAProfile_tail_of_lt {n q floor a : ℕ}
    (multiplicity : ℕ → ℕ) (profile : AgreementProfile n)
    (ha : floor < a) :
    (caseAProfile q floor multiplicity profile).tail q a =
      min 1 (((multiplicity a * profile.labelsAtLeast a : ℕ) : ℚ) / q) := by
  rw [AgreementProfile.tail, caseAProfile_labelsAtLeast_of_lt _ _ ha]

/-- The literal threshold-free response-agreement integral.  This name is
used by the compiler and numerical grid so that no endpoint/list formula can
silently replace the full profile. -/
def caseAIntegral {n : ℕ} (q floor : ℕ) (multiplicity : ℕ → ℕ)
    (profile : AgreementProfile n) (queryCount : ℕ) : ℚ :=
  (caseAProfile q floor multiplicity profile).contribution
    q n n 0 queryCount

/-- Exact expanded formula for `caseAIntegral`.  This is a definitional
layer-cake identity, not an assumed numerical formula. -/
theorem caseAIntegral_eq_sum {n : ℕ} (q floor : ℕ)
    (multiplicity : ℕ → ℕ) (profile : AgreementProfile n)
    (queryCount : ℕ) :
    caseAIntegral q floor multiplicity profile queryCount =
      ∑ a ∈ Finset.range (n + 1),
        AgreementProfile.coverIncrement n n 0 queryCount a *
          if a ≤ floor then
            min 1 ((q : ℚ) / q)
          else
            min 1
              (((multiplicity a * profile.labelsAtLeast a : ℕ) : ℚ) / q) := by
  unfold caseAIntegral AgreementProfile.contribution AgreementProfile.tail
  apply Finset.sum_congr rfl
  intro a _ha
  by_cases haf : a ≤ floor
  · simp [caseAProfile, haf]
  · simp [caseAProfile, haf]

/-- A levelwise tail bound for the actual Case-A tapes implies the complete
threshold-free integral.  The tail profile already contains both the
probability-one cap and the pointwise response-list multiplicity; hence this
theorem has no selected threshold or endpoint loss. -/
theorem average_coverRatio_le_caseAIntegral
    {X : Type*} [Fintype X] [Nonempty X]
    {n : ℕ} (q floor : ℕ) (multiplicity : ℕ → ℕ)
    (profile : AgreementProfile n) (queryCount : ℕ)
    (agreement : X → ℕ) (hq : 0 < q)
    (hagreement : ∀ x, agreement x ≤ n)
    (hdensity : ∀ a ≤ n,
      q * (AgreementProfile.tailSet agreement a).card ≤
        (caseAProfile q floor multiplicity profile).labelsAtLeast a *
          Fintype.card X) :
    (∑ x : X, AgreementProfile.coverRatio n n 0 queryCount
        (agreement x)) / Fintype.card X ≤
      caseAIntegral q floor multiplicity profile queryCount := by
  exact AgreementProfile.average_coverRatio_le_contribution
    q n n 0 queryCount (caseAProfile q floor multiplicity profile)
      agreement hq hagreement hdensity

end ResponseAgreement

end LigeroFamily
