import SelectedMCA.DirectionalBasics
import SelectedMCA.SimpleClique

/-!
# Direct selected-MCA extraction

This module replaces the two-stage support-radius argument by one clique
count.  A large agreement triple determines an affine codeword line.  On
each such line, directionally nonliftable selected points consume disjoint
sets of at least `g+1` active coordinates, so the line contains at most
`floor(n/(g+1))` of them.
-/

namespace SelectedMCA

open CodingTheory AffineAgreement

variable {F : Type*} [Field F] [DecidableEq F]

namespace Internal

variable {n e m : ℕ} {C : LinearCode F n} {u v : Word F n}

/-- The following-parameter sets of any finite family of affine codeword
lines form a pairwise block packing. -/
noncomputable def affineCodewordLinePacking
    {n e m : ℕ} {C : LinearCode F n} {u v : Word F n}
    (D : DecoderData (e := e) (m := m) C u v)
    (lines : Finset (AffineCodewordLine D)) : PairwiseBlockPacking D.parameters := by
  classical
  let blocks := lines.image fun line ↦ line.followingParameters D
  refine {
    blocks := blocks
    block_subset := ?_
    intersection_card_le_one := ?_ }
  · intro block hblock
    obtain ⟨line, _hline, rfl⟩ := Finset.mem_image.mp hblock
    exact line.followingParameters_subset D
  · intro first hfirst second hsecond hne
    obtain ⟨firstLine, _hfirstLine, hfirstEq⟩ :=
      Finset.mem_image.mp hfirst
    obtain ⟨secondLine, _hsecondLine, hsecondEq⟩ :=
      Finset.mem_image.mp hsecond
    apply Nat.le_of_not_gt
    intro hlarge
    obtain ⟨a, ha, b, hb, hab⟩ := Finset.one_lt_card.mp hlarge
    have haFirst := (Finset.mem_inter.mp ha).1
    have haSecond := (Finset.mem_inter.mp ha).2
    have hbFirst := (Finset.mem_inter.mp hb).1
    have hbSecond := (Finset.mem_inter.mp hb).2
    have hlines : firstLine = secondLine :=
      firstLine.eq_of_two_parameters D secondLine hab
        (hfirstEq ▸ haFirst) (hfirstEq ▸ hbFirst)
        (hsecondEq ▸ haSecond) (hsecondEq ▸ hbSecond)
    apply hne
    rw [← hfirstEq, ← hsecondEq, hlines]

@[simp] theorem affineCodewordLinePacking_blocks
    {n e m : ℕ} {C : LinearCode F n} {u v : Word F n}
    (D : DecoderData (e := e) (m := m) C u v)
    (lines : Finset (AffineCodewordLine D)) :
    (affineCodewordLinePacking D lines).blocks =
      lines.image fun line ↦ line.followingParameters D := by
  rfl

private theorem not_threshold_le_parameters_of_all_nonliftable_direct
    {d g threshold : ℕ}
    (D : DecoderData (e := e) (m := m) C u v)
    (hmin : HasMinimumDistanceAtLeast C d)
    (hcondition : DirectCliqueCondition n e g d threshold)
    (hall : ∀ scalar ∈ D.parameters,
      ¬DirectionallyGLiftable D scalar g) :
    ¬threshold ≤ D.parameters.card := by
  classical
  intro hthreshold
  have hm : 3 ≤ threshold := hcondition.card_ge_three
  obtain ⟨selected, hselected, hselectedCard⟩ :=
    Finset.exists_subset_card_eq hthreshold
  let restricted : DecoderData (e := e) (m := threshold) C u v :=
    D.restrict selected hselected hselectedCard
  have hen : e ≤ n := by
    have hdn := hmin.distance_le_length
    exact (Nat.le_of_lt hcondition.radius_lt_distance).trans hdn
  obtain ⟨padded⟩ := paddedErrorFamily_nonempty restricted hen
  let triples := restricted.parameters.powersetCard 3
  let score : Finset F → ℕ := fun triple ↦
    (agreementIntersection padded.error triple).card
  let marked := triples.filter fun triple ↦ n - d < score triple
  have hmarked (triple : Finset F) : triple ∈ marked ↔
      triple ∈ restricted.parameters.powersetCard 3 ∧
        n - d < (agreementIntersection padded.error triple).card := by
    simp [marked, triples, score]
  let lineFor : {triple // triple ∈ marked} → AffineCodewordLine restricted :=
    fun triple ↦ Classical.choose <|
      affineCodewordLine_of_large_intersection restricted padded hmin triple.1
        (hmarked triple.1 |>.mp triple.2).1
        (hmarked triple.1 |>.mp triple.2).2
  have hlineFor (triple : {triple // triple ∈ marked}) :
      triple.1 ⊆ (lineFor triple).followingParameters restricted :=
    Classical.choose_spec <|
      affineCodewordLine_of_large_intersection restricted padded hmin triple.1
        (hmarked triple.1 |>.mp triple.2).1
        (hmarked triple.1 |>.mp triple.2).2
  let lines : Finset (AffineCodewordLine restricted) :=
    marked.attach.image lineFor
  let packing := affineCodewordLinePacking restricted lines
  have hallRestricted (scalar : F) (hscalar : scalar ∈ restricted.parameters) :
      ¬DirectionallyGLiftable restricted scalar g := by
    have hscalarSelected : scalar ∈ selected := by
      simpa [restricted] using hscalar
    intro hliftable
    apply hall scalar (hselected hscalarSelected)
    rcases hliftable with ⟨direction, hdirection, hsmall⟩
    refine ⟨direction, hdirection, ?_⟩
    have hagreement : selectedAgreementCoordinates restricted scalar =
        selectedAgreementCoordinates D scalar := by
      ext coordinate
      simp only [mem_selectedAgreementCoordinates]
      rw [D.restrict_codeword_eq selected hselected hselectedCard
        hscalarSelected]
    simpa [hagreement] using hsmall
  have hblockCard (block : Finset F) (hblock : block ∈ packing.blocks) :
      block.card ≤ directLineOccupancyBound n g := by
    dsimp only [packing] at hblock
    rw [affineCodewordLinePacking_blocks] at hblock
    obtain ⟨line, _hline, rfl⟩ := Finset.mem_image.mp hblock
    have hsubset : line.followingParameters restricted ⊆
        directionallyNonliftableFollowing restricted line g := by
      intro scalar hscalar
      exact Finset.mem_filter.mpr
        ⟨hscalar, hallRestricted scalar
          (line.followingParameters_subset restricted hscalar)⟩
    have hactive : (line.activeSupport restricted).card ≤ n := by
      simpa using Finset.card_le_univ (line.activeSupport restricted)
    exact (Finset.card_le_card hsubset |>.trans
      (directionallyNonliftableFollowing_card_le restricted line hactive))
  have hcovered (triple : Finset F) (htriple : triple ∈ marked) :
      ∃ block ∈ packing.blocks, triple ⊆ block := by
    let indexed : {triple // triple ∈ marked} := ⟨triple, htriple⟩
    refine ⟨(lineFor indexed).followingParameters restricted, ?_,
      hlineFor indexed⟩
    dsimp only [packing]
    rw [affineCodewordLinePacking_blocks]
    apply Finset.mem_image.mpr
    refine ⟨lineFor indexed, ?_, rfl⟩
    apply Finset.mem_image.mpr
    exact ⟨indexed, Finset.mem_attach marked indexed, rfl⟩
  have htripleCard (triple : Finset F) (htriple : triple ∈ marked) :
      triple.card = 3 :=
    (Finset.mem_powersetCard.mp (hmarked triple |>.mp htriple).1).2
  have hupper : (marked.card : ℚ) ≤
      simpleCliqueUpper threshold (directLineOccupancyBound n g) := by
    rw [← restricted.card_parameters]
    exact marked_card_le_simpleCliqueUpper restricted.parameters packing marked
      (directLineOccupancyBound n g) hblockCard htripleCard hcovered
  have hbaseMarked : n - d < n - e := by
    exact hcondition.cap_lt
  have hlower : affineCliqueLower n (n - e) threshold (n - d) (n - e) ≤
      marked.card := by
    apply affineCliqueLower_le_marked_card triples marked score n (n - e)
      threshold (n - d) (n - e)
    · exact Finset.filter_subset _ _
    · simp [triples, restricted.card_parameters]
    · exact hm
    · exact hbaseMarked
    · simpa [triples, score, rounded_choose_three_eq_balanced_choose_three]
        using triple_intersection_sum_lower restricted.parameters padded.error
          restricted.card_parameters
          (fun scalar hscalar ↦ padded.card_eq hscalar)
    · intro triple htriple
      by_cases htripleMarked : triple ∈ marked
      · simp only [htripleMarked, if_true]
        rw [Nat.add_sub_of_le hbaseMarked.le]
        have htriplePower := (hmarked triple |>.mp htripleMarked).1
        obtain ⟨scalar, hscalar⟩ : ∃ scalar, scalar ∈ triple := by
          exact (Finset.card_pos.mp (by
            rw [(Finset.mem_powersetCard.mp htriplePower).2]
            omega))
        have hsubsetAgreement : agreementIntersection padded.error triple ⊆
            Finset.univ \ padded.error scalar := by
          intro coordinate hcoordinate
          exact Finset.mem_sdiff.mpr ⟨Finset.mem_univ _,
            (mem_agreementIntersection padded.error triple coordinate).mp
              hcoordinate scalar hscalar⟩
        have hscalarRestricted : scalar ∈ restricted.parameters :=
          (Finset.mem_powersetCard.mp htriplePower).1 hscalar
        have hcardComplement :
            (Finset.univ \ padded.error scalar).card = n - e := by
          rw [Finset.card_sdiff_of_subset (Finset.subset_univ _),
            Finset.card_univ, Fintype.card_fin,
            padded.card_eq hscalarRestricted]
        dsimp [score]
        rw [← hcardComplement]
        exact Finset.card_le_card hsubsetAgreement
      · simp only [htripleMarked, if_false, add_zero]
        have hnotLarge : ¬n - d < score triple := by
          intro hlarge
          exact htripleMarked (Finset.mem_filter.mpr ⟨htriple, hlarge⟩)
        omega
  exact (not_lt_of_ge hupper) (hcondition.clique_lt.trans_le hlower)

/-- If every selected point is directionally nonliftable, the direct clique
condition gives the sharp integer conclusion that fewer than `threshold`
parameters were selected. -/
theorem parameters_card_lt_of_all_nonliftable_direct
    {d g threshold : ℕ}
    (D : DecoderData (e := e) (m := m) C u v)
    (hmin : HasMinimumDistanceAtLeast C d)
    (hcondition : DirectCliqueCondition n e g d threshold)
    (hall : ∀ scalar ∈ D.parameters,
      ¬DirectionallyGLiftable D scalar g) :
    D.parameters.card < threshold :=
  Nat.lt_of_not_ge <|
    not_threshold_le_parameters_of_all_nonliftable_direct D hmin hcondition hall

/-- Radius-`e` selected points failing directional `g`-liftability number
strictly fewer than the direct clique threshold. -/
theorem directionallyNonliftableParameters_card_lt_direct
    {d g threshold : ℕ}
    (D : DecoderData (e := e) (m := m) C u v)
    (hmin : HasMinimumDistanceAtLeast C d)
    (hcondition : DirectCliqueCondition n e g d threshold) :
    (directionallyNonliftableParameters D g).card < threshold := by
  classical
  let bad := directionallyNonliftableParameters D g
  have hbadSubset : bad ⊆ D.parameters := Finset.filter_subset _ _
  let restricted : DecoderData (e := e) (m := bad.card) C u v :=
    D.restrict bad hbadSubset rfl
  have hall (scalar : F) (hscalar : scalar ∈ restricted.parameters) :
      ¬DirectionallyGLiftable restricted scalar g := by
    have hscalarBad : scalar ∈ bad := by simpa [restricted] using hscalar
    have hnot := (Finset.mem_filter.mp
      (show scalar ∈ directionallyNonliftableParameters D g by
        simpa [bad] using hscalarBad)).2
    intro hliftable
    apply hnot
    rcases hliftable with ⟨direction, hdirection, hsmall⟩
    refine ⟨direction, hdirection, ?_⟩
    have hagreement : selectedAgreementCoordinates restricted scalar =
        selectedAgreementCoordinates D scalar := by
      ext coordinate
      simp only [mem_selectedAgreementCoordinates]
      rw [D.restrict_codeword_eq bad hbadSubset rfl hscalarBad]
    simpa [hagreement] using hsmall
  have hbound := parameters_card_lt_of_all_nonliftable_direct restricted hmin
    hcondition hall
  simpa [restricted, bad] using hbound

/-- Subtraction-form compatibility wrapper for the strict filtered bound. -/
theorem directionallyNonliftableParameters_card_le_direct
    {d g threshold : ℕ}
    (D : DecoderData (e := e) (m := m) C u v)
    (hmin : HasMinimumDistanceAtLeast C d)
    (hcondition : DirectCliqueCondition n e g d threshold) :
    (directionallyNonliftableParameters D g).card ≤
      directLineFailureBound threshold := by
  have hlt := directionallyNonliftableParameters_card_lt_direct D hmin hcondition
  unfold directLineFailureBound
  omega

end Internal

export Internal
  (parameters_card_lt_of_all_nonliftable_direct
    directionallyNonliftableParameters_card_lt_direct
    directionallyNonliftableParameters_card_le_direct)

end SelectedMCA
