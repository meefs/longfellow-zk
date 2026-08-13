import AffineAgreement.LineGeometry
import SelectedMCA.Parameters

/-!
# Directional selected-agreement bounds

Definitions and elementary incidence bounds shared by the global direct and
small-radius selected-MCA bounds.  This module contains no clique extraction.
-/

namespace SelectedMCA

open CodingTheory AffineAgreement
open scoped BigOperators

variable {F : Type*} [Field F] [DecidableEq F]

namespace Internal

variable {n e m : ℕ} {C : LinearCode F n} {u v : Word F n}

/-- Coordinates on which the selected decoding actually agrees with its
received word. -/
def selectedAgreementCoordinates
    (D : DecoderData (e := e) (m := m) C u v) (scalar : F) :
    Finset (Fin n) :=
  Finset.univ.filter fun j ↦
    affineWord u v scalar j = D.codeword scalar j

@[simp] theorem mem_selectedAgreementCoordinates
    (D : DecoderData (e := e) (m := m) C u v) (scalar : F) (j : Fin n) :
    j ∈ selectedAgreementCoordinates D scalar ↔
      affineWord u v scalar j = D.codeword scalar j := by
  simp [selectedAgreementCoordinates]

/-- A selected point is directionally `g`-liftable when, on all but `g` of
its actual agreement coordinates, the received direction agrees with a
codeword direction. -/
def DirectionallyGLiftable
    (D : DecoderData (e := e) (m := m) C u v)
    (scalar : F) (g : ℕ) : Prop :=
  ∃ direction ∈ C,
    (supportOn (selectedAgreementCoordinates D scalar)
      (v - direction)).card ≤ g

/-- Cancellation coordinates for a parameter following a given affine
codeword line. -/
def directionalCancellation
    (D : DecoderData (e := e) (m := m) C u v)
    (line : AffineCodewordLine D) (scalar : F) : Finset (Fin n) :=
  supportOn (selectedAgreementCoordinates D scalar)
    (v - line.direction)

/-- Cancellation coordinates lie in the active support of the followed
affine codeword line. -/
theorem directionalCancellation_subset_activeSupport
    (D : DecoderData (e := e) (m := m) C u v)
    (line : AffineCodewordLine D) {scalar : F} :
    directionalCancellation D line scalar ⊆ line.activeSupport D := by
  intro j hj
  exact Finset.mem_union_right _
    ((mem_supportOn _ _ _).mpr
      ⟨Finset.mem_univ _, (mem_supportOn _ _ _).mp hj |>.2⟩)

/-- Distinct parameters following the same affine codeword line have
disjoint directional-cancellation sets. -/
theorem directionalCancellation_disjoint
    (D : DecoderData (e := e) (m := m) C u v)
    (line : AffineCodewordLine D) {first second : F}
    (hfirst : first ∈ line.followingParameters D)
    (hsecond : second ∈ line.followingParameters D)
    (hne : first ≠ second) :
    Disjoint (directionalCancellation D line first)
      (directionalCancellation D line second) := by
  apply Finset.disjoint_left.mpr
  intro j hjFirst hjSecond
  have hfirstDirection :=
    (mem_supportOn _ _ _).mp hjFirst |>.2
  have hfirstAgreement := (mem_selectedAgreementCoordinates D first j).mp
    ((mem_supportOn _ _ _).mp hjFirst |>.1)
  have hsecondAgreement := (mem_selectedAgreementCoordinates D second j).mp
    ((mem_supportOn _ _ _).mp hjSecond |>.1)
  have hfirstLine := congrFun (line.selectedDecoding_eq D hfirst) j
  have hsecondLine := congrFun (line.selectedDecoding_eq D hsecond) j
  have hfirstZero :
      affineWord (u - line.base) (v - line.direction) first j = 0 := by
    rw [affineWord_sub, Pi.sub_apply, hfirstAgreement, hfirstLine, sub_self]
  have hsecondZero :
      affineWord (u - line.base) (v - line.direction) second j = 0 := by
    rw [affineWord_sub, Pi.sub_apply, hsecondAgreement, hsecondLine, sub_self]
  have hmul : (first - second) * (v - line.direction) j = 0 := by
    calc
      (first - second) * (v - line.direction) j =
          affineWord (u - line.base) (v - line.direction) first j -
            affineWord (u - line.base) (v - line.direction) second j := by
        simp [affineWord]
        ring
      _ = 0 := by rw [hfirstZero, hsecondZero, sub_self]
  exact hne (sub_eq_zero.mp
    ((mul_eq_zero.mp hmul).resolve_right hfirstDirection))

noncomputable def directionallyNonliftableFollowing
    (D : DecoderData (e := e) (m := m) C u v)
    (line : AffineCodewordLine D) (g : ℕ) : Finset F := by
  classical
  exact line.followingParameters D |>.filter fun scalar ↦
    ¬DirectionallyGLiftable D scalar g

/-- On an affine codeword line of active support at most `h`, at most
`floor(h/(g+1))` following parameters can fail directional `g`-liftability. -/
theorem directionallyNonliftableFollowing_card_le
    {h g : ℕ} (D : DecoderData (e := e) (m := m) C u v)
    (line : AffineCodewordLine D)
    (hsupport : (line.activeSupport D).card ≤ h) :
    (directionallyNonliftableFollowing D line g).card ≤ cancellationBound h g := by
  classical
  let bad := directionallyNonliftableFollowing D line g
  have hlarge (scalar : F) (hscalar : scalar ∈ bad) :
      g + 1 ≤ (directionalCancellation D line scalar).card := by
    have hbadMem : scalar ∈ (line.followingParameters D).filter
        (fun scalar ↦ ¬DirectionallyGLiftable D scalar g) := by
      simpa [bad, directionallyNonliftableFollowing] using hscalar
    have hfollowing := (Finset.mem_filter.mp hbadMem).1
    have hnotLiftable := (Finset.mem_filter.mp hbadMem).2
    have hdirectionMem := line.direction_mem
    have hnotSmall : ¬(directionalCancellation D line scalar).card ≤ g := by
      intro hsmall
      exact hnotLiftable ⟨line.direction, hdirectionMem, hsmall⟩
    omega
  have hdisjoint : (bad : Set F).PairwiseDisjoint
      (directionalCancellation D line) := by
    intro first hfirst second hsecond hne
    have hfirstMem : first ∈ (line.followingParameters D).filter
        (fun scalar ↦ ¬DirectionallyGLiftable D scalar g) := by
      simpa [bad, directionallyNonliftableFollowing] using hfirst
    have hsecondMem : second ∈ (line.followingParameters D).filter
        (fun scalar ↦ ¬DirectionallyGLiftable D scalar g) := by
      simpa [bad, directionallyNonliftableFollowing] using hsecond
    exact directionalCancellation_disjoint D line
      (Finset.mem_filter.mp hfirstMem).1
      (Finset.mem_filter.mp hsecondMem).1 hne
  have hunionSubset : bad.biUnion (directionalCancellation D line) ⊆
      line.activeSupport D := by
    intro j hj
    obtain ⟨scalar, hscalar, hjCancellation⟩ := Finset.mem_biUnion.mp hj
    exact directionalCancellation_subset_activeSupport D line hjCancellation
  have hcount : bad.card * (g + 1) ≤ h := by
    calc
      bad.card * (g + 1) = ∑ _scalar ∈ bad, (g + 1) := by simp
      _ ≤ ∑ scalar ∈ bad, (directionalCancellation D line scalar).card :=
        Finset.sum_le_sum fun scalar hscalar ↦ hlarge scalar hscalar
      _ = (bad.biUnion (directionalCancellation D line)).card := by
        symm
        exact Finset.card_biUnion hdisjoint
      _ ≤ (line.activeSupport D).card := Finset.card_le_card hunionSubset
      _ ≤ h := hsupport
  exact (Nat.le_div_iff_mul_le (by omega)).2 hcount

/-- All selected parameters that fail directional `g`-liftability. -/
noncomputable def directionallyNonliftableParameters
    (D : DecoderData (e := e) (m := m) C u v) (g : ℕ) : Finset F := by
  classical
  exact D.parameters.filter fun scalar ↦
    ¬DirectionallyGLiftable D scalar g

/-- Below one third of the code distance, all selected decodings lie on a
single affine codeword line.  This includes the two-point case and needs no
clique threshold or common-support radius. -/
theorem exists_affineCodewordLine_following_all_of_three_radius
    {d : ℕ} (D : DecoderData (e := e) (m := m) C u v)
    (hmin : HasMinimumDistanceAtLeast C d)
    (htwo : 2 ≤ D.parameters.card) (hthree : 3 * e < d) :
    ∃ line : AffineCodewordLine D,
      D.parameters ⊆ line.followingParameters D := by
  classical
  obtain ⟨a, ha, b, hb, hab⟩ :=
    Finset.one_lt_card.mp (by omega : 1 < D.parameters.card)
  obtain ⟨line, haLine, hbLine⟩ :=
    exists_affineCodewordLine_through_two D ha hb hab
  refine ⟨line, ?_⟩
  intro c hc
  by_cases hca : c = a
  · simpa [hca] using haLine
  by_cases hcb : c = b
  · simpa [hcb] using hbLine
  let error : F → Finset (Fin n) := fun scalar ↦
    supportOn Finset.univ (affineWord u v scalar - D.codeword scalar)
  let occupied := (error a ∪ error b) ∪ error c
  let common := Finset.univ \ occupied
  have herror (scalar : F) (hscalar : scalar ∈ D.parameters) :
      (error scalar).card ≤ e := by
    simpa [error, weight] using D.error_card hscalar
  have hoccupied : occupied.card ≤ 3 * e := by
    calc
      occupied.card ≤ (error a ∪ error b).card + (error c).card :=
        Finset.card_union_le (error a ∪ error b) (error c)
      _ ≤ ((error a).card + (error b).card) + (error c).card :=
        Nat.add_le_add_right (Finset.card_union_le (error a) (error b)) _
      _ ≤ 3 * e := by
        have hea := herror a ha
        have heb := herror b hb
        have hec := herror c hc
        omega
  have hcommonCard : common.card = n - occupied.card := by
    dsimp [common]
    rw [Finset.card_sdiff_of_subset (Finset.subset_univ occupied),
      Finset.card_univ, Fintype.card_fin]
  have hdLength := hmin.distance_le_length
  have hlarge : n - d < common.card := by
    rw [hcommonCard]
    omega
  let triple : Finset F := {a, b, c}
  have hac : a ≠ c := Ne.symm hca
  have hbc : b ≠ c := Ne.symm hcb
  have htripleCard : triple.card = 3 := by
    simp [triple, hab, hac, hbc]
  have htripleSubset : triple ⊆ D.parameters := by
    intro scalar hscalar
    simp only [triple, Finset.mem_insert, Finset.mem_singleton] at hscalar
    rcases hscalar with rfl | rfl | rfl
    · exact ha
    · exact hb
    · exact hc
  have htriple : triple ∈ D.parameters.powersetCard 3 :=
    Finset.mem_powersetCard.mpr ⟨htripleSubset, htripleCard⟩
  have hagree (scalar : F) (hscalar : scalar ∈ triple)
      (j : Fin n) (hj : j ∈ common) :
      affineWord u v scalar j = D.codeword scalar j := by
    have hjOccupied : j ∉ occupied := (Finset.mem_sdiff.mp hj).2
    have hscalarCases : scalar = a ∨ scalar = b ∨ scalar = c := by
      simpa [triple] using hscalar
    have hjError : j ∉ error scalar := by
      rcases hscalarCases with rfl | rfl | rfl
      · exact fun h ↦ hjOccupied (Finset.mem_union_left _
          (Finset.mem_union_left _ h))
      · exact fun h ↦ hjOccupied (Finset.mem_union_left _
          (Finset.mem_union_right _ h))
      · exact fun h ↦ hjOccupied (Finset.mem_union_right _ h)
    have hzero :
        (affineWord u v scalar - D.codeword scalar) j = 0 := by
      simpa [error, supportOn] using hjError
    exact sub_eq_zero.mp hzero
  obtain ⟨other, hother⟩ := affineCodewordLine_of_common_agreement
    D hmin triple htriple common hagree hlarge
  have haOther : a ∈ other.followingParameters D :=
    hother (by simp [triple])
  have hbOther : b ∈ other.followingParameters D :=
    hother (by simp [triple])
  have hlines : line = other :=
    line.eq_of_two_parameters D other hab haLine hbLine haOther hbOther
  rw [hlines]
  exact hother (by simp [triple])

/-- Sharp one-line profile below `d/3`.  If every selected point is
directionally nonliftable, incidence counting and cancellation disjointness
give `(B-1)(g+1) ≤ e`. -/
theorem parameters_card_le_one_add_div_of_all_nonliftable_three_radius
    {d g : ℕ} (D : DecoderData (e := e) (m := m) C u v)
    (hmin : HasMinimumDistanceAtLeast C d) (hthree : 3 * e < d)
    (hall : ∀ scalar ∈ D.parameters,
      ¬DirectionallyGLiftable D scalar g) :
    D.parameters.card ≤ 1 + e / (g + 1) := by
  classical
  by_cases hsmall : D.parameters.card ≤ 1
  · exact hsmall.trans (Nat.le_add_right 1 (e / (g + 1)))
  have htwo : 2 ≤ D.parameters.card := by omega
  obtain ⟨line, hfollowing⟩ :=
    exists_affineCodewordLine_following_all_of_three_radius D hmin htwo hthree
  have hbadEq : directionallyNonliftableFollowing D line g = D.parameters := by
    apply Finset.Subset.antisymm
    · exact (Finset.filter_subset _ _).trans line.followingParameters_subset
    · intro scalar hscalar
      exact Finset.mem_filter.mpr
        ⟨hfollowing hscalar, hall scalar hscalar⟩
  let active := (line.activeSupport D).card
  have hbadBound := directionallyNonliftableFollowing_card_le
    (h := active) (g := g) D line (by simp [active])
  rw [hbadEq] at hbadBound
  have hcancellations : D.parameters.card * (g + 1) ≤ active := by
    exact (Nat.le_div_iff_mul_le (by omega : 0 < g + 1)).mp hbadBound
  let x := u - line.base
  let y := v - line.direction
  have hweight (scalar : F) (hscalar : scalar ∈ D.parameters) :
      weight (affineWord x y scalar) ≤ e := by
    have hline := line.selectedDecoding_eq D (hfollowing hscalar)
    dsimp [x, y]
    rw [affineWord_sub, ← hline]
    exact D.error_card hscalar
  have hincidence := affineLine_incidence_bound x y D.parameters hweight
  have hactive : (jointSupport x y).card = active := by rfl
  rw [hactive] at hincidence
  have hscaled :
      D.parameters.card * ((D.parameters.card - 1) * (g + 1)) ≤
        D.parameters.card * e := by
    calc
      D.parameters.card * ((D.parameters.card - 1) * (g + 1)) =
          (D.parameters.card - 1) *
            (D.parameters.card * (g + 1)) := by ring
      _ ≤ (D.parameters.card - 1) * active :=
        Nat.mul_le_mul_left _ hcancellations
      _ ≤ D.parameters.card * e := hincidence
  have hpositive : 0 < D.parameters.card := by omega
  have hcancelled : (D.parameters.card - 1) * (g + 1) ≤ e := by
    exact Nat.le_of_mul_le_mul_left (c := D.parameters.card) hscaled hpositive
  have hquotient : D.parameters.card - 1 ≤ e / (g + 1) :=
    (Nat.le_div_iff_mul_le (by omega : 0 < g + 1)).mpr hcancelled
  omega

/-- Radius-`e` selected points that fail directional `g`-liftability obey the
sharp profile `1 + floor(e/(g+1))` whenever `3e < d`. -/
theorem directionallyNonliftableParameters_card_le_of_three_radius
    {d g : ℕ} (D : DecoderData (e := e) (m := m) C u v)
    (hmin : HasMinimumDistanceAtLeast C d) (hthree : 3 * e < d) :
    (directionallyNonliftableParameters D g).card ≤
      1 + e / (g + 1) := by
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
      ext j
      simp only [mem_selectedAgreementCoordinates]
      rw [D.restrict_codeword_eq bad hbadSubset rfl hscalarBad]
    simpa [hagreement] using hsmall
  have hbound :=
    parameters_card_le_one_add_div_of_all_nonliftable_three_radius
      restricted hmin hthree hall
  simpa [restricted, bad] using hbound


end Internal

export Internal
  (DirectionallyGLiftable directionallyNonliftableParameters
    selectedAgreementCoordinates mem_selectedAgreementCoordinates
    exists_affineCodewordLine_following_all_of_three_radius
    parameters_card_le_one_add_div_of_all_nonliftable_three_radius
    directionallyNonliftableParameters_card_le_of_three_radius)

end SelectedMCA
