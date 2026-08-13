import SelectedMCA.Parameters
import AffineAgreement.TripleCounting
import Mathlib.Algebra.BigOperators.Ring.Finset
import Mathlib.Algebra.Order.Field.Rat
import Mathlib.Tactic.FieldSimp
import Mathlib.Tactic.Linarith

/-!
# Simple selected-clique counting

The direct selected-MCA theorem only needs a transparent pair budget.  If
distinct blocks meet in at most one vertex, their two-element subsets are
disjoint.  The exact local identity
`3 * choose(b, 3) = (b - 2) * choose(b, 2)` then gives the uniform upper
bound `floor((R - 2) * choose(m, 2) / 3)`.
-/

namespace SelectedMCA

open AffineAgreement

namespace Internal

/-- A finite block family in which distinct blocks share at most one vertex. -/
structure PairwiseBlockPacking {α : Type*} [DecidableEq α]
    (vertices : Finset α) where
  blocks : Finset (Finset α)
  block_subset : ∀ block ∈ blocks, block ⊆ vertices
  intersection_card_le_one : ∀ first ∈ blocks, ∀ second ∈ blocks,
    first ≠ second → (first ∩ second).card ≤ 1

/-- The pair sets of distinct blocks are disjoint, so the total number of
block pairs is at most the number of pairs of vertices. -/
theorem pairwiseBlockPacking_pairs_le {α : Type*} [DecidableEq α]
    (vertices : Finset α) (packing : PairwiseBlockPacking vertices) :
    ∑ block ∈ packing.blocks, block.card.choose 2 ≤ vertices.card.choose 2 := by
  let pairs : Finset α → Finset (Finset α) := fun block ↦ block.powersetCard 2
  have hdisjoint : (↑packing.blocks : Set (Finset α)).PairwiseDisjoint pairs := by
    intro first hfirst second hsecond hne
    apply Finset.disjoint_left.mpr
    intro pair hpairFirst hpairSecond
    have hfirstData := Finset.mem_powersetCard.mp hpairFirst
    have hsecondData := Finset.mem_powersetCard.mp hpairSecond
    have hsubset : pair ⊆ first ∩ second := by
      intro vertex hvertex
      exact Finset.mem_inter.mpr
        ⟨hfirstData.1 hvertex, hsecondData.1 hvertex⟩
    have hintersection := packing.intersection_card_le_one first hfirst second
      hsecond hne
    have hpairCard := Finset.card_le_card hsubset
    omega
  have hunionSubset : packing.blocks.biUnion pairs ⊆ vertices.powersetCard 2 := by
    intro pair hpair
    obtain ⟨block, hblock, hpairBlock⟩ := Finset.mem_biUnion.mp hpair
    have hdata := Finset.mem_powersetCard.mp hpairBlock
    exact Finset.mem_powersetCard.mpr
      ⟨hdata.1.trans (packing.block_subset block hblock), hdata.2⟩
  calc
    ∑ block ∈ packing.blocks, block.card.choose 2 =
        ∑ block ∈ packing.blocks, (pairs block).card := by
      apply Finset.sum_congr rfl
      intro block _
      exact (Finset.card_powersetCard 2 block).symm
    _ = (packing.blocks.biUnion pairs).card :=
      (Finset.card_biUnion hdisjoint).symm
    _ ≤ (vertices.powersetCard 2).card := Finset.card_le_card hunionSubset
    _ = vertices.card.choose 2 := Finset.card_powersetCard 2 vertices

private theorem three_mul_choose_three_eq (card : ℕ) :
    3 * card.choose 3 = card * (card - 1).choose 2 := by
  by_cases hcard : card = 0
  · simp [hcard]
  obtain ⟨previous, rfl⟩ := Nat.exists_eq_succ_of_ne_zero hcard
  simpa [Nat.mul_comm] using Nat.add_one_mul_choose_eq previous 2 |>.symm

private theorem three_mul_choose_three_eq_sub_two_mul_choose_two (card : ℕ) :
    3 * card.choose 3 = (card - 2) * card.choose 2 := by
  by_cases hcard : card = 0
  · simp [hcard]
  obtain ⟨previous, rfl⟩ := Nat.exists_eq_succ_of_ne_zero hcard
  calc
    3 * (previous + 1).choose 3 =
        (previous + 1) * previous.choose 2 :=
      three_mul_choose_three_eq (previous + 1)
    _ = (previous + 1 - 2) * (previous + 1).choose 2 := by
      simpa [Nat.mul_comm] using Nat.choose_mul_succ_eq previous 2

/-- A pairwise block family of occupancy at most `R` covers at most
`floor((R - 2) * choose(m, 2) / 3)` triples. -/
theorem pairwiseBlockPacking_triples_le_simple {α : Type*} [DecidableEq α]
    (vertices : Finset α) (packing : PairwiseBlockPacking vertices)
    (R : ℕ) (hblockCard : ∀ block ∈ packing.blocks, block.card ≤ R) :
    ∑ block ∈ packing.blocks, block.card.choose 3 ≤
      simpleCliqueUpperNat vertices.card R := by
  have hlocal (block : Finset α) (hblock : block ∈ packing.blocks) :
      3 * block.card.choose 3 ≤ (R - 2) * block.card.choose 2 := by
    rw [three_mul_choose_three_eq_sub_two_mul_choose_two]
    exact Nat.mul_le_mul_right _ (Nat.sub_le_sub_right
      (hblockCard block hblock) 2)
  have hscaled :
      3 * ∑ block ∈ packing.blocks, block.card.choose 3 ≤
        (R - 2) * vertices.card.choose 2 := by
    calc
      3 * ∑ block ∈ packing.blocks, block.card.choose 3 =
          ∑ block ∈ packing.blocks, 3 * block.card.choose 3 := by
        rw [Finset.mul_sum]
      _ ≤ ∑ block ∈ packing.blocks, (R - 2) * block.card.choose 2 :=
        Finset.sum_le_sum hlocal
      _ = (R - 2) * ∑ block ∈ packing.blocks, block.card.choose 2 := by
        rw [Finset.mul_sum]
      _ ≤ (R - 2) * vertices.card.choose 2 :=
        Nat.mul_le_mul_left (R - 2)
          (pairwiseBlockPacking_pairs_le vertices packing)
  unfold simpleCliqueUpperNat
  apply (Nat.le_div_iff_mul_le (by omega : 0 < 3)).2
  simpa [Nat.mul_comm] using hscaled

/-- Any marked triples covered by the blocks inherit the simple upper bound. -/
theorem marked_card_le_simpleCliqueUpper
    {α : Type*} [DecidableEq α]
    (vertices : Finset α) (packing : PairwiseBlockPacking vertices)
    (marked : Finset (Finset α)) (R : ℕ)
    (hblockCard : ∀ block ∈ packing.blocks, block.card ≤ R)
    (htripleCard : ∀ triple ∈ marked, triple.card = 3)
    (hcovered : ∀ triple ∈ marked,
      ∃ block ∈ packing.blocks, triple ⊆ block) :
    (marked.card : ℚ) ≤ simpleCliqueUpper vertices.card R := by
  let coveredTriples := packing.blocks.biUnion fun block ↦ block.powersetCard 3
  have hsubset : marked ⊆ coveredTriples := by
    intro triple htriple
    obtain ⟨block, hblock, htripleBlock⟩ := hcovered triple htriple
    exact Finset.mem_biUnion.mpr
      ⟨block, hblock, Finset.mem_powersetCard.mpr
        ⟨htripleBlock, htripleCard triple htriple⟩⟩
  have hcard : marked.card ≤
      ∑ block ∈ packing.blocks, block.card.choose 3 := by
    calc
      marked.card ≤ coveredTriples.card := Finset.card_le_card hsubset
      _ ≤ ∑ block ∈ packing.blocks, (block.powersetCard 3).card :=
        Finset.card_biUnion_le
      _ = ∑ block ∈ packing.blocks, block.card.choose 3 := by
        apply Finset.sum_congr rfl
        intro block _
        exact Finset.card_powersetCard 3 block
  have hpacking := pairwiseBlockPacking_triples_le_simple vertices packing R
    hblockCard
  have hnat : marked.card ≤ simpleCliqueUpperNat vertices.card R :=
    hcard.trans hpacking
  change (marked.card : ℚ) ≤ (simpleCliqueUpperNat vertices.card R : ℕ)
  exact_mod_cast hnat

/-- Exact lower bound on the number of marked triples from the balanced
third-moment estimate and two score caps. -/
theorem affineCliqueLower_le_marked_card
    {Triple : Type*} [DecidableEq Triple]
    (triples marked : Finset Triple) (score : Triple → ℕ)
    (N support m baseCap markedCap : ℕ)
    (hmarked : marked ⊆ triples)
    (htriples : triples.card = m.choose 3)
    (hm : 3 ≤ m) (hcaps : baseCap < markedCap)
    (hsum : balanced_choose_three N (m * support) ≤
      ∑ triple ∈ triples, score triple)
    (hscore : ∀ triple ∈ triples,
      score triple ≤
        baseCap + if triple ∈ marked then markedCap - baseCap else 0) :
    affineCliqueLower N support m baseCap markedCap ≤ marked.card := by
  have hfilter : triples.filter (fun triple ↦ triple ∈ marked) = marked := by
    ext triple
    simp only [Finset.mem_filter]
    constructor
    · exact fun h ↦ h.2
    · exact fun h ↦ ⟨hmarked h, h⟩
  have hconditional :
      ∑ triple ∈ triples,
          (if triple ∈ marked then markedCap - baseCap else 0) =
        marked.card * (markedCap - baseCap) := by
    rw [← Finset.sum_filter, hfilter]
    simp
  have hupper : ∑ triple ∈ triples, score triple ≤
      triples.card * baseCap + marked.card * (markedCap - baseCap) := by
    calc
      ∑ triple ∈ triples, score triple ≤
          ∑ triple ∈ triples,
            (baseCap + if triple ∈ marked then markedCap - baseCap else 0) :=
        Finset.sum_le_sum fun triple htriple ↦ hscore triple htriple
      _ = triples.card * baseCap +
          marked.card * (markedCap - baseCap) := by
        rw [Finset.sum_add_distrib, hconditional]
        simp
  have hbetween : balanced_choose_three N (m * support) ≤
      m.choose 3 * baseCap + marked.card * (markedCap - baseCap) := by
    rw [← htriples]
    exact hsum.trans hupper
  have hchoose : 0 < m.choose 3 := Nat.choose_pos hm
  have hchooseQ : (0 : ℚ) < m.choose 3 := by exact_mod_cast hchoose
  have hcapDiffQ : (0 : ℚ) < (markedCap : ℚ) - baseCap := by
    have hcapsQ : (baseCap : ℚ) < markedCap := by exact_mod_cast hcaps
    linarith
  have hbetweenQ :
      (balanced_choose_three N (m * support) : ℚ) ≤
        (m.choose 3 : ℚ) * baseCap +
          (marked.card : ℚ) * (markedCap - baseCap : ℕ) := by
    exact_mod_cast hbetween
  rw [Nat.cast_sub hcaps.le] at hbetweenQ
  unfold affineCliqueLower cliqueIntersectionMean
    AffineAgreement.tripleIntersectionMean
  rw [Nat.cast_sub hcaps.le]
  rw [div_le_iff₀ hcapDiffQ]
  field_simp [ne_of_gt hchooseQ]
  nlinarith

end Internal

end SelectedMCA
