import AffineAgreement.LineGeometry
import CorrelatedAgreement.Parameters

/-! Exact incidence counting and extraction of an affine codeword line. -/

namespace CorrelatedAgreement

open AffineAgreement

open scoped BigOperators

variable {F : Type*} [Field F] [DecidableEq F]

namespace Internal

omit [Field F] [DecidableEq F] in
private theorem triple_intersection_mean_le_support {n e m : ℕ} (hm : 3 ≤ m) :
    triple_intersection_mean n e m ≤ (n - e : ℕ) := by
  let active : Finset (Fin n) :=
    Finset.univ.filter fun i ↦ i.1 < n - e
  have hactiveCard : active.card = n - e := by
    simpa [active] using
      (Fin.card_filter_val_lt (n := n) (m := n - e))
  let occupancy : Fin n → ℕ := fun i ↦ if i ∈ active then m else 0
  have hsum : ∑ i, occupancy i = m * (n - e) := by
    simp [occupancy, hactiveCard, Nat.mul_comm]
  have hbalanced := balanced_choose_three_lower occupancy hsum
  have hchoosePoint (i : Fin n) :
      (occupancy i).choose 3 = if i ∈ active then m.choose 3 else 0 := by
    by_cases hi : i ∈ active <;> simp [occupancy, hi]
  have hupper : balanced_choose_three n (m * (n - e)) ≤
      (n - e) * m.choose 3 := by
    simp_rw [hchoosePoint] at hbalanced
    simpa [hactiveCard] using hbalanced
  have hchoose : (0 : ℚ) < m.choose 3 := by
    exact_mod_cast Nat.choose_pos hm
  unfold triple_intersection_mean AffineAgreement.tripleIntersectionMean
  rw [div_le_iff₀ hchoose]
  exact_mod_cast hupper

/-- The extraction inequality itself forces the tested radius below the
distance parameter. -/
theorem testRadius_lt_distance_of_extraction_bound {n e d m b : ℕ}
    (hm : 3 ≤ m)
    (hA : (((m - 2 : ℕ) : ℚ)) *
        (triple_intersection_mean n e m - (n - d : ℕ)) >
      (b - 3 : ℕ) * (d - e : ℕ)) :
    e < d := by
  by_contra hnot
  have hde : d ≤ e := Nat.le_of_not_gt hnot
  have hmean := triple_intersection_mean_le_support (n := n) (e := e) hm
  have hsub : n - e ≤ n - d := Nat.sub_le_sub_left hde n
  have hdiff : triple_intersection_mean n e m - (n - d : ℕ) ≤ 0 := by
    exact sub_nonpos.mpr (hmean.trans (by exact_mod_cast hsub))
  have hleft : (((m - 2 : ℕ) : ℚ)) *
      (triple_intersection_mean n e m - (n - d : ℕ)) ≤ 0 :=
    mul_nonpos_of_nonneg_of_nonpos (by positivity) hdiff
  have hright : (0 : ℚ) ≤ (b - 3 : ℕ) * (d - e : ℕ) := by positivity
  linarith

omit [Field F] [DecidableEq F] in
private theorem agreementIntersection_card_le {n e : ℕ} {S : Finset F}
    (E : F → Finset (Fin n)) (hE : ∀ a ∈ S, (E a).card = e)
    {t : Finset F} (htS : t ⊆ S) (ht : t.Nonempty) :
    (agreementIntersection E t).card ≤ n - e := by
  obtain ⟨a, ha⟩ := ht
  have hsub : agreementIntersection E t ⊆ Finset.univ \ E a := by
    intro i hi
    exact Finset.mem_sdiff.mpr ⟨Finset.mem_univ i,
      (mem_agreementIntersection E t i).mp hi a ha⟩
  calc
    (agreementIntersection E t).card ≤ (Finset.univ \ E a).card :=
      Finset.card_le_card hsub
    _ = n - e := by
      rw [Finset.card_sdiff_of_subset (Finset.subset_univ _),
        Finset.card_univ, Fintype.card_fin, hE a (htS ha)]

omit [Field F] in
private theorem sum_pair_degrees (S : Finset F) (G : Finset (Finset F))
    (hGsub : ∀ t ∈ G, t ⊆ S) (hGcard : ∀ t ∈ G, t.card = 3) :
    ∑ p ∈ S.powersetCard 2, (G.filter fun t ↦ p ⊆ t).card =
      3 * G.card := by
  have hfilter (p : Finset F) : (G.filter fun t ↦ p ⊆ t).card =
    ∑ t ∈ G, (if (p ⊆ t) then (1 : ℕ) else 0) := by
    exact (Finset.sum_boole (R := ℕ) (fun t ↦ p ⊆ t) G).symm
  simp_rw [hfilter]
  rw [Finset.sum_comm]
  calc
    ∑ t ∈ G, ∑ p ∈ S.powersetCard 2,
        (if (p ⊆ t) then (1 : ℕ) else 0) =
        ∑ t ∈ G, (t.powersetCard 2).card := by
      apply Finset.sum_congr rfl
      intro t ht
      rw [Finset.sum_boole (R := ℕ)]
      apply congrArg Finset.card
      ext p
      simp only [Finset.mem_filter, Finset.mem_powersetCard]
      constructor
      · rintro ⟨⟨hpS, hpcard⟩, hpt⟩
        exact ⟨hpt, hpcard⟩
      · rintro ⟨hpt, hpcard⟩
        exact ⟨⟨hpt.trans (hGsub t ht), hpcard⟩, hpt⟩
    _ = ∑ _t ∈ G, 3 := by
      apply Finset.sum_congr rfl
      intro t ht
      simp [hGcard t ht]
    _ = 3 * G.card := by simp [Nat.mul_comm]

private theorem rigid_triple_pair_degree_le {n e m d b : ℕ}
    {C : LinearCode F n} {u v : Word F n}
    (D : DecoderData (e := e) (m := m) C u v) (P : PaddedErrorFamily D)
    (hmin : HasMinimumDistanceAtLeast C d)
    (hsmall : ∀ line : AffineCodewordLine D,
      (line.followingParameters D).card < b)
    (p : Finset F) (hp : p ∈ D.parameters.powersetCard 2)
    (G : Finset (Finset F))
    (hG : ∀ t : Finset F, t ∈ G ↔
      t ∈ D.parameters.powersetCard 3 ∧
        n - d < (agreementIntersection P.error t).card) :
    (G.filter fun t ↦ p ⊆ t).card ≤ b - 3 := by
  let H := G.filter fun t ↦ p ⊆ t
  by_cases hH : H = ∅
  · simp [H, hH]
  · obtain ⟨t₀, ht₀H⟩ := Finset.nonempty_iff_ne_empty.mpr hH
    have ht₀G : t₀ ∈ G := (Finset.mem_filter.mp ht₀H).1
    have hpT₀ : p ⊆ t₀ := (Finset.mem_filter.mp ht₀H).2
    obtain ⟨B₀, ht₀B⟩ := affineCodewordLine_of_large_intersection D P hmin t₀
      (hG t₀ |>.mp ht₀G).1 (hG t₀ |>.mp ht₀G).2
    have hpB₀ : p ⊆ B₀.followingParameters D := hpT₀.trans ht₀B
    have hHB : H ⊆ ((B₀.followingParameters D).powersetCard 3).filter
        (fun t ↦ p ⊆ t) := by
      intro t htH
      have htG : t ∈ G := (Finset.mem_filter.mp htH).1
      have hpT : p ⊆ t := (Finset.mem_filter.mp htH).2
      obtain ⟨Q, htQ⟩ := affineCodewordLine_of_large_intersection D P hmin t
        (hG t |>.mp htG).1 (hG t |>.mp htG).2
      have hpcard : p.card = 2 := (Finset.mem_powersetCard.mp hp).2
      obtain ⟨a, b, hab, hpEq⟩ := Finset.card_eq_two.mp hpcard
      have haP : a ∈ p := by simp [hpEq]
      have hbP : b ∈ p := by simp [hpEq]
      have hBQ : B₀ = Q := B₀.eq_of_two_parameters D Q hab
        (hpB₀ haP) (hpB₀ hbP) (htQ (hpT haP)) (htQ (hpT hbP))
      apply Finset.mem_filter.mpr
      refine ⟨Finset.mem_powersetCard.mpr ⟨?_, ?_⟩, hpT⟩
      · simpa [hBQ] using htQ
      · exact (Finset.mem_powersetCard.mp (hG t |>.mp htG).1).2
    have hcardH := Finset.card_le_card hHB
    have hpcard : p.card = 2 := (Finset.mem_powersetCard.mp hp).2
    have htarget := Finset.card_filter_powersetCard_subset p
      (B₀.followingParameters D) 3 hpB₀
        (by rw [hpcard]; norm_num : p.card ≤ 3)
    rw [htarget] at hcardH
    rw [hpcard] at hcardH
    norm_num at hcardH
    have hBsmall := hsmall B₀
    change H.card ≤ b - 3
    omega

private theorem three_mul_choose_three (m : ℕ) :
    3 * m.choose 3 = m.choose 2 * (m - 2) := by
  have h6 : 6 * m.choose 3 = m * (m - 1) * (m - 2) := by
    calc
      6 * m.choose 3 = Nat.factorial 3 * m.choose 3 := by
        norm_num [Nat.factorial]
      _ = m.descFactorial 3 :=
        (Nat.descFactorial_eq_factorial_mul_choose m 3).symm
      _ = m * (m - 1) * (m - 2) := by
        simp [Nat.descFactorial, mul_assoc, mul_comm]
  have h2 : 2 * m.choose 2 = m * (m - 1) := by
    calc
      2 * m.choose 2 = Nat.factorial 2 * m.choose 2 := by
        norm_num [Nat.factorial]
      _ = m.descFactorial 2 :=
        (Nat.descFactorial_eq_factorial_mul_choose m 2).symm
      _ = m * (m - 1) := by
        simp [Nat.descFactorial, mul_comm]
  have htwice : 2 * (3 * m.choose 3) =
      2 * (m.choose 2 * (m - 2)) := by
    calc
      2 * (3 * m.choose 3) = 6 * m.choose 3 := by ring
      _ = m * (m - 1) * (m - 2) := h6
      _ = (2 * m.choose 2) * (m - 2) := by rw [h2]
      _ = 2 * (m.choose 2 * (m - 2)) := by ring
  omega

/-- Exact extraction of an affine codeword line followed by at least `b`
selected decodings. -/
theorem exists_affineCodewordLine_with_many_followers {n e d m b : ℕ}
    {C : LinearCode F n} {u v : Word F n}
    (D : DecoderData (e := e) (m := m) C u v) (P : PaddedErrorFamily D)
    (hmin : HasMinimumDistanceAtLeast C d)
    (hS : D.parameters.card = m) (hm : 3 ≤ m) (hed : e < d)
    (hA : (((m - 2 : ℕ) : ℚ)) *
        (triple_intersection_mean n e m - (n - d : ℕ)) >
      (b - 3 : ℕ) * (d - e : ℕ)) :
    ∃ line : AffineCodewordLine D,
      b ≤ (line.followingParameters D).card := by
  let S := D.parameters
  have hScard : S.card = m := by simpa [S] using hS
  by_cases hex : ∃ line : AffineCodewordLine D,
      b ≤ (line.followingParameters D).card
  · exact hex
  · push Not at hex
    have hsmall : ∀ line : AffineCodewordLine D,
        (line.followingParameters D).card < b := hex
    let T := S.powersetCard 3
    let good : Finset F → Prop := fun t ↦
      n - d < (agreementIntersection P.error t).card
    let G := T.filter good
    have hG (t : Finset F) : t ∈ G ↔
        t ∈ S.powersetCard 3 ∧
          n - d < (agreementIntersection P.error t).card := by
      simp [G, T, good]
    have hGsub : G ⊆ T := Finset.filter_subset _ _
    have hTcard : T.card = m.choose 3 := by simp [T, hScard]
    have hGmembers (t : Finset F) (ht : t ∈ G) : t ⊆ S :=
      (Finset.mem_powersetCard.mp (hG t |>.mp ht).1).1
    have hGcard3 (t : Finset F) (ht : t ∈ G) : t.card = 3 :=
      (Finset.mem_powersetCard.mp (hG t |>.mp ht).1).2
    have hinterUpper :
        ∑ t ∈ T, (agreementIntersection P.error t).card ≤
          T.card * (n - d) + G.card * (d - e) := by
      calc
        ∑ t ∈ T, (agreementIntersection P.error t).card ≤
            ∑ t ∈ T, ((n - d) + if good t then (d - e) else 0) := by
          apply Finset.sum_le_sum
          intro t htT
          have htdata := Finset.mem_powersetCard.mp htT
          have htNonempty : t.Nonempty := Finset.card_pos.mp (by omega)
          have hbase := agreementIntersection_card_le (e := e) (S := S)
            P.error (fun a ha ↦ P.card_eq ha)
            htdata.1 htNonempty
          by_cases hgood : good t
          · simp only [hgood, if_true]
            dsimp [good] at hgood
            omega
          · simp only [hgood, if_false, add_zero]
            dsimp [good] at hgood
            omega
        _ = T.card * (n - d) + G.card * (d - e) := by
          rw [Finset.sum_add_distrib]
          simp only [Finset.sum_const, nsmul_eq_mul]
          congr 1
          rw [← Finset.sum_filter]
          simp [G, good]
    have hinterLower :
        rounded_choose_three n (m * (n - e)) ≤
          ∑ t ∈ T, (agreementIntersection P.error t).card := by
      simpa [T, S] using triple_intersection_sum_lower D.parameters P.error
        hS (fun a ha ↦ P.card_eq ha)
    have hpairSum := sum_pair_degrees S G hGmembers hGcard3
    have hpairEach (p : Finset F) (hp : p ∈ S.powersetCard 2) :
        (G.filter fun t ↦ p ⊆ t).card ≤ b - 3 := by
      apply rigid_triple_pair_degree_le D P hmin hsmall p
      · simpa [S] using hp
      · intro t
        simpa [S] using hG t
    have hGbound : 3 * G.card ≤ m.choose 2 * (b - 3) := by
      rw [← hpairSum]
      calc
        ∑ p ∈ S.powersetCard 2, (G.filter fun t ↦ p ⊆ t).card ≤
            ∑ _p ∈ S.powersetCard 2, (b - 3) :=
          Finset.sum_le_sum fun p hp ↦ hpairEach p hp
        _ = m.choose 2 * (b - 3) := by simp [hScard]
    have hchoosePos : 0 < m.choose 3 := Nat.choose_pos hm
    have hdePos : 0 < d - e := Nat.sub_pos_of_lt hed
    have hmean : triple_intersection_mean n e m =
        (rounded_choose_three n (m * (n - e)) : ℚ) / m.choose 3 := by
      rfl
    have hinter :
        rounded_choose_three n (m * (n - e)) ≤
          m.choose 3 * (n - d) + G.card * (d - e) := by
      exact hinterLower.trans (hinterUpper.trans_eq (by rw [hTcard]))
    have hthree := three_mul_choose_three m
    have hinterQ :
        (rounded_choose_three n (m * (n - e)) : ℚ) ≤
          ((m.choose 3 * (n - d) + G.card * (d - e) : ℕ) : ℚ) := by
      exact_mod_cast hinter
    have hGboundQ : ((3 * G.card : ℕ) : ℚ) ≤
        ((m.choose 2 * (b - 3) : ℕ) : ℚ) := by
      exact_mod_cast hGbound
    rw [hmean] at hA
    have hchooseQ : (0 : ℚ) < m.choose 3 := by exact_mod_cast hchoosePos
    have hthreeQ : ((3 * m.choose 3 : ℕ) : ℚ) =
        ((m.choose 2 * (m - 2) : ℕ) : ℚ) := by
      exact_mod_cast hthree
    have hdeQ : (0 : ℚ) < (d - e : ℕ) := by exact_mod_cast hdePos
    have hm2 : 0 < m - 2 := by omega
    have hm2Q : (0 : ℚ) < (m - 2 : ℕ) := by exact_mod_cast hm2
    field_simp [ne_of_gt hchooseQ] at hA
    push_cast at hA hinterQ hGboundQ hthreeQ hdeQ hm2Q
    have hLdiff :
        (rounded_choose_three n (m * (n - e)) : ℚ) -
          (m.choose 3 : ℕ) * (n - d : ℕ) ≤
            (G.card : ℕ) * (d - e : ℕ) := by
      linarith
    have hscaled := mul_le_mul_of_nonneg_left hLdiff (le_of_lt hm2Q)
    have hcancelled :
        ((b - 3 : ℕ) : ℚ) * (m.choose 3 : ℕ) <
          ((m - 2 : ℕ) : ℚ) * (G.card : ℕ) := by
      have hprod :
          (((b - 3 : ℕ) : ℚ) * (m.choose 3 : ℕ)) * (d - e : ℕ) <
            (((m - 2 : ℕ) : ℚ) * (G.card : ℕ)) * (d - e : ℕ) := by
        calc
        (((b - 3 : ℕ) : ℚ) * (m.choose 3 : ℕ)) * (d - e : ℕ) =
            ((b - 3 : ℕ) : ℚ) * (d - e : ℕ) * (m.choose 3 : ℕ) := by ring
        _ < ((m - 2 : ℕ) : ℚ) *
            ((rounded_choose_three n (m * (n - e)) : ℚ) -
              (m.choose 3 : ℕ) * (n - d : ℕ)) := hA
        _ ≤ ((m - 2 : ℕ) : ℚ) *
            ((G.card : ℕ) * (d - e : ℕ)) := hscaled
        _ = (((m - 2 : ℕ) : ℚ) * (G.card : ℕ)) *
            (d - e : ℕ) := by ring
      nlinarith
    have hleft := mul_lt_mul_of_pos_left hcancelled (show (0 : ℚ) < 3 by norm_num)
    have hright := mul_le_mul_of_nonneg_left hGboundQ (le_of_lt hm2Q)
    nlinarith

end Internal

end CorrelatedAgreement
