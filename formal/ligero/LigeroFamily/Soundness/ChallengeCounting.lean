import LigeroFamily.Protocol.MaskScheme

/-!
# Scheme-challenge coordinate counting

Lifts density bounds on a linear or quadratic challenge coordinate to the
complete simultaneous scheme challenge. This bookkeeping is shared by both
mask representations.
-/

namespace LigeroFamily.SchemeInternal

variable {F Equations CheckedMask : Type*}
variable [Fintype F] [Fintype Equations] [Fintype CheckedMask]
variable {nw nq : ℕ}

abbrev ProximityCoins := SchemeTestedRow CheckedMask nw nq 1 → F
abbrev LinearCoins := Equations → F
abbrev QuadraticCoins := Fin nq → F

noncomputable local instance testedRowFintype :
    Fintype (SchemeTestedRow CheckedMask nw nq 1) := by
  classical
  exact instFintypeSum _ _

noncomputable local instance proximityCoinsFintype :
    Fintype (ProximityCoins (F := F) (CheckedMask := CheckedMask)
      (nw := nw) (nq := nq)) := by
  classical
  exact Pi.instFintype

noncomputable local instance linearCoinsFintype :
    Fintype (LinearCoins (F := F) (Equations := Equations)) := by
  classical
  exact Pi.instFintype

noncomputable local instance quadraticCoinsFintype :
    Fintype (QuadraticCoins (F := F) (nq := nq)) := Pi.instFintype

theorem card_challenge :
    Nat.card (SchemeChallenge F CheckedMask nw nq 1 Equations) =
      Nat.card (ProximityCoins (F := F) (CheckedMask := CheckedMask)
        (nw := nw) (nq := nq)) *
      Nat.card (LinearCoins (F := F) (Equations := Equations)) *
      Nat.card (QuadraticCoins (F := F) (nq := nq)) := by
  calc
    Nat.card (SchemeChallenge F CheckedMask nw nq 1 Equations) =
        Nat.card (SchemeRoundChallenge F CheckedMask nw nq 1 Equations) := by
      change Nat.card
        (Fin 1 → SchemeRoundChallenge F CheckedMask nw nq 1 Equations) = _
      exact Nat.card_congr
        (Equiv.funUnique (Fin 1)
          (SchemeRoundChallenge F CheckedMask nw nq 1 Equations))
    _ = Nat.card
        ((SchemeTestedRow CheckedMask nw nq 1 → F) ×
          (Equations → F) × (Fin nq → F)) :=
      Nat.card_congr
        (schemeRoundChallengeEquiv F CheckedMask Equations nw nq 1)
    _ = _ := by simp [ProximityCoins, LinearCoins,
      QuadraticCoins, Nat.mul_assoc]

noncomputable def liftLinear [DecidableEq F] [DecidableEq Equations]
    [DecidableEq CheckedMask]
    (special : Finset (LinearCoins (F := F) (Equations := Equations))) :
    Finset (SchemeChallenge F CheckedMask nw nq 1 Equations) := by
  classical
  exact Finset.univ.filter fun challenge ↦ (challenge 0).linear ∈ special

noncomputable def liftQuadratic [DecidableEq F] [DecidableEq Equations]
    [DecidableEq CheckedMask]
    (special : Finset (QuadraticCoins (F := F) (nq := nq))) :
    Finset (SchemeChallenge F CheckedMask nw nq 1 Equations) := by
  classical
  exact Finset.univ.filter fun challenge ↦ (challenge 0).quadratic ∈ special

theorem card_liftLinear [DecidableEq F] [DecidableEq Equations]
    [DecidableEq CheckedMask]
    (special : Finset (LinearCoins (F := F) (Equations := Equations))) :
    (liftLinear (CheckedMask := CheckedMask) (nw := nw) (nq := nq)
      special).card =
      Nat.card (ProximityCoins (F := F) (CheckedMask := CheckedMask)
        (nw := nw) (nq := nq)) * special.card *
      Nat.card (QuadraticCoins (F := F) (nq := nq)) := by
  classical
  let target :=
    (Finset.univ : Finset (ProximityCoins (F := F) (CheckedMask := CheckedMask)
      (nw := nw) (nq := nq))) ×ˢ
      (special ×ˢ (Finset.univ : Finset (QuadraticCoins (F := F) (nq := nq))))
  calc
    (liftLinear (CheckedMask := CheckedMask) (nw := nw) (nq := nq)
      special).card = target.card := by
      apply Finset.card_bij (fun challenge _ ↦
        ((challenge 0).proximity, (challenge 0).linear,
          (challenge 0).quadratic))
      · intro challenge hchallenge
        simpa [target, liftLinear] using (Finset.mem_filter.mp hchallenge).2
      · intro first _ second _ hequal
        funext h
        rw [Subsingleton.elim h 0]
        exact (schemeRoundChallengeEquiv F CheckedMask Equations nw nq 1).injective
          hequal
      · intro value hvalue
        refine ⟨fun _ ↦ ⟨value.1, value.2.1, value.2.2⟩, ?_, rfl⟩
        exact Finset.mem_filter.mpr
          ⟨Finset.mem_univ _, by simpa [target] using hvalue⟩
    _ = _ := by simp [target, Nat.card_eq_fintype_card, Nat.mul_assoc]

theorem card_liftQuadratic [DecidableEq F] [DecidableEq Equations]
    [DecidableEq CheckedMask]
    (special : Finset (QuadraticCoins (F := F) (nq := nq))) :
    (liftQuadratic (CheckedMask := CheckedMask) (Equations := Equations)
      (nw := nw) special).card =
      Nat.card (ProximityCoins (F := F) (CheckedMask := CheckedMask)
        (nw := nw) (nq := nq)) *
      Nat.card (LinearCoins (F := F) (Equations := Equations)) *
      special.card := by
  classical
  let target :=
    (Finset.univ : Finset (ProximityCoins (F := F) (CheckedMask := CheckedMask)
      (nw := nw) (nq := nq))) ×ˢ
      ((Finset.univ : Finset (LinearCoins (F := F) (Equations := Equations))) ×ˢ
        special)
  calc
    (liftQuadratic (CheckedMask := CheckedMask) (Equations := Equations)
      (nw := nw) special).card = target.card := by
      apply Finset.card_bij (fun challenge _ ↦
        ((challenge 0).proximity, (challenge 0).linear,
          (challenge 0).quadratic))
      · intro challenge hchallenge
        simpa [target, liftQuadratic] using
          (Finset.mem_filter.mp hchallenge).2
      · intro first _ second _ hequal
        funext h
        rw [Subsingleton.elim h 0]
        exact (schemeRoundChallengeEquiv F CheckedMask Equations nw nq 1).injective
          hequal
      · intro value hvalue
        refine ⟨fun _ ↦ ⟨value.1, value.2.1, value.2.2⟩, ?_, rfl⟩
        exact Finset.mem_filter.mpr
          ⟨Finset.mem_univ _, by simpa [target] using hvalue⟩
    _ = _ := by simp [target, Nat.card_eq_fintype_card, Nat.mul_assoc]

theorem liftLinear_density [DecidableEq F] [DecidableEq Equations]
    [DecidableEq CheckedMask]
    (q B : ℕ)
    (special : Finset (LinearCoins (F := F) (Equations := Equations)))
    (hspecial : q * special.card ≤
      B * Nat.card (LinearCoins (F := F) (Equations := Equations))) :
    q * (liftLinear (CheckedMask := CheckedMask) (nw := nw) (nq := nq)
        special).card ≤
      B * Nat.card (SchemeChallenge F CheckedMask nw nq 1 Equations) := by
  rw [card_liftLinear, card_challenge]
  calc
    q * (Nat.card (ProximityCoins (F := F) (CheckedMask := CheckedMask)
          (nw := nw) (nq := nq)) * special.card *
        Nat.card (QuadraticCoins (F := F) (nq := nq))) =
      Nat.card (ProximityCoins (F := F) (CheckedMask := CheckedMask)
          (nw := nw) (nq := nq)) * (q * special.card) *
        Nat.card (QuadraticCoins (F := F) (nq := nq)) := by ring
    _ ≤ Nat.card (ProximityCoins (F := F) (CheckedMask := CheckedMask)
          (nw := nw) (nq := nq)) *
        (B * Nat.card (LinearCoins (F := F) (Equations := Equations))) *
          Nat.card (QuadraticCoins (F := F) (nq := nq)) := by gcongr
    _ = B * (Nat.card (ProximityCoins (F := F)
          (CheckedMask := CheckedMask) (nw := nw) (nq := nq)) *
        Nat.card (LinearCoins (F := F) (Equations := Equations)) *
          Nat.card (QuadraticCoins (F := F) (nq := nq))) := by ring

theorem liftQuadratic_density [DecidableEq F] [DecidableEq Equations]
    [DecidableEq CheckedMask]
    (q B : ℕ)
    (special : Finset (QuadraticCoins (F := F) (nq := nq)))
    (hspecial : q * special.card ≤
      B * Nat.card (QuadraticCoins (F := F) (nq := nq))) :
    q * (liftQuadratic (CheckedMask := CheckedMask) (Equations := Equations)
        (nw := nw) special).card ≤
      B * Nat.card (SchemeChallenge F CheckedMask nw nq 1 Equations) := by
  rw [card_liftQuadratic, card_challenge]
  calc
    q * (Nat.card (ProximityCoins (F := F) (CheckedMask := CheckedMask)
          (nw := nw) (nq := nq)) *
        Nat.card (LinearCoins (F := F) (Equations := Equations)) * special.card) =
      Nat.card (ProximityCoins (F := F) (CheckedMask := CheckedMask)
          (nw := nw) (nq := nq)) *
        Nat.card (LinearCoins (F := F) (Equations := Equations)) *
          (q * special.card) := by ring
    _ ≤ Nat.card (ProximityCoins (F := F) (CheckedMask := CheckedMask)
          (nw := nw) (nq := nq)) *
        Nat.card (LinearCoins (F := F) (Equations := Equations)) *
          (B * Nat.card (QuadraticCoins (F := F) (nq := nq))) := by gcongr
    _ = B * (Nat.card (ProximityCoins (F := F)
          (CheckedMask := CheckedMask) (nw := nw) (nq := nq)) *
        Nat.card (LinearCoins (F := F) (Equations := Equations)) *
          Nat.card (QuadraticCoins (F := F) (nq := nq))) := by ring

end LigeroFamily.SchemeInternal
