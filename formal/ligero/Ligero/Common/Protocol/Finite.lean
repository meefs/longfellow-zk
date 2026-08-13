import CodingTheory.Proximity
import Mathlib.Data.Finset.Powerset

/-!
# Finite combinatorics used by Ligero.Common

This module keeps query-set and affine-equation counting independent of the
rest of the protocol development.
-/

namespace Ligero.Common

/-- Uniform query space of `r`-subsets of the `n` committed positions. -/
abbrev QuerySet (n r : ℕ) :=
  ↥((Finset.univ : Finset (Fin n)).powersetCard r)

namespace QuerySet

def coordinates {n r : ℕ} (query : QuerySet n r) : Finset (Fin n) :=
  query.1

@[simp] theorem card_coordinates {n r : ℕ} (query : QuerySet n r) :
    query.coordinates.card = r :=
  (Finset.mem_powersetCard.mp query.2).2

@[simp] theorem fintype_card (n r : ℕ) :
    Fintype.card (QuerySet n r) = n.choose r := by
  rw [Fintype.card_coe]
  simp

/-- A size-`r` query exists whenever `r ≤ n`. -/
theorem nonempty {n r : ℕ} (hr : r ≤ n) : Nonempty (QuerySet n r) := by
  have hsets :
      ((Finset.univ : Finset (Fin n)).powersetCard r).Nonempty := by
    rw [Finset.powersetCard_nonempty]
    simpa using hr
  rcases hsets with ⟨query, hquery⟩
  exact ⟨⟨query, hquery⟩⟩

end QuerySet

noncomputable def queriesWithin {n r : ℕ} (allowed : Finset (Fin n)) :
    Finset (QuerySet n r) :=
  Finset.univ.filter fun query ↦ query.coordinates ⊆ allowed

theorem card_queriesWithin {n r : ℕ} (allowed : Finset (Fin n)) :
    (queriesWithin (r := r) allowed).card = allowed.card.choose r := by
  classical
  rw [← Finset.card_powersetCard]
  apply Finset.card_bij (fun query _ ↦ query.coordinates)
  · intro query hquery
    exact Finset.mem_powersetCard.mpr
      ⟨(Finset.mem_filter.mp hquery).2, QuerySet.card_coordinates query⟩
  · intro first _ second _ hequal
    exact Subtype.ext hequal
  · intro coordinates hcoordinates
    have hglobal : coordinates ∈
        (Finset.univ : Finset (Fin n)).powersetCard r :=
      Finset.mem_powersetCard.mpr
        ⟨Finset.subset_univ _, (Finset.mem_powersetCard.mp hcoordinates).2⟩
    let query : QuerySet n r := ⟨coordinates, hglobal⟩
    refine ⟨query, ?_, rfl⟩
    exact Finset.mem_filter.mpr
      ⟨Finset.mem_univ _, (Finset.mem_powersetCard.mp hcoordinates).1⟩

theorem card_queriesWithin_le {n r bound : ℕ}
    (allowed : Finset (Fin n)) (hcard : allowed.card ≤ bound) :
    (queriesWithin (r := r) allowed).card ≤ bound.choose r := by
  rw [card_queriesWithin]
  exact Nat.choose_le_choose r hcard

/-- Dot product over a finite index type. -/
def finiteDot {F Index : Type*} [Semiring F] [Fintype Index]
    (left right : Index → F) : F :=
  ∑ i, left i * right i

def affineEquationSolutions
    {F Index : Type*} [Field F] [Fintype F] [Fintype Index]
    [DecidableEq F] [DecidableEq Index]
    (coefficients : Index → F) (target : F) : Finset (Index → F) :=
  Finset.univ.filter fun weights ↦ finiteDot weights coefficients = target

/-- A nontrivial affine equation occupies at most one field fraction of its
challenge space. -/
theorem card_affineEquationSolutions_le
    {F Index : Type*} [Field F] [Fintype F] [Fintype Index]
    [DecidableEq F] [DecidableEq Index]
    (coefficients : Index → F) (target : F) (hnonzero : coefficients ≠ 0) :
    (affineEquationSolutions coefficients target).card ≤
      Fintype.card F ^ (Fintype.card Index - 1) := by
  classical
  obtain ⟨pivot, hpivot⟩ : ∃ i, coefficients i ≠ 0 := by
    simpa [Function.ne_iff] using hnonzero
  let Other := { i : Index // i ≠ pivot }
  let Solutions := ↥(affineEquationSolutions coefficients target)
  let restrict : Solutions → Other → F := fun weights i ↦ weights.1 i.1
  have hinjective : Function.Injective restrict := by
    intro first second hequal
    apply Subtype.ext
    funext i
    by_cases hi : i = pivot
    · subst i
      have hfirst : finiteDot first.1 coefficients = target :=
        (Finset.mem_filter.mp first.2).2
      have hsecond : finiteDot second.1 coefficients = target :=
        (Finset.mem_filter.mp second.2).2
      have hother : ∀ j, j ≠ pivot → first.1 j = second.1 j := by
        intro j hj
        exact congrFun hequal ⟨j, hj⟩
      have hpivotProduct :
          (first.1 pivot - second.1 pivot) * coefficients pivot = 0 := by
        calc
          _ = ∑ j, (first.1 j - second.1 j) * coefficients j := by
            symm
            calc
              _ = (first.1 pivot - second.1 pivot) * coefficients pivot +
                    ∑ j ∈ (Finset.univ : Finset Index).erase pivot,
                      (first.1 j - second.1 j) * coefficients j :=
                ((Finset.univ : Finset Index).add_sum_erase
                  (fun j ↦ (first.1 j - second.1 j) * coefficients j)
                  (Finset.mem_univ pivot)).symm
              _ = _ := by
                rw [Finset.sum_eq_zero]
                · simp
                · intro j hj
                  simp [hother j (Finset.mem_erase.mp hj).1]
          _ = finiteDot first.1 coefficients -
              finiteDot second.1 coefficients := by
            simp only [finiteDot, sub_mul, Finset.sum_sub_distrib]
          _ = 0 := by rw [hfirst, hsecond, sub_self]
      exact sub_eq_zero.mp
        ((mul_eq_zero.mp hpivotProduct).resolve_right hpivot)
    · exact congrFun hequal ⟨i, hi⟩
  calc
    (affineEquationSolutions coefficients target).card =
        Fintype.card Solutions := by simp [Solutions]
    _ ≤ Fintype.card (Other → F) :=
      Fintype.card_le_of_injective restrict hinjective
    _ = Fintype.card F ^ (Fintype.card Index - 1) := by
      simp [Other, Fintype.card_subtype_compl]

/-- Denominator-cleared `1/|F|` density bound. -/
theorem affineEquationSolutions_density
    {F Index : Type*} [Field F] [Fintype F] [Fintype Index]
    [DecidableEq F] [DecidableEq Index]
    (coefficients : Index → F) (target : F) (hnonzero : coefficients ≠ 0) :
    Fintype.card F * (affineEquationSolutions coefficients target).card ≤
      Fintype.card (Index → F) := by
  obtain ⟨pivot, hpivot⟩ : ∃ i, coefficients i ≠ 0 := by
    simpa [Function.ne_iff] using hnonzero
  letI : Nonempty Index := ⟨pivot⟩
  calc
    Fintype.card F * (affineEquationSolutions coefficients target).card ≤
        Fintype.card F * Fintype.card F ^ (Fintype.card Index - 1) :=
      Nat.mul_le_mul_left _
        (card_affineEquationSolutions_le coefficients target hnonzero)
    _ = Fintype.card F ^ Fintype.card Index := by
      rw [← pow_succ']
      congr
      exact Nat.sub_add_cancel (Fintype.card_pos : 1 ≤ Fintype.card Index)
    _ = Fintype.card (Index → F) := by simp

end Ligero.Common
