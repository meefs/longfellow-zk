import Mathlib.Algebra.BigOperators.Ring.Finset
import Mathlib.Algebra.Order.BigOperators.Ring.Finset
import Mathlib.Data.Fintype.BigOperators
import Mathlib.Data.Fintype.Prod
import Mathlib.Data.Rat.Cast.Order

/-!
# Slicing a product sample space

The compiled experiment's sample space is `(Fin T → D) × (Challenge × Query)`: the hash tape, then
the verifier's external coins.  The two error terms are counted along the two different slicings —
`Merkle`'s bound is per coin pair, over tapes; the IOP's is per tape, over coins — so both are
needed, and they are the same lemma up to `Finset.sum_comm`.
-/

set_option autoImplicit false
set_option relaxedAutoImplicit false

namespace Bcs

open Finset

/-- Count a product event by slicing on the first coordinate.

Stated with the predicate applied to a *pair* rather than curried, so that `rw` unifies it
first-order against a filter that is already there. -/
theorem card_filter_prod_fst {α β : Type*} [Fintype α] [Fintype β]
    (P : α × β → Prop) [DecidablePred P] :
    (univ.filter P).card = ∑ a : α, (univ.filter fun b ↦ P (a, b)).card := by
  simp only [Finset.card_filter, Fintype.sum_prod_type]

/-- Count a product event by slicing on the second coordinate. -/
theorem card_filter_prod_snd {α β : Type*} [Fintype α] [Fintype β]
    (P : α × β → Prop) [DecidablePred P] :
    (univ.filter P).card = ∑ b : β, (univ.filter fun a ↦ P (a, b)).card := by
  simp only [Finset.card_filter, Fintype.sum_prod_type]
  exact Finset.sum_comm

/-- A uniform probability bound on every second-coordinate fiber remains
valid after adjoining an independent first coordinate. -/
theorem product_ratio_le_of_fst_fiber
    {α β : Type*} [Fintype α] [Fintype β] [Nonempty α] [Nonempty β]
    (event : α → β → Prop) [∀ a, DecidablePred (event a)]
    (epsilon : ℚ)
    (hfiber : ∀ a, ((univ.filter (event a)).card : ℚ) /
      Fintype.card β ≤ epsilon) :
    ((univ.filter fun value : α × β ↦ event value.1 value.2).card : ℚ) /
        Fintype.card (α × β) ≤ epsilon := by
  classical
  have hα : (0 : ℚ) < Fintype.card α := by
    exact_mod_cast Fintype.card_pos
  have hβ : (0 : ℚ) < Fintype.card β := by
    exact_mod_cast Fintype.card_pos
  rw [card_filter_prod_fst, Fintype.card_prod]
  push_cast
  rw [div_le_iff₀ (mul_pos hα hβ)]
  calc
    (∑ a : α, ((univ.filter (event a)).card : ℚ))
        ≤ ∑ _a : α, epsilon * Fintype.card β := by
          apply Finset.sum_le_sum
          intro a _
          exact (div_le_iff₀ hβ).mp (hfiber a)
    _ = epsilon * (Fintype.card α * Fintype.card β) := by
      simp
      ring

/-- Symmetric product-space averaging, slicing on the second coordinate. -/
theorem product_ratio_le_of_snd_fiber
    {α β : Type*} [Fintype α] [Fintype β] [Nonempty α] [Nonempty β]
    (event : α → β → Prop) [∀ b, DecidablePred (fun a ↦ event a b)]
    (epsilon : ℚ)
    (hfiber : ∀ b, ((univ.filter fun a ↦ event a b).card : ℚ) /
      Fintype.card α ≤ epsilon) :
    ((univ.filter fun value : α × β ↦ event value.1 value.2).card : ℚ) /
        Fintype.card (α × β) ≤ epsilon := by
  classical
  have hα : (0 : ℚ) < Fintype.card α := by
    exact_mod_cast Fintype.card_pos
  have hβ : (0 : ℚ) < Fintype.card β := by
    exact_mod_cast Fintype.card_pos
  rw [card_filter_prod_snd, Fintype.card_prod]
  push_cast
  rw [div_le_iff₀ (mul_pos hα hβ)]
  calc
    (∑ b : β, ((univ.filter fun a : α ↦ event a b).card : ℚ))
        ≤ ∑ _b : β, epsilon * Fintype.card α := by
          apply Finset.sum_le_sum
          intro b _
          exact (div_le_iff₀ hα).mp (hfiber b)
    _ = epsilon * (Fintype.card α * Fintype.card β) := by
      simp
      ring

end Bcs
