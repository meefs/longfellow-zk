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

end Bcs
