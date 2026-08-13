import Mathlib.Data.Fintype.BigOperators
import Mathlib.Data.Fintype.Prod

/-! # Mask-independent finite product counting -/

namespace Ligero.Common.Internal

theorem card_filter_product_eq_sum
    {First Second : Type*} [Fintype First] [DecidableEq First]
    [Fintype Second] [DecidableEq Second]
    (accepts : First → Second → Prop) [DecidableRel accepts] :
    (Finset.univ.filter fun pair : First × Second ↦
      accepts pair.1 pair.2).card =
      ∑ a, (Finset.univ.filter fun b ↦ accepts a b).card := by
  classical
  let source := Finset.univ.filter fun pair : First × Second ↦
    accepts pair.1 pair.2
  let fiber := fun a ↦ Finset.univ.filter fun b ↦ accepts a b
  let pairSubtype := ↑source
  let fiberSigma := (a : First) × ↑(fiber a)
  let equivalence : pairSubtype ≃ fiberSigma :=
    { toFun := fun pair ↦ ⟨pair.1.1, ⟨pair.1.2, by
          exact Finset.mem_filter.mpr
            ⟨Finset.mem_univ _, (Finset.mem_filter.mp pair.2).2⟩⟩⟩
      invFun := fun value ↦ ⟨(value.1, value.2.1), by
          exact Finset.mem_filter.mpr
            ⟨Finset.mem_univ _, (Finset.mem_filter.mp value.2.2).2⟩⟩
      left_inv := fun _ ↦ rfl
      right_inv := fun _ ↦ rfl }
  calc
    source.card = Fintype.card pairSubtype := by simp [pairSubtype]
    _ = Fintype.card fiberSigma := Fintype.card_congr equivalence
    _ = ∑ a, Fintype.card ↥(fiber a) := Fintype.card_sigma
    _ = ∑ a, (fiber a).card := by simp

end Ligero.Common.Internal
