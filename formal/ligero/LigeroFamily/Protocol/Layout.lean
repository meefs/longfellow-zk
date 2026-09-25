import LigeroFamily.Protocol.MaskScheme









namespace LigeroFamily

/-- Embed the positions visible to a constraint system into the witness suffix
of an encoded row. `extend` is the corresponding public coefficient-vector
linear extension. No constraint can name a witness position outside `logical`.-/
structure ConstraintLayout (F : Type*) [Semiring F] (q w : ℕ) where
  logical : Fin q ↪ Fin w
  extend : (Fin q → F) →ₗ[F] (Fin w → F)
  extend_logical : ∀ values i, extend values (logical i) = values i

namespace ConstraintLayout

variable {F : Type*} [Semiring F]



def identity (w : ℕ) : ConstraintLayout F w w where
  logical := Function.Embedding.refl _
  extend := LinearMap.id
  extend_logical := by simp



def logicalPrefix (q q' : ℕ) : ConstraintLayout F q (q + q') where
  logical := ⟨Fin.castAdd q', Fin.castAdd_injective q q'⟩
  extend :=
    { toFun := fun values => Fin.addCases values (fun _ => 0)
      map_add' := by
        intro x y
        funext i
        refine Fin.addCases (fun j => ?_) (fun j => ?_) i <;> simp
      map_smul' := by
        intro a x
        funext i
        refine Fin.addCases (fun j => ?_) (fun j => ?_) i <;> simp }
  extend_logical := by
    intro values i
    simp

end ConstraintLayout

def logicalWitnessPosition {F : Type*} [Semiring F] {q r w n : ℕ}
    (layout : ConstraintLayout F q w) (i : Fin q) : Position r w n :=
  witnessPosition (layout.logical i)

def logicalValues {F : Type*} [Semiring F] {q r w n : ℕ}
    (layout : ConstraintLayout F q w) (row : EvaluationRow F r w n) :
    Fin q → F :=
  fun i => row (logicalWitnessPosition layout i)

@[simp] theorem logicalValues_apply {F : Type*} [Semiring F] {q r w n : ℕ}
    (layout : ConstraintLayout F q w) (row : EvaluationRow F r w n)
    (i : Fin q) :
    logicalValues layout row i = row (logicalWitnessPosition layout i) := rfl

/-- Decode precisely the values visible to the constraint system. -/
def layoutCoreMessages {F : Type*} [Semiring F] {q r w n nw nq : ℕ}
    (layout : ConstraintLayout F q w)
    (core : (block : CoreBlock) → Fin (block.rowCount nw nq) →
      EvaluationRow F r w n) : CoreMessages F nw nq q :=
  fun block row => logicalValues layout (core block row)

/-- The linear functional that sums exactly the constraint-visible witness
coordinates and ignores every extension coordinate. -/
def logicalSumLinearMap {F : Type*} [Field F] {q w : ℕ}
    (layout : ConstraintLayout F q w) : (Fin w → F) →ₗ[F] F where
  toFun values := ∑ i : Fin q, values (layout.logical i)
  map_add' left right := by simp [Finset.sum_add_distrib]
  map_smul' scalar values := by simp [Finset.mul_sum]

end LigeroFamily
