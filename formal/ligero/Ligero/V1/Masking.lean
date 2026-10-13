import LigeroFamily.Protocol.MaskScheme

/-! # Ligero V1 masking

V1 commits one linear and one quadratic response-code mask outside the
proximity-tested matrix.  The generic scheme machinery lives in
`LigeroFamily`; this concrete masking choice belongs to the Ligero V1 child.
-/

namespace Ligero.V1

open LigeroFamily

/-- The two direct response masks committed by V1. -/
inductive Mask
  | linear
  | quadratic
  deriving DecidableEq, Fintype

abbrev Scheme (F : Type*) (r w n : ℕ) :=
  MaskScheme F NoMask Mask r w n

/-- V1's direct, unchecked response-code masking scheme. -/
def scheme {F : Type*} [Field F] {r w n : ℕ} : Scheme F r w n where
  linearAt _ _ mask := mask .linear
  quadraticAt _ _ mask := mask .quadratic

abbrev Oracle (F : Type*) (nw nq n repetitions : ℕ) :=
  SchemeOracle F NoMask Mask nw nq n repetitions

abbrev Challenge (F : Type*) (nw nq repetitions : ℕ) (Equations : Type*) :=
  SchemeChallenge F NoMask nw nq repetitions Equations

abbrev Opening (F : Type*) (nw nq repetitions n r : ℕ)
    (query : QuerySet n r) :=
  SchemeOpening F NoMask Mask nw nq repetitions n r query

end Ligero.V1
