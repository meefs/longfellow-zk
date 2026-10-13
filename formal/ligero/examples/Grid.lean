import Mathlib.Data.Nat.Basic








namespace Examples

structure GridPoint where
  n : ℕ
  k : ℕ
  d : ℕ
  e : ℕ
  fieldBits : ℕ
  targetBits : ℕ
  deriving DecidableEq

end Examples
