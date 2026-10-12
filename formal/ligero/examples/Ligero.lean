import examples.Ligero.Grid.All

/-!
# Exhaustive Ligero opening-count examples

Kernel-checked selected-MCA certificates for the complete requested grid,
including the exact-profile optimized results in `Grid.Tight`. The
parameter-generic protocol and end-to-end theorems remain in `Ligero.API`.

`Grid.Rigid` adds the 195-point response-rigid Fiat--Shamir compiler grid.
Its exact arithmetic and CA premises are kernel-checked, together with the
generic repaired ROM compiler, selection-safe alpha-last lemma, valid-response
adapter, and prefix-fixed Merkle binding theorem.  Concrete transcript
serialization still supplies the compiler's first-occurrence attribution
interface rather than being conflated with the interactive guarantees.

`Grid.LowRate` adds nominal rates `1/64`, `1/256` and `1/1024`, which are the rates a *small*
instance wants: the opening count falls by a third against `1/15`, and the codeword stays short
enough that the prover does not notice.
-/
