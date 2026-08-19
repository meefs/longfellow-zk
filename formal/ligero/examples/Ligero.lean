import examples.Ligero.Grid.All

/-!
# Exhaustive Ligero opening-count examples

Kernel-checked selected-MCA certificates for the complete requested grid,
including the exact-profile optimized results in `Grid.Tight`. The
parameter-generic protocol and end-to-end theorems remain in `Ligero.API`.

`Grid.LowRate` adds nominal rates `1/64`, `1/256` and `1/1024`, which are the rates a *small*
instance wants: the opening count falls by a third against `1/15`, and the codeword stays short
enough that the prover does not notice.
-/
