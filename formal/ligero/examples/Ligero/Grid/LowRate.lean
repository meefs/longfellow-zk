import examples.Ligero.Grid.Tight

/-! # Low-rate opening-count certificates

The canonical grid of `Ligero.Examples.Grid.Data` covers nominal rates `1/7` and `1/15`, chosen
because those are the rates at which a large instance is cheap for the prover.  Small instances
invert that preference: below a few hundred witness elements the transcript is dominated by the
Merkle multiproof and the transmitted test rows, both of which shrink with the opening count, while
the codeword is short enough that a very low rate costs the prover almost nothing.  A `1/1024`
codeword at `k = 99` is `101376` field elements — under two megabytes.

This layer therefore certifies three further rates, `1/64`, `1/256` and `1/1024`, at
`GF(2 ^ 128)` and a `120`-bit target.  Message lengths are chosen so that `k = θ + w` leaves a
payload width `w` able to carry five hundred witness elements in fourteen or fifteen rows, which is
the geometry a small zero-knowledge instance actually wants.

Two things the numbers show.

* **Openings fall by a third.** `θ` goes `89 → 61 → 45 → 37` as the rate goes `1/15 → 1/1024`.
  Rate is the productive axis at this scale, which is the opposite of the large-instance case, where
  the opening count is nearly flat in `n` and it is the *block length* axis that needs extending.

* **The lift list grows.** `listBound` goes `8 → 10 → 12 → 18` along the same sequence, because the
  admissible radius rises with the rate and the interleaved Johnson denominator shrinks.  For a
  single non-recursive layer the list size is harmless — it enters the error additively, as
  `listBound / |F|`, and `18 / 2 ^ 128` is not a term anyone notices.  For a *recursive* chain it is
  the opposite: composition charges one factor of the list size per layer, so a depth-`k` chain pays
  `k log₂ listBound` bits.  The rows below are calibrated for the single-layer case, and a chain
  wanting these rates should re-tighten at a smaller radius to buy the list size back.

Each row records `θ` and the tightness witness `θ - 1`, so the opening counts are minimal for the
stated parameters rather than merely sufficient.  Every row also satisfies
`MaskingRateCondition θ (k - θ)`, i.e. `k ≥ 2θ`: without it the layer has a fine proximity bound and
no simulator.
-/

namespace Ligero.Examples.Grid.LowRate

open LigeroFamily Ligero.Examples.Grid

set_option maxHeartbeats 10000000

private def certificate (n k d e g m fieldBits targetBits openings : ℕ) : Certificate :=
  { n := n, k := k, d := d, e := e, g := g, m := m
    fieldBits := fieldBits, targetBits := targetBits, openings := openings }

end Ligero.Examples.Grid.LowRate
