import examples.Ligero

/-! Compile-time checks at all four corners of the generated grid. -/

open Ligero.Examples.Grid.Generated

#check N1024_R7_V1_F128_S120_conditions
#check N1024_R7_V1_F128_S120_soundness_le_envelope
#check N1024_R7_V1_F128_S120_minimum
#check N8192_R15_V1_F128_S125_minimum
