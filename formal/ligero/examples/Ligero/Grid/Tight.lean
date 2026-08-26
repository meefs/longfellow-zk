import examples.Ligero.Grid.Data

/-! # Tight exact-profile opening-count grid

This layer reports minima for the exact profiled soundness expressions and
changes selected-MCA parameters where exhaustive optimization over the
admissible residual size finds a smaller opening count.
-/

namespace Ligero.Examples.Grid.Tight

open LigeroFamily

set_option maxHeartbeats 10000000

structure V1Result where
  certificate : Ligero.Examples.Grid.V1Certificate
  g? : Option ℕ := none
  m? : Option ℕ := none
  cutoff? : Option ℕ := none
  localM? : Option ℕ := none
  openings : ℕ

def V1Result.point (result : V1Result) : Examples.GridPoint :=
  result.certificate.point

/-- The protocol certificate represented by a tightened V1 grid row. -/
def V1Result.tightCertificate (result : V1Result) :
    Ligero.Examples.Grid.V1Certificate :=
  { result.certificate with
      g := result.g?.getD result.certificate.g
      m := result.m?.getD result.certificate.m
      cutoff := result.cutoff?.getD 0
      localM := result.localM?.getD 0
      openings := result.openings }


def V1Result.bound (result : V1Result) : ℕ → ℚ :=
  result.tightCertificate.compressedV1Soundness

theorem V1Result.bound_eq_soundness (result : V1Result) (queries : ℕ) :
    result.bound queries = result.tightCertificate.v1Soundness queries :=
  result.tightCertificate.compressedV1Soundness_eq queries

def V1Result.Valid (result : V1Result) : Prop :=
  SelectedMCA.DirectCliqueCondition result.tightCertificate.n
      result.tightCertificate.e result.tightCertificate.g
      result.tightCertificate.d result.tightCertificate.m ∧
    ¬SelectedMCA.DirectCliqueCondition result.tightCertificate.n
      result.tightCertificate.e result.tightCertificate.g
      result.tightCertificate.d (result.tightCertificate.m - 1) ∧
    3 * result.tightCertificate.g <
      result.tightCertificate.d - result.tightCertificate.e ∧
    result.tightCertificate.g + 1 < result.tightCertificate.fieldSize ∧
    0 < CodingTheory.InterleavedJohnson.denominator
      result.tightCertificate.n result.tightCertificate.d
      (result.tightCertificate.e + result.tightCertificate.g) ∧
    result.tightCertificate.integratedLocalValidBool = true ∧
    0 < result.tightCertificate.k ∧
    2 * result.tightCertificate.k ≤ result.tightCertificate.n ∧
    result.openings ≤ result.tightCertificate.n ∧
    result.bound result.openings ≤
      (1 : ℚ) / 2 ^ result.certificate.targetBits ∧
    (1 : ℚ) / 2 ^ result.certificate.targetBits <
      result.bound (result.openings - 1)

def V1Result.validBool (result : V1Result) : Bool :=
  @decide result.Valid (by unfold Valid; infer_instance)

theorem V1Result.valid_of_validBool (result : V1Result)
    (h : result.validBool = true) : result.Valid := by
  letI : Decidable result.Valid := by
    unfold V1Result.Valid
    infer_instance
  apply of_decide_eq_true
  simpa [V1Result.validBool] using h

/-- A valid tight V1 row supplies the numerical hypotheses required by the
end-to-end Ligero V1 theorem. -/
theorem V1Result.conditions (result : V1Result) (h : result.Valid) :
    result.tightCertificate.conditions := by
  rcases h with ⟨hdirect, _hminimal, hthree, hfield, hdenominator,
    hlocal, _⟩
  exact result.tightCertificate.conditions_of_checked hdirect hthree hfield
    hdenominator hlocal



theorem V1Result.k_pos (result : V1Result) (h : result.Valid) :
    0 < result.tightCertificate.k := by
  rcases h with ⟨_, _, _, _, _, _, hk, _⟩
  exact hk

theorem V1Result.responseRange (result : V1Result) (h : result.Valid) :
    2 * result.tightCertificate.k ≤ result.tightCertificate.n := by
  rcases h with ⟨_, _, _, _, _, _, _, hrange, _⟩
  exact hrange

theorem V1Result.acceptanceRate_le_target
    (result : V1Result) (hvalid : result.Valid)
    {F Equations : Type*} [_root_.Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    {w nw nq : ℕ}
    (hrows : CoreRowsNonempty nw nq)
    (hfield : Fintype.card F = result.tightCertificate.fieldSize)
    (C : MultiplicativeCode F result.openings w result.tightCertificate.n)
    (hk : C.k = result.tightCertificate.k)
    (statement : ConstraintSystem F nw nq w Equations)
    (hfalse : ¬statement.Language)
    (prover : IPCPProver
      (ConstraintSystem F nw nq w Equations)
      (Ligero.V1.Oracle F nw nq result.tightCertificate.n 1)
      (Ligero.V1.Challenge F nw nq 1 Equations)
      (Response F result.openings w result.tightCertificate.n 1))
    (hmin : CodingTheory.HasMinimumDistanceAtLeast C.baseCode
      result.tightCertificate.d) :
    (SchemeVerifier.protocol C Ligero.V1.scheme).acceptanceRate prover statement ≤
      (1 : ℚ) / 2 ^ result.certificate.targetBits := by
  refine le_trans
    (result.tightCertificate.v1_protocol_soundness (result.conditions hvalid)
      hrows hfield C hk (result.k_pos hvalid) (result.responseRange hvalid)
      statement hfalse prover hmin) ?_
  rw [← result.bound_eq_soundness]
  rcases hvalid with ⟨_, _, _, _, _, _, _, _, _, hbound, _⟩
  exact hbound

def v1Results : List V1Result := [
  { certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S120
    g? := some 0
    m? := some 1816008
    openings := 121 },
  { certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S121
    g? := some 0
    m? := some 1816008
    openings := 122 },
  { certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S122
    g? := some 0
    m? := some 1816008
    openings := 123 },
  { certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S123
    g? := some 1
    m? := some 907142
    openings := 125 },
  { certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S124
    g? := some 1
    m? := some 907142
    openings := 126 },
  { certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S125
    g? := some 3
    m? := some 452709
    openings := 128 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S120
    g? := some 0
    m? := some 6248382
    openings := 127 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S121
    g? := some 0
    m? := some 6248382
    openings := 128 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S122
    g? := some 1
    m? := some 3122710
    openings := 129 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S123
    g? := some 2
    m? := some 2078784
    openings := 131 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S124
    g? := some 3
    m? := some 1559873
    openings := 132 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S125
    g? := some 5
    m? := some 1037911
    openings := 134 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S120
    g? := some 49
    m? := some 78858
    openings := 89 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S121
    g? := some 49
    m? := some 78858
    openings := 90 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S122
    g? := some 49
    m? := some 78858
    openings := 90 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S123
    g? := some 49
    m? := some 78858
    openings := 91 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S124
    g? := some 49
    m? := some 78858
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S125
    g? := some 49
    m? := some 78858
    openings := 93 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S120
    g? := some 0
    m? := some 12310240
    openings := 129 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S121
    g? := some 1
    m? := some 6153175
    openings := 130 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S122
    g? := some 2
    m? := some 4100820
    openings := 132 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S123
    g? := some 3
    m? := some 3074642
    openings := 133 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S124
    g? := some 6
    m? := some 1751835
    openings := 135 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S125
    g? := some 10
    m? := some 1114483
    openings := 137 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S120
    g? := some 73
    m? := some 3365650
    openings := 90 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S121
    g? := some 73
    m? := some 3365650
    openings := 91 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S122
    g? := some 73
    m? := some 3365650
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S123
    g? := some 73
    m? := some 3365650
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S124
    g? := some 73
    m? := some 3365650
    openings := 93 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S125
    g? := some 73
    m? := some 3365650
    openings := 94 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S120
    g? := some 1
    m? := some 21812883
    openings := 130 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S121
    g? := some 2
    m? := some 14534923
    openings := 132 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S122
    g? := some 3
    m? := some 10901271
    openings := 133 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S123
    g? := some 4
    m? := some 8716818
    openings := 134 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S124
    g? := some 7
    m? := some 5445466
    openings := 136 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S125
    g? := some 12
    m? := some 3346259
    openings := 138 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S120
    g? := some 99
    m? := some 343687
    openings := 91 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S121
    g? := some 99
    m? := some 343687
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S122
    g? := some 99
    m? := some 343687
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S123
    g? := some 99
    m? := some 343687
    openings := 93 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S124
    g? := some 99
    m? := some 343687
    openings := 94 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S125
    g? := some 99
    m? := some 343687
    openings := 95 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S120
    g? := some 1
    m? := some 27268688
    openings := 131 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S121
    g? := some 2
    m? := some 18168575
    openings := 132 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S122
    g? := some 3
    m? := some 13629174
    openings := 133 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S123
    g? := some 6
    m? := some 7779101
    openings := 135 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S124
    g? := some 10
    m? := some 4944640
    openings := 137 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S125
    g? := some 17
    m? := some 3015927
    openings := 139 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S120
    g? := some 124
    m? := some 211189
    openings := 91 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S121
    g? := some 124
    m? := some 211189
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S122
    g? := some 124
    m? := some 211189
    openings := 93 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S123
    g? := some 124
    m? := some 211189
    openings := 94 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S124
    g? := some 124
    m? := some 211189
    openings := 94 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S125
    g? := some 124
    m? := some 211189
    openings := 96 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S120
    g? := some 1
    m? := some 32724494
    openings := 131 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S121
    g? := some 3
    m? := some 16357077
    openings := 133 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S122
    g? := some 5
    m? := some 10901271
    openings := 134 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S123
    g? := some 6
    m? := some 9334858
    openings := 135 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S124
    g? := some 11
    m? := some 5445466
    openings := 137 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S125
    g? := some 19
    m? := some 3261012
    openings := 139 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S120
    g? := some 149
    m? := some 168011
    openings := 91 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S121
    g? := some 149
    m? := some 168011
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S122
    g? := some 149
    m? := some 168011
    openings := 93 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S123
    g? := some 149
    m? := some 168011
    openings := 94 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S124
    g? := some 149
    m? := some 168011
    openings := 95 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S125
    g? := some 149
    m? := some 168011
    openings := 96 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S120
    g? := some 2
    m? := some 76419450
    openings := 132 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S121
    g? := some 4
    m? := some 45840802
    openings := 133 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S122
    g? := some 5
    m? := some 38196140
    openings := 134 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S123
    g? := some 10
    m? := some 20806634
    openings := 136 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S124
    g? := some 17
    m? := some 12713933
    openings := 138 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S125
    g? := some 27
    m? := some 8149538
    openings := 140 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S120
    g? := some 199
    m? := some 361219
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S121
    g? := some 199
    m? := some 361219
    openings := 93 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S122
    g? := some 199
    m? := some 361219
    openings := 93 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S123
    g? := some 199
    m? := some 361219
    openings := 94 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S124
    g? := some 199
    m? := some 361219
    openings := 95 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S125
    g? := some 199
    m? := some 361219
    openings := 96 },
  { certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S120
    g? := some 0
    m? := some 1816008
    openings := 121 },
  { certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S121
    g? := some 0
    m? := some 1816008
    openings := 122 },
  { certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S122
    g? := some 0
    m? := some 1816008
    openings := 123 },
  { certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S123
    g? := some 0
    m? := some 1816008
    openings := 124 },
  { certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S124
    g? := some 0
    m? := some 1816008
    openings := 125 },
  { certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S125
    g? := some 0
    m? := some 1816008
    openings := 126 },
  { certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S126
    g? := some 0
    m? := some 1816008
    openings := 127 },
  { certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S127
    g? := some 0
    m? := some 1816008
    openings := 128 },
  { certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S128
    g? := some 0
    m? := some 1816008
    openings := 129 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S120
    g? := some 0
    m? := some 6248382
    openings := 127 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S121
    g? := some 0
    m? := some 6248382
    openings := 128 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S122
    g? := some 0
    m? := some 6248382
    openings := 129 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S123
    g? := some 0
    m? := some 6248382
    openings := 130 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S124
    g? := some 0
    m? := some 6248382
    openings := 131 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S125
    g? := some 0
    m? := some 6248382
    openings := 132 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S126
    g? := some 0
    m? := some 6248382
    openings := 133 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S127
    g? := some 0
    m? := some 6248382
    openings := 134 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S128
    g? := some 0
    m? := some 6248382
    openings := 135 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S120
    g? := some 0
    m? := some 4153211
    openings := 89 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S121
    g? := some 0
    m? := some 4153211
    openings := 90 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S122
    g? := some 0
    m? := some 4153211
    openings := 90 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S123
    g? := some 0
    m? := some 4153211
    openings := 91 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S124
    g? := some 0
    m? := some 4153211
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S125
    g? := some 0
    m? := some 4153211
    openings := 93 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S126
    g? := some 0
    m? := some 4153211
    openings := 93 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S127
    g? := some 0
    m? := some 4153211
    openings := 94 },
  { certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S128
    g? := some 0
    m? := some 4153211
    openings := 95 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S120
    g? := some 0
    m? := some 12310240
    openings := 129 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S121
    g? := some 0
    m? := some 12310240
    openings := 130 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S122
    g? := some 0
    m? := some 12310240
    openings := 131 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S123
    g? := some 0
    m? := some 12310240
    openings := 132 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S124
    g? := some 0
    m? := some 12310240
    openings := 133 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S125
    g? := some 0
    m? := some 12310240
    openings := 134 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S126
    g? := some 0
    m? := some 12310240
    openings := 135 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S127
    g? := some 0
    m? := some 12310240
    openings := 136 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S128
    g? := some 0
    m? := some 12310240
    openings := 137 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S120
    g? := some 0
    m? := some 259269631
    openings := 90 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S121
    g? := some 0
    m? := some 259269631
    openings := 91 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S122
    g? := some 0
    m? := some 259269631
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S123
    g? := some 0
    m? := some 259269631
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S124
    g? := some 0
    m? := some 259269631
    openings := 93 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S125
    g? := some 0
    m? := some 259269631
    openings := 94 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S126
    g? := some 0
    m? := some 259269631
    openings := 94 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S127
    g? := some 0
    m? := some 259269631
    openings := 95 },
  { certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S128
    g? := some 0
    m? := some 259269631
    openings := 96 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S120
    g? := some 0
    m? := some 43636105
    openings := 130 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S121
    g? := some 0
    m? := some 43636105
    openings := 131 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S122
    g? := some 0
    m? := some 43636105
    openings := 132 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S123
    g? := some 0
    m? := some 43636105
    openings := 133 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S124
    g? := some 0
    m? := some 43636105
    openings := 134 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S125
    g? := some 0
    m? := some 43636105
    openings := 136 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S126
    g? := some 0
    m? := some 43636105
    openings := 137 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S127
    g? := some 0
    m? := some 43636105
    openings := 138 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S128
    g? := some 0
    m? := some 43636105
    openings := 139 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S120
    g? := some 0
    m? := some 36211342
    openings := 91 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S121
    g? := some 0
    m? := some 36211342
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S122
    g? := some 0
    m? := some 36211342
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S123
    g? := some 0
    m? := some 36211342
    openings := 93 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S124
    g? := some 0
    m? := some 36211342
    openings := 94 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S125
    g? := some 0
    m? := some 36211342
    openings := 95 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S126
    g? := some 0
    m? := some 36211342
    openings := 95 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S127
    g? := some 0
    m? := some 36211342
    openings := 96 },
  { certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S128
    g? := some 0
    m? := some 36211342
    openings := 97 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S120
    g? := some 0
    m? := some 54547717
    openings := 131 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S121
    g? := some 0
    m? := some 54547717
    openings := 132 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S122
    g? := some 0
    m? := some 54547717
    openings := 133 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S123
    g? := some 0
    m? := some 54547717
    openings := 134 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S124
    g? := some 0
    m? := some 54547717
    openings := 135 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S125
    g? := some 0
    m? := some 54547717
    openings := 136 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S126
    g? := some 0
    m? := some 54547717
    openings := 137 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S127
    g? := some 0
    m? := some 54547717
    openings := 138 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S128
    g? := some 0
    m? := some 54547717
    openings := 139 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S120
    g? := some 0
    m? := some 27815389
    openings := 91 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S121
    g? := some 0
    m? := some 27815389
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S122
    g? := some 0
    m? := some 27815389
    openings := 93 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S123
    g? := some 0
    m? := some 27815389
    openings := 93 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S124
    g? := some 0
    m? := some 27815389
    openings := 94 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S125
    g? := some 0
    m? := some 27815389
    openings := 95 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S126
    g? := some 0
    m? := some 27815389
    openings := 96 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S127
    g? := some 0
    m? := some 27815389
    openings := 96 },
  { certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S128
    g? := some 0
    m? := some 27815389
    openings := 97 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S120
    g? := some 0
    m? := some 65459328
    openings := 131 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S121
    g? := some 0
    m? := some 65459328
    openings := 132 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S122
    g? := some 0
    m? := some 65459328
    openings := 133 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S123
    g? := some 0
    m? := some 65459328
    openings := 134 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S124
    g? := some 0
    m? := some 65459328
    openings := 135 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S125
    g? := some 0
    m? := some 65459328
    openings := 136 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S126
    g? := some 0
    m? := some 65459328
    openings := 138 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S127
    g? := some 0
    m? := some 65459328
    openings := 139 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S128
    g? := some 0
    m? := some 65459328
    openings := 140 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S120
    g? := some 0
    m? := some 26554957
    openings := 91 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S121
    g? := some 0
    m? := some 26554957
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S122
    g? := some 0
    m? := some 26554957
    openings := 93 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S123
    g? := some 0
    m? := some 26554957
    openings := 94 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S124
    g? := some 0
    m? := some 26554957
    openings := 94 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S125
    g? := some 0
    m? := some 26554957
    openings := 95 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S126
    g? := some 0
    m? := some 26554957
    openings := 96 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S127
    g? := some 0
    m? := some 26554957
    openings := 97 },
  { certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S128
    g? := some 0
    m? := some 26554957
    openings := 97 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S120
    g? := some 0
    m? := some 229368694
    openings := 132 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S121
    g? := some 0
    m? := some 229368694
    openings := 133 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S122
    g? := some 0
    m? := some 229368694
    openings := 134 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S123
    g? := some 0
    m? := some 229368694
    openings := 135 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S124
    g? := some 0
    m? := some 229368694
    openings := 136 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S125
    g? := some 0
    m? := some 229368694
    openings := 137 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S126
    g? := some 0
    m? := some 229368694
    openings := 138 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S127
    g? := some 0
    m? := some 229368694
    openings := 139 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S128
    g? := some 0
    m? := some 229368694
    openings := 140 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S120
    g? := some 0
    m? := some 76126763
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S121
    g? := some 0
    m? := some 76126763
    openings := 92 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S122
    g? := some 0
    m? := some 76126763
    openings := 93 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S123
    g? := some 0
    m? := some 76126763
    openings := 94 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S124
    g? := some 0
    m? := some 76126763
    openings := 95 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S125
    g? := some 0
    m? := some 76126763
    openings := 96 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S126
    g? := some 0
    m? := some 76126763
    openings := 96 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S127
    g? := some 0
    m? := some 76126763
    openings := 97 },
  { certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S128
    g? := some 0
    m? := some 76126763
    openings := 98 },
]

theorem v1_result_count : v1Results.length = 195 := by native_decide
/-- The rows whose reported V1 opening count changes under exact profiling. -/
def changedV1 : List V1Result := v1Results.filter fun result =>
  result.openings < result.certificate.openings


theorem changed_v1_count : changedV1.length = 47 := by native_decide
/-- One executable certificate table covers both sibling masking variants. -/
def resultTableValid : Bool :=
  v1Results.all V1Result.validBool && true

/-- The single proof-producing check for the complete Ligero table. -/
theorem result_table_valid : resultTableValid = true := by
  native_decide

/-- Every reported V1 count passes the exact-profile boundary check for its
optimized certificate. -/
theorem v1_results_valid : v1Results.all V1Result.validBool = true := by
  have h := result_table_valid
  simpa [resultTableValid] using (Bool.and_eq_true_iff.mp h).1



theorem v1_valid_of_mem {result : V1Result} (hmem : result ∈ v1Results) :
    result.Valid := by
  have hall := v1_results_valid
  rw [List.all_eq_true] at hall
  exact result.valid_of_validBool (hall result hmem)

theorem changed_v1_valid : changedV1.all V1Result.validBool = true := by
  have hall := v1_results_valid
  rw [List.all_eq_true] at hall ⊢
  intro result hresult
  change result ∈ v1Results.filter (fun candidate =>
    candidate.openings < candidate.certificate.openings) at hresult
  exact hall result (List.mem_filter.mp hresult).1

end Ligero.Examples.Grid.Tight
