import examples.Ligero.Grid
import examples.Ligero.Grid.Data











namespace Ligero.Examples.Grid.UDR

open LigeroFamily

set_option maxHeartbeats 10000000

inductive Variant where
  | v1
deriving DecidableEq, Repr

structure Result where
  variant : Variant
  certificate : Ligero.Examples.Grid.Certificate
  e : ℕ
  g : ℕ
  m : ℕ
  cutoff : ℕ := 0
  localM : ℕ := 0
  openings : ℕ

def Result.tightCertificate (result : Result) :
    Ligero.Examples.Grid.Certificate :=
  { result.certificate with
      e := result.e
      g := result.g
      m := result.m
      cutoff := result.cutoff
      localM := result.localM
      openings := result.openings }

/-- Exact compressed singleton-lift bound for the chosen protocol variant. -/
def Result.bound (result : Result) (queries : ℕ) : ℚ :=
  match result.variant with
  | .v1 => Ligero.Examples.Grid.V1Certificate.compressedUniqueV1Soundness
      result.tightCertificate queries
theorem Result.bound_eq_v1 (result : Result) (hvariant : result.variant = .v1)
    (queries : ℕ) :
    result.bound queries =
      Ligero.Examples.Grid.V1Certificate.uniqueV1Soundness
        result.tightCertificate queries := by
  rw [Result.bound, hvariant]
  exact Ligero.Examples.Grid.V1Certificate.compressedUniqueV1Soundness_eq
    result.tightCertificate queries

/-- Every numerical premise used by the singleton-lift protocol theorems. -/
def Result.ParametersValid (result : Result) : Prop :=
  SelectedMCA.DirectCliqueCondition result.certificate.n
      result.e result.g result.certificate.d result.m ∧
    ¬SelectedMCA.DirectCliqueCondition result.certificate.n
      result.e result.g result.certificate.d (result.m - 1) ∧
    3 * result.g < result.certificate.d - result.e ∧
    result.g + 1 < result.certificate.fieldSize ∧
    0 < CodingTheory.InterleavedJohnson.denominator result.certificate.n
      result.certificate.d (result.e + result.g) ∧
    result.tightCertificate.integratedLocalValidBool = true ∧
    2 * (result.e + result.g) < result.certificate.d ∧
    0 < result.certificate.k ∧
    2 * result.certificate.k ≤ result.certificate.n ∧
    result.openings ≤ result.certificate.n

def Result.NumericValid (result : Result) : Prop :=
  result.ParametersValid ∧
    0 < result.openings ∧
    result.bound result.openings ≤
      (1 : ℚ) / 2 ^ result.certificate.targetBits ∧
    (1 : ℚ) / 2 ^ result.certificate.targetBits <
      result.bound (result.openings - 1)

def Result.validBool (result : Result) : Bool :=
  @decide result.NumericValid (by
    unfold NumericValid ParametersValid
    infer_instance)

theorem Result.numericValid_of_validBool (result : Result)
    (h : result.validBool = true) : result.NumericValid := by
  letI : Decidable result.NumericValid := by
    unfold Result.NumericValid Result.ParametersValid
    infer_instance
  apply of_decide_eq_true
  simpa [Result.validBool] using h

theorem Result.conditions (result : Result) (h : result.ParametersValid) :
    result.tightCertificate.conditions := by
  rcases h with ⟨hdirect, _hminimal, hthree, hfield, hdenominator,
    hlocal, _⟩
  exact result.tightCertificate.conditions_of_checked hdirect hthree hfield
    hdenominator hlocal

theorem Result.uniqueRadius (result : Result) (h : result.ParametersValid) :
    2 * (result.tightCertificate.e + result.tightCertificate.g) <
      result.tightCertificate.d := by
  rcases h with ⟨_, _, _, _, _, _, hunique, _⟩
  exact hunique

theorem Result.k_pos (result : Result) (h : result.ParametersValid) :
    0 < result.tightCertificate.k := by
  rcases h with ⟨_, _, _, _, _, _, _, hk, _⟩
  exact hk

theorem Result.responseRange (result : Result) (h : result.ParametersValid) :
    2 * result.tightCertificate.k ≤ result.tightCertificate.n := by
  rcases h with ⟨_, _, _, _, _, _, _, _, hrange, _⟩
  exact hrange

/-! ## Actual protocol consequences -/

theorem Result.v1_acceptanceRate_le_target
    (result : Result) (hvalid : result.NumericValid)
    (hvariant : result.variant = .v1)
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
  have hprotocol :=
    Ligero.Examples.Grid.V1Certificate.v1_unique_protocol_soundness
      result.tightCertificate
    (result.conditions hvalid.1) hrows hfield C hk
    (result.k_pos hvalid.1) (result.responseRange hvalid.1)
    statement hfalse prover hmin (result.uniqueRadius hvalid.1)
  refine le_trans hprotocol ?_
  have hbound := hvalid.2.2.1
  rw [result.bound_eq_v1 hvariant result.openings] at hbound
  simpa [Result.tightCertificate] using hbound

/-- Numerically optimized by `scripts/generate_udr_grid.py`; Lean checks every
row and predecessor but does not claim global optimality outside the declared
search neighborhood. -/
def results : List Result := [
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S120
    e := 439
    g := 0
    m := 9803
    openings := 135 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S121
    e := 439
    g := 0
    m := 9803
    openings := 136 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S122
    e := 439
    g := 0
    m := 9803
    openings := 137 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S123
    e := 439
    g := 0
    m := 9803
    openings := 139 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S124
    e := 438
    g := 1
    m := 4806
    openings := 140 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S125
    e := 437
    g := 2
    m := 3140
    openings := 142 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S120
    e := 878
    g := 0
    m := 19807
    openings := 142 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S121
    e := 878
    g := 0
    m := 19807
    openings := 143 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S122
    e := 877
    g := 1
    m := 9805
    openings := 145 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S123
    e := 877
    g := 1
    m := 9805
    openings := 146 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S124
    e := 875
    g := 3
    m := 4807
    openings := 148 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F128_S125
    e := 873
    g := 5
    m := 3141
    openings := 150 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S120
    e := 956
    g := 0
    m := 11166
    openings := 127 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S121
    e := 956
    g := 0
    m := 11166
    openings := 128 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S122
    e := 955
    g := 1
    m := 5560
    openings := 129 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S123
    e := 954
    g := 2
    m := 3688
    openings := 131 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S124
    e := 953
    g := 3
    m := 2757
    openings := 132 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F128_S125
    e := 951
    g := 5
    m := 1821
    openings := 134 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S120
    e := 1317
    g := 0
    m := 29812
    openings := 144 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S121
    e := 1316
    g := 1
    m := 14807
    openings := 146 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S122
    e := 1316
    g := 1
    m := 14807
    openings := 147 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S123
    e := 1314
    g := 3
    m := 7306
    openings := 149 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S124
    e := 1313
    g := 4
    m := 5803
    openings := 150 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F128_S125
    e := 1310
    g := 7
    m := 3559
    openings := 152 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S120
    e := 1434
    g := 0
    m := 16778
    openings := 129 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S121
    e := 1433
    g := 1
    m := 8366
    openings := 130 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S122
    e := 1433
    g := 1
    m := 8366
    openings := 131 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S123
    e := 1431
    g := 3
    m := 4160
    openings := 133 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S124
    e := 1429
    g := 5
    m := 2758
    openings := 134 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F128_S125
    e := 1426
    g := 8
    m := 1822
    openings := 136 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S120
    e := 1754
    g := 1
    m := 19811
    openings := 146 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S121
    e := 1754
    g := 1
    m := 19811
    openings := 147 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S122
    e := 1753
    g := 2
    m := 13138
    openings := 148 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S123
    e := 1751
    g := 4
    m := 7805
    openings := 150 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S124
    e := 1748
    g := 7
    m := 4808
    openings := 152 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F128_S125
    e := 1744
    g := 11
    m := 3141
    openings := 154 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S120
    e := 1910
    g := 1
    m := 11176
    openings := 130 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S121
    e := 1910
    g := 1
    m := 11176
    openings := 131 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S122
    e := 1909
    g := 2
    m := 7433
    openings := 132 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S123
    e := 1907
    g := 4
    m := 4441
    openings := 134 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S124
    e := 1905
    g := 6
    m := 3159
    openings := 135 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F128_S125
    e := 1900
    g := 11
    m := 1823
    openings := 137 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S120
    e := 2193
    g := 1
    m := 24814
    openings := 146 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S121
    e := 2192
    g := 2
    m := 16470
    openings := 148 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S122
    e := 2191
    g := 3
    m := 12308
    openings := 149 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S123
    e := 2189
    g := 5
    m := 8137
    openings := 151 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S124
    e := 2187
    g := 7
    m := 6057
    openings := 152 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F128_S125
    e := 2183
    g := 11
    m := 3969
    openings := 154 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S120
    e := 2388
    g := 1
    m := 13981
    openings := 131 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S121
    e := 2387
    g := 2
    m := 9302
    openings := 132 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S122
    e := 2386
    g := 3
    m := 6967
    openings := 133 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S123
    e := 2384
    g := 5
    m := 4628
    openings := 134 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S124
    e := 2380
    g := 9
    m := 2759
    openings := 136 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F128_S125
    e := 2374
    g := 15
    m := 1708
    openings := 138 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S120
    e := 2632
    g := 1
    m := 29816
    openings := 147 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S121
    e := 2631
    g := 2
    m := 19811
    openings := 148 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S122
    e := 2629
    g := 4
    m := 11800
    openings := 150 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S123
    e := 2627
    g := 6
    m := 8372
    openings := 151 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S124
    e := 2623
    g := 10
    m := 5257
    openings := 153 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F128_S125
    e := 2618
    g := 15
    m := 3560
    openings := 155 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S120
    e := 2865
    g := 2
    m := 11176
    openings := 131 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S121
    e := 2865
    g := 2
    m := 11176
    openings := 132 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S122
    e := 2863
    g := 4
    m := 6683
    openings := 133 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S123
    e := 2860
    g := 7
    m := 4162
    openings := 135 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S124
    e := 2858
    g := 9
    m := 3318
    openings := 136 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F128_S125
    e := 2851
    g := 16
    m := 1932
    openings := 138 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S120
    e := 3508
    g := 3
    m := 19860
    openings := 148 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S121
    e := 3507
    g := 4
    m := 15844
    openings := 149 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S122
    e := 3506
    g := 5
    m := 13171
    openings := 150 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S123
    e := 3502
    g := 9
    m := 7824
    openings := 152 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S124
    e := 3497
    g := 14
    m := 5152
    openings := 154 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F128_S125
    e := 3489
    g := 22
    m := 3295
    openings := 156 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S120
    e := 3820
    g := 3
    m := 11189
    openings := 132 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S121
    e := 3819
    g := 4
    m := 8939
    openings := 133 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S122
    e := 3817
    g := 6
    m := 6372
    openings := 134 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S123
    e := 3815
    g := 8
    m := 4946
    openings := 135 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S124
    e := 3808
    g := 15
    m := 2763
    openings := 137 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S125
    e := 3799
    g := 24
    m := 1748
    openings := 139 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S120
    e := 439
    g := 0
    m := 9803
    openings := 135 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S121
    e := 439
    g := 0
    m := 9803
    openings := 136 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S122
    e := 439
    g := 0
    m := 9803
    openings := 137 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S123
    e := 439
    g := 0
    m := 9803
    openings := 138 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S124
    e := 439
    g := 0
    m := 9803
    openings := 139 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S125
    e := 439
    g := 0
    m := 9803
    openings := 140 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S126
    e := 439
    g := 0
    m := 9803
    openings := 141 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S127
    e := 439
    g := 0
    m := 9803
    openings := 142 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N1024_R7_V1_F255_S128
    e := 439
    g := 0
    m := 9803
    openings := 143 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S120
    e := 878
    g := 0
    m := 19807
    openings := 142 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S121
    e := 878
    g := 0
    m := 19807
    openings := 143 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S122
    e := 878
    g := 0
    m := 19807
    openings := 144 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S123
    e := 878
    g := 0
    m := 19807
    openings := 145 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S124
    e := 878
    g := 0
    m := 19807
    openings := 146 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S125
    e := 878
    g := 0
    m := 19807
    openings := 147 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S126
    e := 878
    g := 0
    m := 19807
    openings := 149 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S127
    e := 878
    g := 0
    m := 19807
    openings := 150 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R7_V1_F255_S128
    e := 878
    g := 0
    m := 19807
    openings := 151 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S120
    e := 956
    g := 0
    m := 11166
    openings := 127 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S121
    e := 956
    g := 0
    m := 11166
    openings := 128 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S122
    e := 956
    g := 0
    m := 11166
    openings := 129 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S123
    e := 956
    g := 0
    m := 11166
    openings := 130 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S124
    e := 956
    g := 0
    m := 11166
    openings := 131 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S125
    e := 956
    g := 0
    m := 11166
    openings := 132 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S126
    e := 956
    g := 0
    m := 11166
    openings := 133 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S127
    e := 956
    g := 0
    m := 11166
    openings := 134 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N2048_R15_V1_F255_S128
    e := 956
    g := 0
    m := 11166
    openings := 135 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S120
    e := 1317
    g := 0
    m := 29812
    openings := 144 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S121
    e := 1317
    g := 0
    m := 29812
    openings := 145 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S122
    e := 1317
    g := 0
    m := 29812
    openings := 147 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S123
    e := 1317
    g := 0
    m := 29812
    openings := 148 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S124
    e := 1317
    g := 0
    m := 29812
    openings := 149 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S125
    e := 1317
    g := 0
    m := 29812
    openings := 150 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S126
    e := 1317
    g := 0
    m := 29812
    openings := 151 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S127
    e := 1317
    g := 0
    m := 29812
    openings := 152 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R7_V1_F255_S128
    e := 1317
    g := 0
    m := 29812
    openings := 153 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S120
    e := 1434
    g := 0
    m := 16778
    openings := 129 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S121
    e := 1434
    g := 0
    m := 16778
    openings := 130 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S122
    e := 1434
    g := 0
    m := 16778
    openings := 131 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S123
    e := 1434
    g := 0
    m := 16778
    openings := 132 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S124
    e := 1434
    g := 0
    m := 16778
    openings := 133 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S125
    e := 1434
    g := 0
    m := 16778
    openings := 134 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S126
    e := 1434
    g := 0
    m := 16778
    openings := 135 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S127
    e := 1434
    g := 0
    m := 16778
    openings := 136 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N3072_R15_V1_F255_S128
    e := 1434
    g := 0
    m := 16778
    openings := 137 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S120
    e := 1755
    g := 0
    m := 39822
    openings := 146 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S121
    e := 1755
    g := 0
    m := 39822
    openings := 147 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S122
    e := 1755
    g := 0
    m := 39822
    openings := 148 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S123
    e := 1755
    g := 0
    m := 39822
    openings := 149 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S124
    e := 1755
    g := 0
    m := 39822
    openings := 150 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S125
    e := 1755
    g := 0
    m := 39822
    openings := 151 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S126
    e := 1755
    g := 0
    m := 39822
    openings := 153 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S127
    e := 1755
    g := 0
    m := 39822
    openings := 154 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R7_V1_F255_S128
    e := 1755
    g := 0
    m := 39822
    openings := 155 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S120
    e := 1911
    g := 0
    m := 22398
    openings := 130 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S121
    e := 1911
    g := 0
    m := 22398
    openings := 131 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S122
    e := 1911
    g := 0
    m := 22398
    openings := 132 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S123
    e := 1911
    g := 0
    m := 22398
    openings := 133 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S124
    e := 1911
    g := 0
    m := 22398
    openings := 134 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S125
    e := 1911
    g := 0
    m := 22398
    openings := 135 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S126
    e := 1911
    g := 0
    m := 22398
    openings := 136 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S127
    e := 1911
    g := 0
    m := 22398
    openings := 137 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N4096_R15_V1_F255_S128
    e := 1911
    g := 0
    m := 22398
    openings := 138 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S120
    e := 2194
    g := 0
    m := 49828
    openings := 146 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S121
    e := 2194
    g := 0
    m := 49828
    openings := 147 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S122
    e := 2194
    g := 0
    m := 49828
    openings := 149 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S123
    e := 2194
    g := 0
    m := 49828
    openings := 150 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S124
    e := 2194
    g := 0
    m := 49828
    openings := 151 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S125
    e := 2194
    g := 0
    m := 49828
    openings := 152 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S126
    e := 2194
    g := 0
    m := 49828
    openings := 153 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S127
    e := 2194
    g := 0
    m := 49828
    openings := 155 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R7_V1_F255_S128
    e := 2194
    g := 0
    m := 49828
    openings := 156 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S120
    e := 2389
    g := 0
    m := 28009
    openings := 130 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S121
    e := 2389
    g := 0
    m := 28009
    openings := 131 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S122
    e := 2389
    g := 0
    m := 28009
    openings := 133 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S123
    e := 2389
    g := 0
    m := 28009
    openings := 134 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S124
    e := 2389
    g := 0
    m := 28009
    openings := 135 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S125
    e := 2389
    g := 0
    m := 28009
    openings := 136 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S126
    e := 2389
    g := 0
    m := 28009
    openings := 137 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S127
    e := 2389
    g := 0
    m := 28009
    openings := 138 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N5120_R15_V1_F255_S128
    e := 2389
    g := 0
    m := 28009
    openings := 139 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S120
    e := 2633
    g := 0
    m := 59833
    openings := 147 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S121
    e := 2633
    g := 0
    m := 59833
    openings := 148 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S122
    e := 2633
    g := 0
    m := 59833
    openings := 149 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S123
    e := 2633
    g := 0
    m := 59833
    openings := 150 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S124
    e := 2633
    g := 0
    m := 59833
    openings := 151 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S125
    e := 2633
    g := 0
    m := 59833
    openings := 153 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S126
    e := 2633
    g := 0
    m := 59833
    openings := 154 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S127
    e := 2633
    g := 0
    m := 59833
    openings := 155 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R7_V1_F255_S128
    e := 2633
    g := 0
    m := 59833
    openings := 156 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S120
    e := 2867
    g := 0
    m := 33621
    openings := 131 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S121
    e := 2867
    g := 0
    m := 33621
    openings := 132 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S122
    e := 2867
    g := 0
    m := 33621
    openings := 133 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S123
    e := 2867
    g := 0
    m := 33621
    openings := 134 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S124
    e := 2867
    g := 0
    m := 33621
    openings := 135 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S125
    e := 2867
    g := 0
    m := 33621
    openings := 136 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S126
    e := 2867
    g := 0
    m := 33621
    openings := 137 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S127
    e := 2867
    g := 0
    m := 33621
    openings := 138 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N6144_R15_V1_F255_S128
    e := 2867
    g := 0
    m := 33621
    openings := 139 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S120
    e := 3511
    g := 0
    m := 80044
    openings := 147 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S121
    e := 3511
    g := 0
    m := 80044
    openings := 148 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S122
    e := 3511
    g := 0
    m := 80044
    openings := 150 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S123
    e := 3511
    g := 0
    m := 80044
    openings := 151 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S124
    e := 3511
    g := 0
    m := 80044
    openings := 152 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S125
    e := 3511
    g := 0
    m := 80044
    openings := 153 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S126
    e := 3511
    g := 0
    m := 80044
    openings := 155 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S127
    e := 3511
    g := 0
    m := 80044
    openings := 156 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R7_V1_F255_S128
    e := 3511
    g := 0
    m := 80044
    openings := 157 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S120
    e := 3823
    g := 0
    m := 44895
    openings := 131 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S121
    e := 3823
    g := 0
    m := 44895
    openings := 132 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S122
    e := 3823
    g := 0
    m := 44895
    openings := 133 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S123
    e := 3823
    g := 0
    m := 44895
    openings := 135 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S124
    e := 3823
    g := 0
    m := 44895
    openings := 136 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S125
    e := 3823
    g := 0
    m := 44895
    openings := 137 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S126
    e := 3823
    g := 0
    m := 44895
    openings := 138 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S127
    e := 3823
    g := 0
    m := 44895
    openings := 139 },
  { variant := .v1
    certificate := Ligero.Examples.Grid.Data.N8192_R15_V1_F255_S128
    e := 3823
    g := 0
    m := 44895
    openings := 140 },
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
]

theorem v1_result_count :
    (results.filter fun result ↦ result.variant = .v1).length = 195 := by
  native_decide

/-- Exact-rational validation of every row and its predecessor. -/
theorem results_valid : results.all Result.validBool = true := by
  native_decide

theorem numericValid_of_mem_results {result : Result}
    (hmem : result ∈ results) : result.NumericValid := by
  have hall := results_valid
  rw [List.all_eq_true] at hall
  exact result.numericValid_of_validBool (hall result hmem)

end Ligero.Examples.Grid.UDR
