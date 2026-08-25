import examples.Ligero.Grid.Comparison



















namespace Ligero.Examples.Grid.ComparisonR15

open LigeroFamily

set_option maxHeartbeats 20000000

def n : ℕ := 8192
def k : ℕ := 546
def d : ℕ := 7647
def maxRadius : ℕ := 4872
def fieldBits : ℕ := 128
def fieldSize : ℕ := 2 ^ fieldBits
def arithmeticThreshold : ℕ := 2 * k - 1

structure RefinedResult where
  targetBits : ℕ
  openings : ℕ
  e : ℕ
  g : ℕ
  outerM : ℕ
  cutoff : ℕ
  localM : ℕ

def RefinedResult.listSize (result : RefinedResult) : ℕ :=
  CodingTheory.InterleavedJohnson.listBound n d (result.e + result.g)

def RefinedResult.profile (result : RefinedResult) : AgreementProfile n :=
  SchemeSelectedMCA.selectedMCARefinedFailureProfile n result.g d
    (SelectedMCA.directLineFailureBound result.outerM) result.cutoff
    (SelectedMCA.directLineFailureBound result.localM)

def RefinedResult.flatBound (result : RefinedResult) (queries : ℕ) : ℚ :=
  result.profile.compressedContribution
      (fieldSize - (result.g + 1)) n n 0 queries +
    result.arithmeticProfile.compressedContribution
      fieldSize n result.e result.g queries

def RefinedResult.challengeBound (result : RefinedResult) : ℚ :=
  (result.profile.labelsAtLeast result.cutoff : ℚ) /
      (fieldSize - (result.g + 1) : ℕ) +
    (result.arithmeticProfile.labelsAtLeast (arithmeticThreshold + 1) : ℚ) /
      fieldSize

def RefinedResult.failureThreshold (result : RefinedResult) : ℕ :=
  result.cutoff - 1

def RefinedResult.queryCover (result : RefinedResult) : ℕ :=
  max result.failureThreshold
    (max (n - result.e - 1) (min n (result.g + arithmeticThreshold)))

def RefinedResult.queryBound (result : RefinedResult) (queries : ℕ) : ℚ :=
  hypergeometricRatio result.queryCover n queries

def RefinedResult.ParametersValid (result : RefinedResult) : Prop :=
  SelectedMCA.DirectCliqueCondition n result.e result.g d result.outerM ∧
    ¬SelectedMCA.DirectCliqueCondition n result.e result.g d (result.outerM - 1) ∧
    n - result.e ≤ result.cutoff ∧ result.cutoff ≤ n ∧
    SelectedMCA.DirectCliqueCondition n (n - result.cutoff) result.g d result.localM ∧
    ¬SelectedMCA.DirectCliqueCondition n (n - result.cutoff) result.g d
      (result.localM - 1) ∧
    3 * result.g < d - result.e ∧
    3 * result.g < d - (n - result.cutoff) ∧
    result.g + 1 < fieldSize ∧
    0 < CodingTheory.InterleavedJohnson.denominator n d (result.e + result.g)

def RefinedResult.conditions (result : RefinedResult)
    (h : result.ParametersValid) :
    RefinedSelectedMCAParameterConditions fieldSize n result.e result.g d
      result.outerM result.cutoff result.localM := by
  rcases h with ⟨hOuter, _hOuterMinimal, hRadius, hCutoff, hLocal,
    _hLocalMinimal, hThree, hLocalThree, hField, hJohnson⟩
  exact
    { toSelectedMCAParameterConditions :=
        { direct := ⟨hOuter⟩
          punctured := ⟨hThree, hField⟩
          johnson := ⟨hJohnson⟩ }
      radius_le_cutoff := hRadius
      cutoff_le_length := hCutoff
      localDirect := hLocal
      local_three_radius := hLocalThree }

theorem RefinedResult.failureThreshold_succ (result : RefinedResult)
    (h : result.ParametersValid) : result.failureThreshold + 1 = result.cutoff := by
  have hcap := h.1.cap_lt
  have hradius := h.2.2.1
  unfold failureThreshold
  omega

def RefinedResult.FlatValid (result : RefinedResult) : Prop :=
  result.ParametersValid ∧
    result.flatBound result.openings ≤ (1 : ℚ) / 2 ^ result.targetBits ∧
    (1 : ℚ) / 2 ^ result.targetBits < result.flatBound (result.openings - 1)

def RefinedResult.RBRValid (result : RefinedResult) : Prop :=
  result.ParametersValid ∧
    result.challengeBound ≤ (1 : ℚ) / 2 ^ result.targetBits ∧
    result.queryBound result.openings ≤ (1 : ℚ) / 2 ^ result.targetBits ∧
    (1 : ℚ) / 2 ^ result.targetBits < result.queryBound (result.openings - 1)

def RefinedResult.flatValidBool (result : RefinedResult) : Bool :=
  @decide result.FlatValid (by unfold FlatValid ParametersValid; infer_instance)

def RefinedResult.rbrValidBool (result : RefinedResult) : Bool :=
  @decide result.RBRValid (by unfold RBRValid ParametersValid; infer_instance)

/-- Flat rows optimize the integrated refined-MCA objective at the maximum
supported radius. -/
def flatResults : List RefinedResult := [
  { targetBits := 115, openings := 88, e := maxRadius, g := 199, outerM := 361219,
    cutoff := 3354, localM := 6341 },
  { targetBits := 116, openings := 89, e := maxRadius, g := 199, outerM := 361219,
    cutoff := 3375, localM := 3952 },
  { targetBits := 117, openings := 89, e := maxRadius, g := 199, outerM := 361219,
    cutoff := 3375, localM := 3952 },
  { targetBits := 118, openings := 90, e := maxRadius, g := 199, outerM := 361219,
    cutoff := 3391, localM := 3072 },
  { targetBits := 119, openings := 91, e := maxRadius, g := 199, outerM := 361219,
    cutoff := 3540, localM := 1006 },
  { targetBits := 120, openings := 92, e := maxRadius, g := 199, outerM := 361219,
    cutoff := 3747, localM := 523 },
  { targetBits := 121, openings := 93, e := maxRadius, g := 199, outerM := 361219,
    cutoff := 3574, localM := 873 },
  { targetBits := 122, openings := 93, e := maxRadius, g := 199, outerM := 361219,
    cutoff := 3574, localM := 873 },
  { targetBits := 123, openings := 94, e := maxRadius, g := 199, outerM := 361219,
    cutoff := 3726, localM := 550 },
  { targetBits := 124, openings := 95, e := maxRadius, g := 199, outerM := 361219,
    cutoff := 3936, localM := 365 },
  { targetBits := 125, openings := 96, e := maxRadius, g := 199, outerM := 361219,
    cutoff := 4743, localM := 158 }
]

/-- RBR-specific selected/refined-MCA frontier.  These parameters are searched
against the separated challenge and query transition bounds, not copied from
`flatResults`. -/
def rbrResults : List RefinedResult := [
  { targetBits := 115, openings := 88, e := 4872, g := 910, outerM := 63807,
    cutoff := 3325, localM := 6902 },
  { targetBits := 116, openings := 89, e := 4872, g := 693, outerM := 91690,
    cutoff := 3334, localM := 3810 },
  { targetBits := 117, openings := 90, e := 4872, g := 819, outerM := 73101,
    cutoff := 3342, localM := 1965 },
  { targetBits := 118, openings := 91, e := 4863, g := 910, outerM := 4030,
    cutoff := 3358, localM := 1006 },
  { targetBits := 119, openings := 93, e := 4822, g := 915, outerM := 769,
    cutoff := 3398, localM := 496 },
  { targetBits := 120, openings := 97, e := 4720, g := 910, outerM := 258,
    cutoff := 3478, localM := 248 },
  { targetBits := 121, openings := 102, e := 4574, g := 1024, outerM := 114,
    cutoff := 3618, localM := 114 },
  { targetBits := 122, openings := 113, e := 4288, g := 1024, outerM := 60,
    cutoff := 3904, localM := 60 },
  { targetBits := 123, openings := 133, e := 3866, g := 1170, outerM := 30,
    cutoff := 4342, localM := 29 },
  { targetBits := 124, openings := 177, e := 3131, g := 1365, outerM := 15,
    cutoff := 5067, localM := 14 },
  { targetBits := 125, openings := 229, e := 2553, g := 511, outerM := 38,
    cutoff := 5644, localM := 38 }
]

theorem flatResults_valid : flatResults.all RefinedResult.flatValidBool = true := by
  native_decide

theorem rbrResults_valid : rbrResults.all RefinedResult.rbrValidBool = true := by
  native_decide

structure RigidNumericResult where
  targetBits : ℕ
  openings : ℕ

def RigidNumericResult.gridResult (result : RigidNumericResult) :
    Ligero.Examples.Grid.Rigid.Result :=
  { certificate := result.certificate
    g := 924
    m := 63807
    openings := result.openings }

def RigidNumericResult.Valid (result : RigidNumericResult) : Prop :=
  result.gridResult.NumericValid

def RigidNumericResult.validBool (result : RigidNumericResult) : Bool :=
  @decide result.Valid (by
    unfold Valid Ligero.Examples.Grid.Rigid.Result.NumericValid
      Ligero.Examples.Grid.Rigid.Result.ParametersValid
    infer_instance)

def rigidNumerics : List RigidNumericResult := [
  { targetBits := 115, openings := 89 },
  { targetBits := 116, openings := 89 },
  { targetBits := 117, openings := 90 },
  { targetBits := 118, openings := 91 },
  { targetBits := 119, openings := 92 },
  { targetBits := 120, openings := 92 },
  { targetBits := 121, openings := 93 },
  { targetBits := 122, openings := 94 },
  { targetBits := 123, openings := 95 },
  { targetBits := 124, openings := 96 },
  { targetBits := 125, openings := 97 }
]

theorem rigidNumerics_valid :
    rigidNumerics.all RigidNumericResult.validBool = true := by
  native_decide

abbrev Regime := Ligero.Examples.Grid.Comparison.Regime

structure SideBySide where
  targetBits : ℕ
  flatRegime : Regime
  flatOpenings : ℕ
  rigidOpenings : ℕ
  rbrRegime : Regime
  rbrOpenings : ℕ
deriving DecidableEq, Repr

def sideBySide : List SideBySide := [
  ⟨115, .refinedMCA, 88, 89, .refinedMCA, 88⟩,
  ⟨116, .refinedMCA, 89, 89, .refinedMCA, 89⟩,
  ⟨117, .refinedMCA, 89, 90, .refinedMCA, 90⟩,
  ⟨118, .refinedMCA, 90, 91, .refinedMCA, 91⟩,
  ⟨119, .refinedMCA, 91, 92, .refinedMCA, 93⟩,
  ⟨120, .refinedMCA, 92, 92, .refinedMCA, 97⟩,
  ⟨121, .refinedMCA, 93, 93, .selectedMCA, 102⟩,
  ⟨122, .refinedMCA, 93, 94, .selectedMCA, 113⟩,
  ⟨123, .refinedMCA, 94, 95, .refinedMCA, 133⟩,
  ⟨124, .refinedMCA, 95, 96, .refinedMCA, 177⟩,
  ⟨125, .refinedMCA, 96, 97, .selectedMCA, 229⟩
]

theorem sideBySide_count : sideBySide.length = 11 := by native_decide

end Ligero.Examples.Grid.ComparisonR15
