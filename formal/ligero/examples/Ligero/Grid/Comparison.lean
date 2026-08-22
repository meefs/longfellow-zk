import examples.Ligero.Grid
namespace Ligero.Examples.Grid.Comparison

open LigeroFamily

set_option maxHeartbeats 10000000

def n : ℕ := 8192
def k : ℕ := 1170
def d : ℕ := 7023
def maxRadius : ℕ := 3911
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

/-- The executable grid expression is exactly the contribution expression in
the concrete flat soundness theorem. -/
theorem RefinedResult.flatBound_eq_contributions
    (result : RefinedResult) (queries : ℕ) :
    result.flatBound queries =
      result.profile.contribution
          (fieldSize - (result.g + 1)) n n 0 queries +
        result.arithmeticProfile.contribution
          fieldSize n result.e result.g queries := by
  unfold flatBound
  rw [← AgreementProfile.contribution_eq_compressedContribution,
    ← AgreementProfile.contribution_eq_compressedContribution]

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

def RefinedResult.conditions (result : RefinedResult)
    (h : result.ParametersValid) :
    RefinedSelectedMCAParameterConditions fieldSize n result.e result.g d
      result.outerM result.cutoff result.localM :=
  by
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

/-- The recorded cutoff is exactly the successor threshold consumed by the
profiled RBR theorem. -/
theorem RefinedResult.failureThreshold_succ (result : RefinedResult)
    (h : result.ParametersValid) : result.failureThreshold + 1 = result.cutoff := by
  have hcap := h.1.cap_lt
  have hradius := h.2.2.1
  unfold failureThreshold
  omega

def flatResults : List RefinedResult := [
  { targetBits := 115, openings := 122, e := maxRadius, g := 388, outerM := 560881,
    cutoff := 4281, localM := 560881 },
  { targetBits := 116, openings := 123, e := maxRadius, g := 388, outerM := 560881,
    cutoff := 4281, localM := 560881 },
  { targetBits := 117, openings := 124, e := maxRadius, g := 388, outerM := 560881,
    cutoff := 4281, localM := 560881 },
  { targetBits := 118, openings := 125, e := maxRadius, g := 388, outerM := 560881,
    cutoff := 4281, localM := 560881 },
  { targetBits := 119, openings := 126, e := maxRadius, g := 388, outerM := 560881,
    cutoff := 4281, localM := 560881 },
  { targetBits := 120, openings := 127, e := maxRadius, g := 43, outerM := 5181281,
    cutoff := 4281, localM := 5181281 },
  { targetBits := 121, openings := 128, e := maxRadius, g := 43, outerM := 5181281,
    cutoff := 4281, localM := 5181281 },
  { targetBits := 122, openings := 129, e := maxRadius, g := 43, outerM := 5181281,
    cutoff := 4282, localM := 618952 },
  { targetBits := 123, openings := 131, e := maxRadius, g := 43, outerM := 5181281,
    cutoff := 4286, localM := 136919 },
  { targetBits := 124, openings := 132, e := maxRadius, g := 43, outerM := 5181281,
    cutoff := 4282, localM := 618952 },
  { targetBits := 125, openings := 133, e := maxRadius, g := 43, outerM := 5181281,
    cutoff := 4282, localM := 618952 }
]

def rbrMCAResults : List RefinedResult := [
  { targetBits := 115, openings := 122, e := 3907, g := 910, outerM := 6461,
    cutoff := 4285, localM := 6461 },
  { targetBits := 116, openings := 123, e := 3904, g := 1024, outerM := 3214,
    cutoff := 4288, localM := 3214 },
  { targetBits := 117, openings := 125, e := 3894, g := 1024, outerM := 1340,
    cutoff := 4298, localM := 1340 },
  { targetBits := 118, openings := 126, e := 3885, g := 1024, outerM := 880,
    cutoff := 4307, localM := 880 },
  { targetBits := 119, openings := 128, e := 3862, g := 1024, outerM := 470,
    cutoff := 4330, localM := 470 },
  { targetBits := 120, openings := 132, e := 3803, g := 1024, outerM := 216,
    cutoff := 4389, localM := 216 },
  { targetBits := 121, openings := 138, e := 3701, g := 1024, outerM := 113,
    cutoff := 4491, localM := 113 }
]

theorem flatResults_valid : flatResults.all RefinedResult.flatValidBool = true := by
  native_decide

theorem rbrMCAResults_valid :
    rbrMCAResults.all RefinedResult.rbrValidBool = true := by
  native_decide

/-- At the RBR optima the local certificate degenerates to the outer one.
The improvement over the old RBR grid is therefore due to optimizing `e` and
`g`, not to a strictly smaller agreement-local tail. -/
theorem rbrMCAResults_local_eq_outer :
    ∀ result ∈ rbrMCAResults,
      result.cutoff = n - result.e ∧ result.localM = result.outerM := by
  native_decide

structure UDRNumericResult where
  targetBits : ℕ
  openings : ℕ

def udrRadius : ℕ := (d - 1) / 2
def udrCover : ℕ := n - udrRadius - 1

def UDRNumericResult.flatBound (_result : UDRNumericResult) (queries : ℕ) : ℚ :=
  hypergeometricRatio udrCover n queries + 1 / fieldSize

def UDRNumericResult.challengeBound (_result : UDRNumericResult) : ℚ := 1 / fieldSize

def UDRNumericResult.queryBound (_result : UDRNumericResult) (queries : ℕ) : ℚ :=
  hypergeometricRatio udrCover n queries

def UDRNumericResult.RBRValid (result : UDRNumericResult) : Prop :=
  2 * udrRadius < d ∧
    result.challengeBound ≤ (1 : ℚ) / 2 ^ result.targetBits ∧
    result.queryBound result.openings ≤ (1 : ℚ) / 2 ^ result.targetBits ∧
    (1 : ℚ) / 2 ^ result.targetBits < result.queryBound (result.openings - 1)

def UDRNumericResult.FlatValid (result : UDRNumericResult) : Prop :=
  2 * udrRadius < d ∧
    result.flatBound result.openings ≤ (1 : ℚ) / 2 ^ result.targetBits ∧
    (1 : ℚ) / 2 ^ result.targetBits < result.flatBound (result.openings - 1)

def UDRNumericResult.rbrValidBool (result : UDRNumericResult) : Bool :=
  @decide result.RBRValid (by unfold RBRValid; infer_instance)

def UDRNumericResult.flatValidBool (result : UDRNumericResult) : Bool :=
  @decide result.FlatValid (by unfold FlatValid; infer_instance)

def flatUDRNumerics : List UDRNumericResult := [
  { targetBits := 115, openings := 141 },
  { targetBits := 116, openings := 142 },
  { targetBits := 117, openings := 144 },
  { targetBits := 118, openings := 145 },
  { targetBits := 119, openings := 146 },
  { targetBits := 120, openings := 147 },
  { targetBits := 121, openings := 149 },
  { targetBits := 122, openings := 150 },
  { targetBits := 123, openings := 151 },
  { targetBits := 124, openings := 152 },
  { targetBits := 125, openings := 154 }
]

def rbrUDRNumerics : List UDRNumericResult := [
  { targetBits := 115, openings := 141 },
  { targetBits := 116, openings := 142 },
  { targetBits := 117, openings := 144 },
  { targetBits := 118, openings := 145 },
  { targetBits := 119, openings := 146 },
  { targetBits := 120, openings := 147 },
  { targetBits := 121, openings := 148 },
  { targetBits := 122, openings := 150 },
  { targetBits := 123, openings := 151 },
  { targetBits := 124, openings := 152 },
  { targetBits := 125, openings := 153 }
]

theorem rbrUDRNumerics_valid :
    rbrUDRNumerics.all UDRNumericResult.rbrValidBool = true := by
  native_decide

theorem flatUDRNumerics_valid :
    flatUDRNumerics.all UDRNumericResult.flatValidBool = true := by
  native_decide

inductive Regime where
  | selectedMCA
  | refinedMCA
  | udr
deriving DecidableEq, Repr

structure SideBySide where
  targetBits : ℕ
  flatRegime : Regime
  flatOpenings : ℕ
  rbrRegime : Regime
  rbrOpenings : ℕ
deriving DecidableEq, Repr

/-- Search-optimized comparison, conditional on the UDR interface for rows
marked `udr`.  UDR first wins the RBR column at 122 bits; ordinary selected
MCA with reoptimized radius and residual size wins at 120 and 121 bits. -/
def sideBySide : List SideBySide := [
  ⟨115, .selectedMCA, 122, .selectedMCA, 122⟩,
  ⟨116, .selectedMCA, 123, .selectedMCA, 123⟩,
  ⟨117, .selectedMCA, 124, .selectedMCA, 125⟩,
  ⟨118, .selectedMCA, 125, .selectedMCA, 126⟩,
  ⟨119, .selectedMCA, 126, .selectedMCA, 128⟩,
  ⟨120, .selectedMCA, 127, .selectedMCA, 132⟩,
  ⟨121, .selectedMCA, 128, .selectedMCA, 138⟩,
  ⟨122, .refinedMCA, 129, .udr, 150⟩,
  ⟨123, .refinedMCA, 131, .udr, 151⟩,
  ⟨124, .refinedMCA, 132, .udr, 152⟩,
  ⟨125, .refinedMCA, 133, .udr, 153⟩
]

/-- UDR in isolation.  RBR uses a maximum of the singleton field term and the
query term, whereas flat soundness adds them; at two boundary rows that saves
one opening. -/
def udrSideBySide : List SideBySide := [
  ⟨115, .udr, 141, .udr, 141⟩,
  ⟨116, .udr, 142, .udr, 142⟩,
  ⟨117, .udr, 144, .udr, 144⟩,
  ⟨118, .udr, 145, .udr, 145⟩,
  ⟨119, .udr, 146, .udr, 146⟩,
  ⟨120, .udr, 147, .udr, 147⟩,
  ⟨121, .udr, 149, .udr, 148⟩,
  ⟨122, .udr, 150, .udr, 150⟩,
  ⟨123, .udr, 151, .udr, 151⟩,
  ⟨124, .udr, 152, .udr, 152⟩,
  ⟨125, .udr, 154, .udr, 153⟩
]

theorem sideBySide_count : sideBySide.length = 11 := by native_decide

theorem udrSideBySide_count : udrSideBySide.length = 11 := by native_decide

end Ligero.Examples.Grid.Comparison
