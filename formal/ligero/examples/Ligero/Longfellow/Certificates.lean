import examples.Ligero.Longfellow.FixedOpenings

set_option autoImplicit false
set_option relaxedAutoImplicit false
set_option warningAsError true

namespace Ligero.Examples.Grid.Rigid.Longfellow

/-- Parameters from the registered V7 sig circuit component. -/
def v7Sig : Result :=
  { variant := .v1
    certificate :=
      { n := 3187
        k := 455
        d := 2733
        e := 1493
        g := 0
        m := 160574
        fieldBits := 256
        fieldOrder := 115792089210356248762697446949407573530086143415290314195533631308867097853951
        targetBits := 122
        openings := 132 }
    overrideE := true
    e := 1493
    g := 0
    m := 160574
    floor := 1702
    overrideFloor := true
    openings := 132
    unique := false }

theorem v7Sig_parameters : v7Sig.ParametersValid := by
  unfold Result.ParametersValid
  native_decide

theorem v7Sig_integer_bound :
    v7Sig.integerizedTotalNumerator v7Sig.openings *
      2 ^ v7Sig.certificate.targetBits ≤
        v7Sig.integerizedTotalDenominator v7Sig.openings := by native_decide

def v7SigCertified : CertifiedResult :=
  { result := v7Sig, parameters := v7Sig_parameters,
    bound := v7Sig.bound_of_integer_upper_bound
      v7Sig_parameters v7Sig_integer_bound }

/-- Parameters from the registered V7 hash circuit component. -/
def v7Hash1 : Result :=
  { variant := .v1
    certificate :=
      { n := 3230
        k := 461
        d := 2770
        e := 1514
        g := 2
        m := 55485
        fieldBits := 128
        fieldOrder := 0
        targetBits := 121
        openings := 132 }
    overrideE := true
    e := 1514
    g := 2
    m := 55485
    floor := 1726
    overrideFloor := true
    openings := 132
    unique := false }

theorem v7Hash1_parameters : v7Hash1.ParametersValid := by
  unfold Result.ParametersValid
  native_decide

theorem v7Hash1_integer_bound :
    v7Hash1.integerizedTotalNumerator v7Hash1.openings *
      2 ^ v7Hash1.certificate.targetBits ≤
        v7Hash1.integerizedTotalDenominator v7Hash1.openings := by native_decide

def v7Hash1Certified : CertifiedResult :=
  { result := v7Hash1, parameters := v7Hash1_parameters,
    bound := v7Hash1.bound_of_integer_upper_bound
      v7Hash1_parameters v7Hash1_integer_bound }

/-- Parameters from the registered V7 hash circuit component. -/
def v7Hash2 : Result :=
  { variant := .v1
    certificate :=
      { n := 3318
        k := 474
        d := 2845
        e := 1554
        g := 2
        m := 55752
        fieldBits := 128
        fieldOrder := 0
        targetBits := 121
        openings := 132 }
    overrideE := true
    e := 1554
    g := 2
    m := 55752
    floor := 1774
    overrideFloor := true
    openings := 132
    unique := false }

theorem v7Hash2_parameters : v7Hash2.ParametersValid := by
  unfold Result.ParametersValid
  native_decide

theorem v7Hash2_integer_bound :
    v7Hash2.integerizedTotalNumerator v7Hash2.openings *
      2 ^ v7Hash2.certificate.targetBits ≤
        v7Hash2.integerizedTotalDenominator v7Hash2.openings := by native_decide

def v7Hash2Certified : CertifiedResult :=
  { result := v7Hash2, parameters := v7Hash2_parameters,
    bound := v7Hash2.bound_of_integer_upper_bound
      v7Hash2_parameters v7Hash2_integer_bound }

/-- Parameters from the registered V7 hash circuit component. -/
def v7Hash3 : Result :=
  { variant := .v1
    certificate :=
      { n := 3352
        k := 478
        d := 2875
        e := 1571
        g := 2
        m := 56438
        fieldBits := 128
        fieldOrder := 0
        targetBits := 121
        openings := 132 }
    overrideE := true
    e := 1571
    g := 2
    m := 56438
    floor := 1791
    overrideFloor := true
    openings := 132
    unique := false }

theorem v7Hash3_parameters : v7Hash3.ParametersValid := by
  unfold Result.ParametersValid
  native_decide

theorem v7Hash3_integer_bound :
    v7Hash3.integerizedTotalNumerator v7Hash3.openings *
      2 ^ v7Hash3.certificate.targetBits ≤
        v7Hash3.integerizedTotalDenominator v7Hash3.openings := by native_decide

def v7Hash3Certified : CertifiedResult :=
  { result := v7Hash3, parameters := v7Hash3_parameters,
    bound := v7Hash3.bound_of_integer_upper_bound
      v7Hash3_parameters v7Hash3_integer_bound }

/-- Parameters from the registered V7 hash circuit component. -/
def v7Hash4 : Result :=
  { variant := .v1
    certificate :=
      { n := 3436
        k := 490
        d := 2947
        e := 1610
        g := 2
        m := 57292
        fieldBits := 128
        fieldOrder := 0
        targetBits := 121
        openings := 132 }
    overrideE := true
    e := 1610
    g := 2
    m := 57292
    floor := 1836
    overrideFloor := true
    openings := 132
    unique := false }

theorem v7Hash4_parameters : v7Hash4.ParametersValid := by
  unfold Result.ParametersValid
  native_decide

theorem v7Hash4_integer_bound :
    v7Hash4.integerizedTotalNumerator v7Hash4.openings *
      2 ^ v7Hash4.certificate.targetBits ≤
        v7Hash4.integerizedTotalDenominator v7Hash4.openings := by native_decide

def v7Hash4Certified : CertifiedResult :=
  { result := v7Hash4, parameters := v7Hash4_parameters,
    bound := v7Hash4.bound_of_integer_upper_bound
      v7Hash4_parameters v7Hash4_integer_bound }

/-- Parameters from the registered V6 sig circuit component. -/
def v6Sig : Result :=
  { variant := .v1
    certificate :=
      { n := 1964
        k := 491
        d := 1474
        e := 584
        g := 0
        m := 9134
        fieldBits := 256
        fieldOrder := 115792089210356248762697446949407573530086143415290314195533631308867097853951
        targetBits := 65
        openings := 128 }
    overrideE := true
    e := 584
    g := 0
    m := 9134
    floor := 1388
    overrideFloor := true
    openings := 128
    unique := false }

theorem v6Sig_parameters : v6Sig.ParametersValid := by
  unfold Result.ParametersValid
  native_decide

theorem v6Sig_integer_bound :
    v6Sig.integerizedTotalNumerator v6Sig.openings *
      2 ^ v6Sig.certificate.targetBits ≤
        v6Sig.integerizedTotalDenominator v6Sig.openings := by native_decide

def v6SigCertified : CertifiedResult :=
  { result := v6Sig, parameters := v6Sig_parameters,
    bound := v6Sig.bound_of_integer_upper_bound
      v6Sig_parameters v6Sig_integer_bound }

/-- Parameters from the registered V6 hash circuit component. -/
def v6Hash1 : Result :=
  { variant := .v1
    certificate :=
      { n := 2733
        k := 682
        d := 2052
        e := 811
        g := 0
        m := 12580
        fieldBits := 128
        fieldOrder := 0
        targetBits := 65
        openings := 128 }
    overrideE := true
    e := 811
    g := 0
    m := 12580
    floor := 1930
    overrideFloor := true
    openings := 128
    unique := false }

theorem v6Hash1_parameters : v6Hash1.ParametersValid := by
  unfold Result.ParametersValid
  native_decide

theorem v6Hash1_integer_bound :
    v6Hash1.integerizedTotalNumerator v6Hash1.openings *
      2 ^ v6Hash1.certificate.targetBits ≤
        v6Hash1.integerizedTotalDenominator v6Hash1.openings := by native_decide

def v6Hash1Certified : CertifiedResult :=
  { result := v6Hash1, parameters := v6Hash1_parameters,
    bound := v6Hash1.bound_of_integer_upper_bound
      v6Hash1_parameters v6Hash1_integer_bound }

/-- Parameters from the registered V6 hash circuit component. -/
def v6Hash2 : Result :=
  { variant := .v1
    certificate :=
      { n := 2684
        k := 671
        d := 2014
        e := 795
        g := 0
        m := 12312
        fieldBits := 128
        fieldOrder := 0
        targetBits := 64
        openings := 128 }
    overrideE := true
    e := 795
    g := 0
    m := 12312
    floor := 1897
    overrideFloor := true
    openings := 128
    unique := false }

theorem v6Hash2_parameters : v6Hash2.ParametersValid := by
  unfold Result.ParametersValid
  native_decide

theorem v6Hash2_integer_bound :
    v6Hash2.integerizedTotalNumerator v6Hash2.openings *
      2 ^ v6Hash2.certificate.targetBits ≤
        v6Hash2.integerizedTotalDenominator v6Hash2.openings := by native_decide

def v6Hash2Certified : CertifiedResult :=
  { result := v6Hash2, parameters := v6Hash2_parameters,
    bound := v6Hash2.bound_of_integer_upper_bound
      v6Hash2_parameters v6Hash2_integer_bound }

/-- Parameters from the registered V6 hash circuit component. -/
def v6Hash3 : Result :=
  { variant := .v1
    certificate :=
      { n := 2748
        k := 687
        d := 2062
        e := 814
        g := 0
        m := 12609
        fieldBits := 128
        fieldOrder := 0
        targetBits := 64
        openings := 128 }
    overrideE := true
    e := 814
    g := 0
    m := 12609
    floor := 1942
    overrideFloor := true
    openings := 128
    unique := false }

theorem v6Hash3_parameters : v6Hash3.ParametersValid := by
  unfold Result.ParametersValid
  native_decide

theorem v6Hash3_integer_bound :
    v6Hash3.integerizedTotalNumerator v6Hash3.openings *
      2 ^ v6Hash3.certificate.targetBits ≤
        v6Hash3.integerizedTotalDenominator v6Hash3.openings := by native_decide

def v6Hash3Certified : CertifiedResult :=
  { result := v6Hash3, parameters := v6Hash3_parameters,
    bound := v6Hash3.bound_of_integer_upper_bound
      v6Hash3_parameters v6Hash3_integer_bound }

/-- Parameters from the registered V6 hash circuit component. -/
def v6Hash4 : Result :=
  { variant := .v1
    certificate :=
      { n := 2856
        k := 714
        d := 2143
        e := 846
        g := 0
        m := 13107
        fieldBits := 128
        fieldOrder := 0
        targetBits := 64
        openings := 128 }
    overrideE := true
    e := 846
    g := 0
    m := 13107
    floor := 2018
    overrideFloor := true
    openings := 128
    unique := false }

theorem v6Hash4_parameters : v6Hash4.ParametersValid := by
  unfold Result.ParametersValid
  native_decide

theorem v6Hash4_integer_bound :
    v6Hash4.integerizedTotalNumerator v6Hash4.openings *
      2 ^ v6Hash4.certificate.targetBits ≤
        v6Hash4.integerizedTotalDenominator v6Hash4.openings := by native_decide

def v6Hash4Certified : CertifiedResult :=
  { result := v6Hash4, parameters := v6Hash4_parameters,
    bound := v6Hash4.bound_of_integer_upper_bound
      v6Hash4_parameters v6Hash4_integer_bound }

end Ligero.Examples.Grid.Rigid.Longfellow
