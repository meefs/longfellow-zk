import examples.Ligero.Grid

/-! Shared arithmetic facts for generated opening-count certificates. -/

namespace Ligero.Examples.Grid.Generated

open Ligero.Common

set_option maxHeartbeats 1000000

theorem config_p000_lineBound :
    SelectedMCA.directLineFailureBound 603595 = 603594 := by
  native_decide

theorem config_p000_listSize :
    CodingTheory.InterleavedJohnson.listBound 1024 879 (490 + 2) =
      2 := by
  native_decide

theorem config_p000_v1Threshold :
    Nat.sqrt (1024 * (2 * 146 - 1)) + 1 = 546 := by
  native_decide

theorem config_p000_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 1024 490 2 879
      603595 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p000_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 1024 490 2 879
      603595 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p001_lineBound :
    SelectedMCA.directLineFailureBound 257445 = 257444 := by
  native_decide

theorem config_p001_listSize :
    CodingTheory.InterleavedJohnson.listBound 1024 879 (490 + 6) =
      3 := by
  native_decide

theorem config_p001_v1Threshold :
    Nat.sqrt (1024 * (2 * 146 - 1)) + 1 = 546 := by
  native_decide

theorem config_p001_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 1024 490 6 879
      257445 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p002_lineBound :
    SelectedMCA.directLineFailureBound 300048 = 300047 := by
  native_decide

theorem config_p002_listSize :
    CodingTheory.InterleavedJohnson.listBound 1024 879 (490 + 5) =
      2 := by
  native_decide

theorem config_p002_v1Threshold :
    Nat.sqrt (1024 * (2 * 146 - 1)) + 1 = 546 := by
  native_decide

theorem config_p002_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 1024 490 5 879
      300048 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p003_lineBound :
    SelectedMCA.directLineFailureBound 225493 = 225492 := by
  native_decide

theorem config_p003_listSize :
    CodingTheory.InterleavedJohnson.listBound 1024 879 (490 + 7) =
      3 := by
  native_decide

theorem config_p003_v1Threshold :
    Nat.sqrt (1024 * (2 * 146 - 1)) + 1 = 546 := by
  native_decide

theorem config_p003_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 1024 490 7 879
      225493 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p004_lineBound :
    SelectedMCA.directLineFailureBound 127861 = 127860 := by
  native_decide

theorem config_p004_listSize :
    CodingTheory.InterleavedJohnson.listBound 1024 879 (490 + 13) =
      3 := by
  native_decide

theorem config_p004_v1Threshold :
    Nat.sqrt (1024 * (2 * 146 - 1)) + 1 = 546 := by
  native_decide

theorem config_p004_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 1024 490 13 879
      127861 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p005_lineBound :
    SelectedMCA.directLineFailureBound 111885 = 111884 := by
  native_decide

theorem config_p005_listSize :
    CodingTheory.InterleavedJohnson.listBound 1024 879 (490 + 15) =
      3 := by
  native_decide

theorem config_p005_v1Threshold :
    Nat.sqrt (1024 * (2 * 146 - 1)) + 1 = 546 := by
  native_decide

theorem config_p005_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 1024 490 15 879
      111885 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p006_lineBound :
    SelectedMCA.directLineFailureBound 26678 = 26677 := by
  native_decide

theorem config_p006_listSize :
    CodingTheory.InterleavedJohnson.listBound 1024 879 (490 + 63) =
      4 := by
  native_decide

theorem config_p006_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 1024 490 63 879
      26678 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p006_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 1024 490 63 879
      26678 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p007_lineBound :
    SelectedMCA.directLineFailureBound 888342 = 888341 := by
  native_decide

theorem config_p007_listSize :
    CodingTheory.InterleavedJohnson.listBound 2048 1757 (979 + 6) =
      2 := by
  native_decide

theorem config_p007_v1Threshold :
    Nat.sqrt (2048 * (2 * 292 - 1)) + 1 = 1093 := by
  native_decide

theorem config_p007_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 2048 979 6 1757
      888342 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p008_lineBound :
    SelectedMCA.directLineFailureBound 515948 = 515947 := by
  native_decide

theorem config_p008_listSize :
    CodingTheory.InterleavedJohnson.listBound 2048 1757 (979 + 11) =
      3 := by
  native_decide

theorem config_p008_v1Threshold :
    Nat.sqrt (2048 * (2 * 292 - 1)) + 1 = 1093 := by
  native_decide

theorem config_p008_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 2048 979 11 1757
      515948 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p009_lineBound :
    SelectedMCA.directLineFailureBound 363327 = 363326 := by
  native_decide

theorem config_p009_listSize :
    CodingTheory.InterleavedJohnson.listBound 2048 1757 (979 + 16) =
      3 := by
  native_decide

theorem config_p009_v1Threshold :
    Nat.sqrt (2048 * (2 * 292 - 1)) + 1 = 1093 := by
  native_decide

theorem config_p009_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 2048 979 16 1757
      363327 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p010_lineBound :
    SelectedMCA.directLineFailureBound 293121 = 293120 := by
  native_decide

theorem config_p010_listSize :
    CodingTheory.InterleavedJohnson.listBound 2048 1757 (979 + 20) =
      3 := by
  native_decide

theorem config_p010_v1Threshold :
    Nat.sqrt (2048 * (2 * 292 - 1)) + 1 = 1093 := by
  native_decide

theorem config_p010_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 2048 979 20 1757
      293121 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p011_lineBound :
    SelectedMCA.directLineFailureBound 268702 = 268701 := by
  native_decide

theorem config_p011_listSize :
    CodingTheory.InterleavedJohnson.listBound 2048 1757 (979 + 22) =
      3 := by
  native_decide

theorem config_p011_v1Threshold :
    Nat.sqrt (2048 * (2 * 292 - 1)) + 1 = 1093 := by
  native_decide

theorem config_p011_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 2048 979 22 1757
      268702 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p012_lineBound :
    SelectedMCA.directLineFailureBound 198497 = 198496 := by
  native_decide

theorem config_p012_listSize :
    CodingTheory.InterleavedJohnson.listBound 2048 1757 (979 + 30) =
      3 := by
  native_decide

theorem config_p012_v1Threshold :
    Nat.sqrt (2048 * (2 * 292 - 1)) + 1 = 1093 := by
  native_decide

theorem config_p012_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 2048 979 30 1757
      198497 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p013_lineBound :
    SelectedMCA.directLineFailureBound 39771 = 39770 := by
  native_decide

theorem config_p013_listSize :
    CodingTheory.InterleavedJohnson.listBound 2048 1757 (979 + 141) =
      4 := by
  native_decide

theorem config_p013_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 2048 979 141 1757
      39771 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p013_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 2048 979 141 1757
      39771 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p014_lineBound :
    SelectedMCA.directLineFailureBound 44364 = 44363 := by
  native_decide

theorem config_p014_listSize :
    CodingTheory.InterleavedJohnson.listBound 2048 1913 (1220 + 86) =
      4 := by
  native_decide

theorem config_p014_v1Threshold :
    Nat.sqrt (2048 * (2 * 136 - 1)) + 1 = 745 := by
  native_decide

theorem config_p014_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 2048 1220 86 1913
      44364 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p014_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 2048 1220 86 1913
      44364 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p015_lineBound :
    SelectedMCA.directLineFailureBound 50452 = 50451 := by
  native_decide

theorem config_p015_listSize :
    CodingTheory.InterleavedJohnson.listBound 2048 1913 (1220 + 77) =
      4 := by
  native_decide

theorem config_p015_v1Threshold :
    Nat.sqrt (2048 * (2 * 136 - 1)) + 1 = 745 := by
  native_decide

theorem config_p015_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 2048 1220 77 1913
      50452 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p015_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 2048 1220 77 1913
      50452 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p016_lineBound :
    SelectedMCA.directLineFailureBound 17986 = 17985 := by
  native_decide

theorem config_p016_listSize :
    CodingTheory.InterleavedJohnson.listBound 2048 1913 (1220 + 195) =
      8 := by
  native_decide

theorem config_p016_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 2048 1220 195 1913
      17986 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p016_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 2048 1220 195 1913
      17986 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p017_lineBound :
    SelectedMCA.directLineFailureBound 36248 = 36247 := by
  native_decide

theorem config_p017_listSize :
    CodingTheory.InterleavedJohnson.listBound 2048 1913 (1220 + 103) =
      4 := by
  native_decide

theorem config_p017_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 2048 1220 103 1913
      36248 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p018_lineBound :
    SelectedMCA.directLineFailureBound 20016 = 20015 := by
  native_decide

theorem config_p018_listSize :
    CodingTheory.InterleavedJohnson.listBound 2048 1913 (1220 + 173) =
      6 := by
  native_decide

theorem config_p018_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 2048 1220 173 1913
      20016 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p019_lineBound :
    SelectedMCA.directLineFailureBound 26103 = 26102 := by
  native_decide

theorem config_p019_listSize :
    CodingTheory.InterleavedJohnson.listBound 2048 1913 (1220 + 142) =
      5 := by
  native_decide

theorem config_p019_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 2048 1220 142 1913
      26103 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p020_lineBound :
    SelectedMCA.directLineFailureBound 1363010 = 1363009 := by
  native_decide

theorem config_p020_listSize :
    CodingTheory.InterleavedJohnson.listBound 3072 2635 (1468 + 8) =
      2 := by
  native_decide

theorem config_p020_v1Threshold :
    Nat.sqrt (3072 * (2 * 438 - 1)) + 1 = 1640 := by
  native_decide

theorem config_p020_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 3072 1468 8 2635
      1363010 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p021_lineBound :
    SelectedMCA.directLineFailureBound 717641 = 717640 := by
  native_decide

theorem config_p021_listSize :
    CodingTheory.InterleavedJohnson.listBound 3072 2635 (1468 + 16) =
      2 := by
  native_decide

theorem config_p021_v1Threshold :
    Nat.sqrt (3072 * (2 * 438 - 1)) + 1 = 1640 := by
  native_decide

theorem config_p021_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 3072 1468 16 2635
      717641 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p022_lineBound :
    SelectedMCA.directLineFailureBound 529241 = 529240 := by
  native_decide

theorem config_p022_listSize :
    CodingTheory.InterleavedJohnson.listBound 3072 2635 (1468 + 22) =
      3 := by
  native_decide

theorem config_p022_v1Threshold :
    Nat.sqrt (3072 * (2 * 438 - 1)) + 1 = 1640 := by
  native_decide

theorem config_p022_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 3072 1468 22 2635
      529241 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p023_lineBound :
    SelectedMCA.directLineFailureBound 449071 = 449070 := by
  native_decide

theorem config_p023_listSize :
    CodingTheory.InterleavedJohnson.listBound 3072 2635 (1468 + 26) =
      3 := by
  native_decide

theorem config_p023_v1Threshold :
    Nat.sqrt (3072 * (2 * 438 - 1)) + 1 = 1640 := by
  native_decide

theorem config_p023_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 3072 1468 26 2635
      449071 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p024_lineBound :
    SelectedMCA.directLineFailureBound 300756 = 300755 := by
  native_decide

theorem config_p024_listSize :
    CodingTheory.InterleavedJohnson.listBound 3072 2635 (1468 + 39) =
      3 := by
  native_decide

theorem config_p024_v1Threshold :
    Nat.sqrt (3072 * (2 * 438 - 1)) + 1 = 1640 := by
  native_decide

theorem config_p024_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 3072 1468 39 2635
      300756 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p025_lineBound :
    SelectedMCA.directLineFailureBound 260671 = 260670 := by
  native_decide

theorem config_p025_listSize :
    CodingTheory.InterleavedJohnson.listBound 3072 2635 (1468 + 45) =
      3 := by
  native_decide

theorem config_p025_v1Threshold :
    Nat.sqrt (3072 * (2 * 438 - 1)) + 1 = 1640 := by
  native_decide

theorem config_p025_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 3072 1468 45 2635
      260671 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p026_lineBound :
    SelectedMCA.directLineFailureBound 40203 = 40202 := by
  native_decide

theorem config_p026_listSize :
    CodingTheory.InterleavedJohnson.listBound 3072 2635 (1468 + 272) =
      6 := by
  native_decide

theorem config_p026_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 3072 1468 272 2635
      40203 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p026_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 3072 1468 272 2635
      40203 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p027_lineBound :
    SelectedMCA.directLineFailureBound 76280 = 76279 := by
  native_decide

theorem config_p027_listSize :
    CodingTheory.InterleavedJohnson.listBound 3072 2635 (1468 + 146) =
      4 := by
  native_decide

theorem config_p027_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 3072 1468 146 2635
      76280 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p028_lineBound :
    SelectedMCA.directLineFailureBound 2099216 = 2099215 := by
  native_decide

theorem config_p028_listSize :
    CodingTheory.InterleavedJohnson.listBound 3072 2869 (1830 + 117) =
      4 := by
  native_decide

theorem config_p028_v1Threshold :
    Nat.sqrt (3072 * (2 * 204 - 1)) + 1 = 1119 := by
  native_decide

theorem config_p028_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 3072 1830 117 2869
      2099216 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p028_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 3072 1830 117 2869
      2099216 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p029_lineBound :
    SelectedMCA.directLineFailureBound 2099216 = 2099215 := by
  native_decide

theorem config_p029_listSize :
    CodingTheory.InterleavedJohnson.listBound 3072 2869 (1830 + 117) =
      4 := by
  native_decide

theorem config_p029_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 3072 1830 117 2869
      2099216 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p029_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 3072 1830 117 2869
      2099216 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p030_lineBound :
    SelectedMCA.directLineFailureBound 1886405 = 1886404 := by
  native_decide

theorem config_p030_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3512 (1956 + 22) =
      3 := by
  native_decide

theorem config_p030_v1Threshold :
    Nat.sqrt (4096 * (2 * 585 - 1)) + 1 = 2189 := by
  native_decide

theorem config_p030_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 4096 1956 22 3512
      1886405 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p031_lineBound :
    SelectedMCA.directLineFailureBound 2547069 = 2547068 := by
  native_decide

theorem config_p031_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3512 (1956 + 16) =
      2 := by
  native_decide

theorem config_p031_v1Threshold :
    Nat.sqrt (4096 * (2 * 585 - 1)) + 1 = 2189 := by
  native_decide

theorem config_p031_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 4096 1956 16 3512
      2547069 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p032_lineBound :
    SelectedMCA.directLineFailureBound 1726567 = 1726566 := by
  native_decide

theorem config_p032_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3512 (1956 + 24) =
      3 := by
  native_decide

theorem config_p032_v1Threshold :
    Nat.sqrt (4096 * (2 * 585 - 1)) + 1 = 2189 := by
  native_decide

theorem config_p032_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 4096 1956 24 3512
      1726567 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p033_lineBound :
    SelectedMCA.directLineFailureBound 959344 = 959343 := by
  native_decide

theorem config_p033_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3512 (1956 + 44) =
      3 := by
  native_decide

theorem config_p033_v1Threshold :
    Nat.sqrt (4096 * (2 * 585 - 1)) + 1 = 2189 := by
  native_decide

theorem config_p033_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 4096 1956 44 3512
      959344 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p034_lineBound :
    SelectedMCA.directLineFailureBound 767539 = 767538 := by
  native_decide

theorem config_p034_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3512 (1956 + 55) =
      3 := by
  native_decide

theorem config_p034_v1Threshold :
    Nat.sqrt (4096 * (2 * 585 - 1)) + 1 = 2189 := by
  native_decide

theorem config_p034_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 4096 1956 55 3512
      767539 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p035_lineBound :
    SelectedMCA.directLineFailureBound 170810 = 170809 := by
  native_decide

theorem config_p035_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3512 (1956 + 230) =
      4 := by
  native_decide

theorem config_p035_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 4096 1956 230 3512
      170810 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p035_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 4096 1956 230 3512
      170810 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p036_lineBound :
    SelectedMCA.directLineFailureBound 219884 = 219883 := by
  native_decide

theorem config_p036_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3824 (2437 + 156) =
      4 := by
  native_decide

theorem config_p036_v1Threshold :
    Nat.sqrt (4096 * (2 * 273 - 1)) + 1 = 1495 := by
  native_decide

theorem config_p036_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 4096 2437 156 3824
      219884 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p036_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 4096 2437 156 3824
      219884 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p037_lineBound :
    SelectedMCA.directLineFailureBound 69551 = 69550 := by
  native_decide

theorem config_p037_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3824 (2437 + 447) =
      10 := by
  native_decide

theorem config_p037_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 4096 2437 447 3824
      69551 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p037_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 4096 2437 447 3824
      69551 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p038_lineBound :
    SelectedMCA.directLineFailureBound 87237 = 87236 := by
  native_decide

theorem config_p038_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3824 (2437 + 347) =
      7 := by
  native_decide

theorem config_p038_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 4096 2437 347 3824
      87237 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p039_lineBound :
    SelectedMCA.directLineFailureBound 122610 = 122609 := by
  native_decide

theorem config_p039_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3824 (2437 + 260) =
      5 := by
  native_decide

theorem config_p039_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 4096 2437 260 3824
      122610 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p040_lineBound :
    SelectedMCA.directLineFailureBound 3015927 = 3015926 := by
  native_decide

theorem config_p040_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 17) =
      2 := by
  native_decide

theorem config_p040_v1Threshold :
    Nat.sqrt (5120 * (2 * 731 - 1)) + 1 = 2736 := by
  native_decide

theorem config_p040_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 5120 2445 17 4390
      3015927 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p041_lineBound :
    SelectedMCA.directLineFailureBound 1865093 = 1865092 := by
  native_decide

theorem config_p041_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 28) =
      3 := by
  native_decide

theorem config_p041_v1Threshold :
    Nat.sqrt (5120 * (2 * 731 - 1)) + 1 = 2736 := by
  native_decide

theorem config_p041_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 5120 2445 28 4390
      1865093 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p042_lineBound :
    SelectedMCA.directLineFailureBound 1385579 = 1385578 := by
  native_decide

theorem config_p042_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 38) =
      3 := by
  native_decide

theorem config_p042_v1Threshold :
    Nat.sqrt (5120 * (2 * 731 - 1)) + 1 = 2736 := by
  native_decide

theorem config_p042_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 5120 2445 38 4390
      1385579 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p043_lineBound :
    SelectedMCA.directLineFailureBound 1225741 = 1225740 := by
  native_decide

theorem config_p043_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 43) =
      3 := by
  native_decide

theorem config_p043_v1Threshold :
    Nat.sqrt (5120 * (2 * 731 - 1)) + 1 = 2736 := by
  native_decide

theorem config_p043_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 5120 2445 43 4390
      1225741 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p044_lineBound :
    SelectedMCA.directLineFailureBound 778194 = 778193 := by
  native_decide

theorem config_p044_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 68) =
      3 := by
  native_decide

theorem config_p044_v1Threshold :
    Nat.sqrt (5120 * (2 * 731 - 1)) + 1 = 2736 := by
  native_decide

theorem config_p044_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 5120 2445 68 4390
      778194 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p045_lineBound :
    SelectedMCA.directLineFailureBound 597045 = 597044 := by
  native_decide

theorem config_p045_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 88) =
      3 := by
  native_decide

theorem config_p045_v1Threshold :
    Nat.sqrt (5120 * (2 * 731 - 1)) + 1 = 2736 := by
  native_decide

theorem config_p045_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 5120 2445 88 4390
      597045 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p046_lineBound :
    SelectedMCA.directLineFailureBound 138842 = 138841 := by
  native_decide

theorem config_p046_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 352) =
      4 := by
  native_decide

theorem config_p046_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 5120 2445 352 4390
      138842 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p046_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 5120 2445 352 4390
      138842 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p047_lineBound :
    SelectedMCA.directLineFailureBound 288024 = 288023 := by
  native_decide

theorem config_p047_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 176) =
      3 := by
  native_decide

theorem config_p047_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 5120 2445 176 4390
      288024 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p048_lineBound :
    SelectedMCA.directLineFailureBound 124247 = 124246 := by
  native_decide

theorem config_p048_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4780 (3046 + 205) =
      4 := by
  native_decide

theorem config_p048_v1Threshold :
    Nat.sqrt (5120 * (2 * 341 - 1)) + 1 = 1868 := by
  native_decide

theorem config_p048_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 5120 3046 205 4780
      124247 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p048_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 5120 3046 205 4780
      124247 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p049_lineBound :
    SelectedMCA.directLineFailureBound 118813 = 118812 := by
  native_decide

theorem config_p049_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4780 (3046 + 216) =
      4 := by
  native_decide

theorem config_p049_v1Threshold :
    Nat.sqrt (5120 * (2 * 341 - 1)) + 1 = 1868 := by
  native_decide

theorem config_p049_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 5120 3046 216 4780
      118813 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p049_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 5120 3046 216 4780
      118813 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p050_lineBound :
    SelectedMCA.directLineFailureBound 42738 = 42737 := by
  native_decide

theorem config_p050_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4780 (3046 + 558) =
      10 := by
  native_decide

theorem config_p050_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 5120 3046 558 4780
      42738 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p050_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 5120 3046 558 4780
      42738 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p051_lineBound :
    SelectedMCA.directLineFailureBound 75342 = 75341 := by
  native_decide

theorem config_p051_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4780 (3046 + 325) =
      5 := by
  native_decide

theorem config_p051_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 5120 3046 325 4780
      75342 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p052_lineBound :
    SelectedMCA.directLineFailureBound 1907717 = 1907716 := by
  native_decide

theorem config_p052_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 33) =
      3 := by
  native_decide

theorem config_p052_v1Threshold :
    Nat.sqrt (6144 * (2 * 877 - 1)) + 1 = 3282 := by
  native_decide

theorem config_p052_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 6144 2934 33 5268
      1907717 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p053_lineBound :
    SelectedMCA.directLineFailureBound 2238049 = 2238048 := by
  native_decide

theorem config_p053_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 28) =
      2 := by
  native_decide

theorem config_p053_v1Threshold :
    Nat.sqrt (6144 * (2 * 877 - 1)) + 1 = 3282 := by
  native_decide

theorem config_p053_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 6144 2934 28 5268
      2238049 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p054_lineBound :
    SelectedMCA.directLineFailureBound 1705255 = 1705254 := by
  native_decide

theorem config_p054_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 37) =
      3 := by
  native_decide

theorem config_p054_v1Threshold :
    Nat.sqrt (6144 * (2 * 877 - 1)) + 1 = 3282 := by
  native_decide

theorem config_p054_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 6144 2934 37 5268
      1705255 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p055_lineBound :
    SelectedMCA.directLineFailureBound 1023279 = 1023278 := by
  native_decide

theorem config_p055_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 62) =
      3 := by
  native_decide

theorem config_p055_v1Threshold :
    Nat.sqrt (6144 * (2 * 877 - 1)) + 1 = 3282 := by
  native_decide

theorem config_p055_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 6144 2934 62 5268
      1023279 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p056_lineBound :
    SelectedMCA.directLineFailureBound 895409 = 895408 := by
  native_decide

theorem config_p056_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 71) =
      3 := by
  native_decide

theorem config_p056_v1Threshold :
    Nat.sqrt (6144 * (2 * 877 - 1)) + 1 = 3282 := by
  native_decide

theorem config_p056_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 6144 2934 71 5268
      895409 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p057_lineBound :
    SelectedMCA.directLineFailureBound 629012 = 629011 := by
  native_decide

theorem config_p057_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 100) =
      3 := by
  native_decide

theorem config_p057_v1Threshold :
    Nat.sqrt (6144 * (2 * 877 - 1)) + 1 = 3282 := by
  native_decide

theorem config_p057_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 6144 2934 100 5268
      629012 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p058_lineBound :
    SelectedMCA.directLineFailureBound 106874 = 106873 := by
  native_decide

theorem config_p058_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 544) =
      6 := by
  native_decide

theorem config_p058_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 6144 2934 544 5268
      106874 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p058_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 6144 2934 544 5268
      106874 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p059_lineBound :
    SelectedMCA.directLineFailureBound 245401 = 245400 := by
  native_decide

theorem config_p059_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 253) =
      3 := by
  native_decide

theorem config_p059_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 6144 2934 253 5268
      245401 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p060_lineBound :
    SelectedMCA.directLineFailureBound 98844 = 98843 := by
  native_decide

theorem config_p060_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5736 (3655 + 246) =
      4 := by
  native_decide

theorem config_p060_v1Threshold :
    Nat.sqrt (6144 * (2 * 409 - 1)) + 1 = 2241 := by
  native_decide

theorem config_p060_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 6144 3655 246 5736
      98844 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p060_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 6144 3655 246 5736
      98844 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p061_lineBound :
    SelectedMCA.directLineFailureBound 94521 = 94520 := by
  native_decide

theorem config_p061_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5736 (3655 + 260) =
      4 := by
  native_decide

theorem config_p061_v1Threshold :
    Nat.sqrt (6144 * (2 * 409 - 1)) + 1 = 2241 := by
  native_decide

theorem config_p061_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 6144 3655 260 5736
      94521 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p061_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 6144 3655 260 5736
      94521 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p062_lineBound :
    SelectedMCA.directLineFailureBound 34001 = 34000 := by
  native_decide

theorem config_p062_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5736 (3655 + 670) =
      10 := by
  native_decide

theorem config_p062_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 6144 3655 670 5736
      34001 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p062_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 6144 3655 670 5736
      34001 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p063_lineBound :
    SelectedMCA.directLineFailureBound 38324 = 38323 := by
  native_decide

theorem config_p063_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5736 (3655 + 586) =
      8 := by
  native_decide

theorem config_p063_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 6144 3655 586 5736
      38324 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p064_lineBound :
    SelectedMCA.directLineFailureBound 77230 = 77229 := by
  native_decide

theorem config_p064_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5736 (3655 + 312) =
      4 := by
  native_decide

theorem config_p064_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 6144 3655 312 5736
      77230 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p065_lineBound :
    SelectedMCA.directLineFailureBound 7869514 = 7869513 := by
  native_decide

theorem config_p065_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 28) =
      2 := by
  native_decide

theorem config_p065_v1Threshold :
    Nat.sqrt (8192 * (2 * 1170 - 1)) + 1 = 4378 := by
  native_decide

theorem config_p065_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 8192 3911 28 7023
      7869514 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p066_lineBound :
    SelectedMCA.directLineFailureBound 5069271 = 5069270 := by
  native_decide

theorem config_p066_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 44) =
      3 := by
  native_decide

theorem config_p066_v1Threshold :
    Nat.sqrt (8192 * (2 * 1170 - 1)) + 1 = 4378 := by
  native_decide

theorem config_p066_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 8192 3911 44 7023
      5069271 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p067_lineBound :
    SelectedMCA.directLineFailureBound 3781159 = 3781158 := by
  native_decide

theorem config_p067_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 59) =
      3 := by
  native_decide

theorem config_p067_v1Threshold :
    Nat.sqrt (8192 * (2 * 1170 - 1)) + 1 = 4378 := by
  native_decide

theorem config_p067_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 8192 3911 59 7023
      3781159 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p068_lineBound :
    SelectedMCA.directLineFailureBound 3109101 = 3109100 := by
  native_decide

theorem config_p068_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 72) =
      3 := by
  native_decide

theorem config_p068_v1Threshold :
    Nat.sqrt (8192 * (2 * 1170 - 1)) + 1 = 4378 := by
  native_decide

theorem config_p068_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 8192 3911 72 7023
      3109101 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p069_lineBound :
    SelectedMCA.directLineFailureBound 2437043 = 2437042 := by
  native_decide

theorem config_p069_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 92) =
      3 := by
  native_decide

theorem config_p069_v1Threshold :
    Nat.sqrt (8192 * (2 * 1170 - 1)) + 1 = 4378 := by
  native_decide

theorem config_p069_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 8192 3911 92 7023
      2437043 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p070_lineBound :
    SelectedMCA.directLineFailureBound 1764985 = 1764984 := by
  native_decide

theorem config_p070_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 126) =
      3 := by
  native_decide

theorem config_p070_v1Threshold :
    Nat.sqrt (8192 * (2 * 1170 - 1)) + 1 = 4378 := by
  native_decide

theorem config_p070_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 8192 3911 126 7023
      1764985 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p071_lineBound :
    SelectedMCA.directLineFailureBound 364864 = 364863 := by
  native_decide

theorem config_p071_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 564) =
      4 := by
  native_decide

theorem config_p071_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 8192 3911 564 7023
      364864 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p071_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 8192 3911 564 7023
      364864 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p072_lineBound :
    SelectedMCA.directLineFailureBound 560881 = 560880 := by
  native_decide

theorem config_p072_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 383) =
      3 := by
  native_decide

theorem config_p072_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 8192 3911 383 7023
      560881 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p073_lineBound :
    SelectedMCA.directLineFailureBound 203219 = 203218 := by
  native_decide

theorem config_p073_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7647 (4872 + 347) =
      4 := by
  native_decide

theorem config_p073_v1Threshold :
    Nat.sqrt (8192 * (2 * 546 - 1)) + 1 = 2990 := by
  native_decide

theorem config_p073_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 8192 4872 347 7647
      203219 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p073_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 8192 4872 347 7647
      203219 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p074_lineBound :
    SelectedMCA.directLineFailureBound 212513 = 212512 := by
  native_decide

theorem config_p074_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7647 (4872 + 328) =
      4 := by
  native_decide

theorem config_p074_v1Threshold :
    Nat.sqrt (8192 * (2 * 546 - 1)) + 1 = 2990 := by
  native_decide

theorem config_p074_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 8192 4872 328 7647
      212513 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p074_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 8192 4872 328 7647
      212513 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p075_lineBound :
    SelectedMCA.directLineFailureBound 73101 = 73100 := by
  native_decide

theorem config_p075_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7647 (4872 + 894) =
      10 := by
  native_decide

theorem config_p075_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 8192 4872 894 7647
      73101 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p075_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 8192 4872 894 7647
      73101 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p076_lineBound :
    SelectedMCA.directLineFailureBound 119572 = 119571 := by
  native_decide

theorem config_p076_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7647 (4872 + 568) =
      5 := by
  native_decide

theorem config_p076_F128_conditions :
    SelectedMCAParameterConditions (2 ^ 128) 8192 4872 568 7647
      119572 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p077_lineBound :
    SelectedMCA.directLineFailureBound 1816008 = 1816007 := by
  native_decide

theorem config_p077_listSize :
    CodingTheory.InterleavedJohnson.listBound 1024 879 (490 + 0) =
      2 := by
  native_decide

theorem config_p077_v1Threshold :
    Nat.sqrt (1024 * (2 * 146 - 1)) + 1 = 546 := by
  native_decide

theorem config_p077_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 1024 490 0 879
      1816008 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p078_lineBound :
    SelectedMCA.directLineFailureBound 907142 = 907141 := by
  native_decide

theorem config_p078_listSize :
    CodingTheory.InterleavedJohnson.listBound 1024 879 (490 + 1) =
      2 := by
  native_decide

theorem config_p078_v1Threshold :
    Nat.sqrt (1024 * (2 * 146 - 1)) + 1 = 546 := by
  native_decide

theorem config_p078_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 1024 490 1 879
      907142 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p079_lineBound :
    SelectedMCA.directLineFailureBound 2078784 = 2078783 := by
  native_decide

theorem config_p079_listSize :
    CodingTheory.InterleavedJohnson.listBound 2048 1757 (979 + 2) =
      2 := by
  native_decide

theorem config_p079_v1Threshold :
    Nat.sqrt (2048 * (2 * 292 - 1)) + 1 = 1093 := by
  native_decide

theorem config_p079_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 2048 979 2 1757
      2078784 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p080_lineBound :
    SelectedMCA.directLineFailureBound 3074642 = 3074641 := by
  native_decide

theorem config_p080_listSize :
    CodingTheory.InterleavedJohnson.listBound 3072 2635 (1468 + 3) =
      2 := by
  native_decide

theorem config_p080_v1Threshold :
    Nat.sqrt (3072 * (2 * 438 - 1)) + 1 = 1640 := by
  native_decide

theorem config_p080_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 3072 1468 3 2635
      3074642 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p081_lineBound :
    SelectedMCA.directLineFailureBound 4100820 = 4100819 := by
  native_decide

theorem config_p081_listSize :
    CodingTheory.InterleavedJohnson.listBound 3072 2635 (1468 + 2) =
      2 := by
  native_decide

theorem config_p081_v1Threshold :
    Nat.sqrt (3072 * (2 * 438 - 1)) + 1 = 1640 := by
  native_decide

theorem config_p081_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 3072 1468 2 2635
      4100820 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p082_lineBound :
    SelectedMCA.directLineFailureBound 6153175 = 6153174 := by
  native_decide

theorem config_p082_listSize :
    CodingTheory.InterleavedJohnson.listBound 3072 2635 (1468 + 1) =
      2 := by
  native_decide

theorem config_p082_v1Threshold :
    Nat.sqrt (3072 * (2 * 438 - 1)) + 1 = 1640 := by
  native_decide

theorem config_p082_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 3072 1468 1 2635
      6153175 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p083_lineBound :
    SelectedMCA.directLineFailureBound 14534923 = 14534922 := by
  native_decide

theorem config_p083_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3512 (1956 + 2) =
      2 := by
  native_decide

theorem config_p083_v1Threshold :
    Nat.sqrt (4096 * (2 * 585 - 1)) + 1 = 2189 := by
  native_decide

theorem config_p083_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 4096 1956 2 3512
      14534923 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p084_lineBound :
    SelectedMCA.directLineFailureBound 21812883 = 21812882 := by
  native_decide

theorem config_p084_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3512 (1956 + 1) =
      2 := by
  native_decide

theorem config_p084_v1Threshold :
    Nat.sqrt (4096 * (2 * 585 - 1)) + 1 = 2189 := by
  native_decide

theorem config_p084_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 4096 1956 1 3512
      21812883 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p085_lineBound :
    SelectedMCA.directLineFailureBound 43636105 = 43636104 := by
  native_decide

theorem config_p085_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3512 (1956 + 0) =
      2 := by
  native_decide

theorem config_p085_v1Threshold :
    Nat.sqrt (4096 * (2 * 585 - 1)) + 1 = 2189 := by
  native_decide

theorem config_p085_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 4096 1956 0 3512
      43636105 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p086_lineBound :
    SelectedMCA.directLineFailureBound 3953644 = 3953643 := by
  native_decide

theorem config_p086_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3512 (1956 + 10) =
      2 := by
  native_decide

theorem config_p086_v1Threshold :
    Nat.sqrt (4096 * (2 * 585 - 1)) + 1 = 2189 := by
  native_decide

theorem config_p086_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 4096 1956 10 3512
      3953644 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p087_lineBound :
    SelectedMCA.directLineFailureBound 4347911 = 4347910 := by
  native_decide

theorem config_p087_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3512 (1956 + 9) =
      2 := by
  native_decide

theorem config_p087_v1Threshold :
    Nat.sqrt (4096 * (2 * 585 - 1)) + 1 = 2189 := by
  native_decide

theorem config_p087_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 4096 1956 9 3512
      4347911 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p088_lineBound :
    SelectedMCA.directLineFailureBound 4838081 = 4838080 := by
  native_decide

theorem config_p088_listSize :
    CodingTheory.InterleavedJohnson.listBound 4096 3512 (1956 + 8) =
      2 := by
  native_decide

theorem config_p088_v1Threshold :
    Nat.sqrt (4096 * (2 * 585 - 1)) + 1 = 2189 := by
  native_decide

theorem config_p088_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 4096 1956 8 3512
      4838081 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p089_lineBound :
    SelectedMCA.directLineFailureBound 5445466 = 5445465 := by
  native_decide

theorem config_p089_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 9) =
      2 := by
  native_decide

theorem config_p089_v1Threshold :
    Nat.sqrt (5120 * (2 * 731 - 1)) + 1 = 2736 := by
  native_decide

theorem config_p089_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 5120 2445 9 4390
      5445466 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p090_lineBound :
    SelectedMCA.directLineFailureBound 6042194 = 6042193 := by
  native_decide

theorem config_p090_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 8) =
      2 := by
  native_decide

theorem config_p090_v1Threshold :
    Nat.sqrt (5120 * (2 * 731 - 1)) + 1 = 2736 := by
  native_decide

theorem config_p090_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 5120 2445 8 4390
      6042194 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p091_lineBound :
    SelectedMCA.directLineFailureBound 6809417 = 6809416 := by
  native_decide

theorem config_p091_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 7) =
      2 := by
  native_decide

theorem config_p091_v1Threshold :
    Nat.sqrt (5120 * (2 * 731 - 1)) + 1 = 2736 := by
  native_decide

theorem config_p091_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 5120 2445 7 4390
      6809417 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p092_lineBound :
    SelectedMCA.directLineFailureBound 7779101 = 7779100 := by
  native_decide

theorem config_p092_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 6) =
      2 := by
  native_decide

theorem config_p092_v1Threshold :
    Nat.sqrt (5120 * (2 * 731 - 1)) + 1 = 2736 := by
  native_decide

theorem config_p092_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 5120 2445 6 4390
      7779101 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p093_lineBound :
    SelectedMCA.directLineFailureBound 9079117 = 9079116 := by
  native_decide

theorem config_p093_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 5) =
      2 := by
  native_decide

theorem config_p093_v1Threshold :
    Nat.sqrt (5120 * (2 * 731 - 1)) + 1 = 2736 := by
  native_decide

theorem config_p093_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 5120 2445 5 4390
      9079117 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p094_lineBound :
    SelectedMCA.directLineFailureBound 10901271 = 10901270 := by
  native_decide

theorem config_p094_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 4) =
      2 := by
  native_decide

theorem config_p094_v1Threshold :
    Nat.sqrt (5120 * (2 * 731 - 1)) + 1 = 2736 := by
  native_decide

theorem config_p094_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 5120 2445 4 4390
      10901271 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p095_lineBound :
    SelectedMCA.directLineFailureBound 13629174 = 13629173 := by
  native_decide

theorem config_p095_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 3) =
      2 := by
  native_decide

theorem config_p095_v1Threshold :
    Nat.sqrt (5120 * (2 * 731 - 1)) + 1 = 2736 := by
  native_decide

theorem config_p095_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 5120 2445 3 4390
      13629174 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p096_lineBound :
    SelectedMCA.directLineFailureBound 18168575 = 18168574 := by
  native_decide

theorem config_p096_listSize :
    CodingTheory.InterleavedJohnson.listBound 5120 4390 (2445 + 2) =
      2 := by
  native_decide

theorem config_p096_v1Threshold :
    Nat.sqrt (5120 * (2 * 731 - 1)) + 1 = 2736 := by
  native_decide

theorem config_p096_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 5120 2445 2 4390
      18168575 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p097_lineBound :
    SelectedMCA.directLineFailureBound 10901271 = 10901270 := by
  native_decide

theorem config_p097_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 5) =
      2 := by
  native_decide

theorem config_p097_v1Threshold :
    Nat.sqrt (6144 * (2 * 877 - 1)) + 1 = 3282 := by
  native_decide

theorem config_p097_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 6144 2934 5 5268
      10901271 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p098_lineBound :
    SelectedMCA.directLineFailureBound 13075069 = 13075068 := by
  native_decide

theorem config_p098_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 4) =
      2 := by
  native_decide

theorem config_p098_v1Threshold :
    Nat.sqrt (6144 * (2 * 877 - 1)) + 1 = 3282 := by
  native_decide

theorem config_p098_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 6144 2934 4 5268
      13075069 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p099_lineBound :
    SelectedMCA.directLineFailureBound 16357077 = 16357076 := by
  native_decide

theorem config_p099_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 3) =
      2 := by
  native_decide

theorem config_p099_v1Threshold :
    Nat.sqrt (6144 * (2 * 877 - 1)) + 1 = 3282 := by
  native_decide

theorem config_p099_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 6144 2934 3 5268
      16357077 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p100_lineBound :
    SelectedMCA.directLineFailureBound 21812883 = 21812882 := by
  native_decide

theorem config_p100_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 2) =
      2 := by
  native_decide

theorem config_p100_v1Threshold :
    Nat.sqrt (6144 * (2 * 877 - 1)) + 1 = 3282 := by
  native_decide

theorem config_p100_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 6144 2934 2 5268
      21812883 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p101_lineBound :
    SelectedMCA.directLineFailureBound 32724494 = 32724493 := by
  native_decide

theorem config_p101_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 1) =
      2 := by
  native_decide

theorem config_p101_v1Threshold :
    Nat.sqrt (6144 * (2 * 877 - 1)) + 1 = 3282 := by
  native_decide

theorem config_p101_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 6144 2934 1 5268
      32724494 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p102_lineBound :
    SelectedMCA.directLineFailureBound 65459328 = 65459327 := by
  native_decide

theorem config_p102_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 0) =
      2 := by
  native_decide

theorem config_p102_v1Threshold :
    Nat.sqrt (6144 * (2 * 877 - 1)) + 1 = 3282 := by
  native_decide

theorem config_p102_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 6144 2934 0 5268
      65459328 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p103_lineBound :
    SelectedMCA.directLineFailureBound 4347911 = 4347910 := by
  native_decide

theorem config_p103_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 14) =
      2 := by
  native_decide

theorem config_p103_v1Threshold :
    Nat.sqrt (6144 * (2 * 877 - 1)) + 1 = 3282 := by
  native_decide

theorem config_p103_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 6144 2934 14 5268
      4347911 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p104_lineBound :
    SelectedMCA.directLineFailureBound 5019231 = 5019230 := by
  native_decide

theorem config_p104_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 12) =
      2 := by
  native_decide

theorem config_p104_v1Threshold :
    Nat.sqrt (6144 * (2 * 877 - 1)) + 1 = 3282 := by
  native_decide

theorem config_p104_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 6144 2934 12 5268
      5019231 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p105_lineBound :
    SelectedMCA.directLineFailureBound 5445466 = 5445465 := by
  native_decide

theorem config_p105_listSize :
    CodingTheory.InterleavedJohnson.listBound 6144 5268 (2934 + 11) =
      2 := by
  native_decide

theorem config_p105_v1Threshold :
    Nat.sqrt (6144 * (2 * 877 - 1)) + 1 = 3282 := by
  native_decide

theorem config_p105_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 6144 2934 11 5268
      5445466 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p106_lineBound :
    SelectedMCA.directLineFailureBound 13441996 = 13441995 := by
  native_decide

theorem config_p106_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 16) =
      2 := by
  native_decide

theorem config_p106_v1Threshold :
    Nat.sqrt (8192 * (2 * 1170 - 1)) + 1 = 4378 := by
  native_decide

theorem config_p106_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 8192 3911 16 7023
      13441996 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p107_lineBound :
    SelectedMCA.directLineFailureBound 15262154 = 15262153 := by
  native_decide

theorem config_p107_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 14) =
      2 := by
  native_decide

theorem config_p107_v1Threshold :
    Nat.sqrt (8192 * (2 * 1170 - 1)) + 1 = 4378 := by
  native_decide

theorem config_p107_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 8192 3911 14 7023
      15262154 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p108_lineBound :
    SelectedMCA.directLineFailureBound 17614357 = 17614356 := by
  native_decide

theorem config_p108_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 12) =
      2 := by
  native_decide

theorem config_p108_v1Threshold :
    Nat.sqrt (8192 * (2 * 1170 - 1)) + 1 = 4378 := by
  native_decide

theorem config_p108_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 8192 3911 12 7023
      17614357 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p109_lineBound :
    SelectedMCA.directLineFailureBound 20806634 = 20806633 := by
  native_decide

theorem config_p109_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 10) =
      2 := by
  native_decide

theorem config_p109_v1Threshold :
    Nat.sqrt (8192 * (2 * 1170 - 1)) + 1 = 4378 := by
  native_decide

theorem config_p109_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 8192 3911 10 7023
      20806634 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p110_lineBound :
    SelectedMCA.directLineFailureBound 22906816 = 22906815 := by
  native_decide

theorem config_p110_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 9) =
      2 := by
  native_decide

theorem config_p110_v1Threshold :
    Nat.sqrt (8192 * (2 * 1170 - 1)) + 1 = 4378 := by
  native_decide

theorem config_p110_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 8192 3911 9 7023
      22906816 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p111_lineBound :
    SelectedMCA.directLineFailureBound 28647313 = 28647312 := by
  native_decide

theorem config_p111_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 7) =
      2 := by
  native_decide

theorem config_p111_v1Threshold :
    Nat.sqrt (8192 * (2 * 1170 - 1)) + 1 = 4378 := by
  native_decide

theorem config_p111_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 8192 3911 7 7023
      28647313 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p112_lineBound :
    SelectedMCA.directLineFailureBound 38196140 = 38196139 := by
  native_decide

theorem config_p112_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 5) =
      2 := by
  native_decide

theorem config_p112_v1Threshold :
    Nat.sqrt (8192 * (2 * 1170 - 1)) + 1 = 4378 := by
  native_decide

theorem config_p112_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 8192 3911 5 7023
      38196140 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p113_lineBound :
    SelectedMCA.directLineFailureBound 45840802 = 45840801 := by
  native_decide

theorem config_p113_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 4) =
      2 := by
  native_decide

theorem config_p113_v1Threshold :
    Nat.sqrt (8192 * (2 * 1170 - 1)) + 1 = 4378 := by
  native_decide

theorem config_p113_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 8192 3911 4 7023
      45840802 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

theorem config_p114_lineBound :
    SelectedMCA.directLineFailureBound 76419450 = 76419449 := by
  native_decide

theorem config_p114_listSize :
    CodingTheory.InterleavedJohnson.listBound 8192 7023 (3911 + 2) =
      2 := by
  native_decide

theorem config_p114_v1Threshold :
    Nat.sqrt (8192 * (2 * 1170 - 1)) + 1 = 4378 := by
  native_decide

theorem config_p114_F255_conditions :
    SelectedMCAParameterConditions (2 ^ 255) 8192 3911 2 7023
      76419450 := by
  refine ⟨⟨?_⟩, ⟨?_, ?_⟩, ⟨?_⟩⟩ <;> native_decide

end Ligero.Examples.Grid.Generated
