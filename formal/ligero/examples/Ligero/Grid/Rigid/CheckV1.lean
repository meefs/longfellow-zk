import examples.Ligero.Grid.Rigid

/-! The V1 third of the response-rigid grid's native validity check. -/

namespace Ligero.Examples.Grid.Rigid

def v1CheckedResults : List Result :=
  results.filter fun result ↦ result.variant = .v1

theorem v1_checked_results_valid :
    v1CheckedResults.all Result.validBool = true := by
  native_decide

theorem numericValid_of_mem_v1CheckedResults {result : Result}
    (hmem : result ∈ v1CheckedResults) : result.NumericValid := by
  have hall := v1_checked_results_valid
  rw [List.all_eq_true] at hall
  exact result.numericValid_of_validBool (hall result hmem)

end Ligero.Examples.Grid.Rigid
