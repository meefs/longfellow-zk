import examples.Ligero.Grid.Rigid.CheckV1
namespace Ligero.Examples.Grid.Rigid

theorem numericValid_of_mem_results {result : Result}
    (hmem : result ∈ results) : result.NumericValid := by
  cases hvariant : result.variant with
  | v1 =>
      apply numericValid_of_mem_v1CheckedResults
      simpa [v1CheckedResults, hvariant] using hmem
/- These rows are numerically optimized over the generator's declared
radius/residual neighborhood.  This theorem certifies soundness and the
fixed-candidate predecessor boundary for every row; it does not claim global
optimality over all extraction radii and residuals. -/
theorem results_valid : results.all Result.validBool = true := by
  rw [List.all_eq_true]
  intro result hmem
  cases hvariant : result.variant with
  | v1 =>
      have hall := v1_checked_results_valid
      rw [List.all_eq_true] at hall
      apply hall result
      simpa [v1CheckedResults, hvariant] using hmem
end Ligero.Examples.Grid.Rigid
