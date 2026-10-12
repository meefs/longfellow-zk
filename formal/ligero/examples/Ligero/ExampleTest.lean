import examples.Ligero

/-! Compile-time checks at all four corners of the canonical grid data. -/

#guard_msgs (drop info) in #check Ligero.Examples.Grid.Data.N1024_R7_V1_F128_S120
#guard_msgs (drop info) in #check Ligero.Examples.Grid.Data.N8192_R15_V1_F128_S125
#guard_msgs (drop info) in #check Ligero.Examples.Grid.Tight.v1_result_count
#guard_msgs (drop info) in #check Ligero.Examples.Grid.Tight.changed_v1_count
#guard_msgs (drop info) in #check Ligero.Examples.Grid.Tight.result_table_valid
#guard_msgs (drop info) in #check Ligero.Examples.Grid.Tight.v1_results_valid
#guard_msgs (drop info) in #check Ligero.Examples.Grid.Tight.changed_v1_valid
