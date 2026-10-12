"""Equivalence tests for the integer-only rigid-grid evaluator.

The Fraction implementation in ``generate_rigid_grid`` is a reference oracle
only.  These tests must pass before the integer path is used to regenerate any
row.
"""
from __future__ import annotations
import math
import unittest
from fractions import Fraction
from pathlib import Path
import generate_rigid_grid as grid

def same_ratio(value: Fraction, numerator: int, denominator: int) -> bool:
    return value.numerator * denominator == numerator * value.denominator

class IntegerRigidEvaluatorTests(unittest.TestCase):
    SMALL_SHAPES = ((8, 1, 3, 1), (10, 1, 4, 1), (12, 2, 6, 2), (16, 2, 7, 2), (20, 3, 10, 3), (24, 3, 11, 3))

    def assert_fraction_equal(self, value: Fraction, numerator: int, denominator: int) -> None:
        self.assertTrue(same_ratio(value, numerator, denominator), f'{value} != {numerator}/{denominator}')

    def check_candidate(self, point: grid.Point, variant: str, e: int, g: int, m: int, unique: bool) -> None:
        profiles = grid.integer_profiles(point, variant, e, g, m, unique)
        reference_profile = grid.case_a_raw_profile(point, variant, e, g, m, unique)
        for agreement in range(point.n + 1):
            self.assertEqual(profiles.failure[agreement], grid.failure_profile_label(point, e, g, m, agreement))
            self.assertEqual(profiles.arithmetic[agreement], grid.arithmetic_label(point, variant, e, g, agreement, unique))
            expected_combined = profiles.profile_denominator * profiles.failure[agreement] + profiles.failure_denominator * grid.arithmetic_label(point, variant, e, g, max(0, agreement - g), unique)
            self.assertEqual(profiles.combined[agreement], expected_combined)
            if agreement <= profiles.minimum_floor:
                self.assertEqual(profiles.response[agreement], 0)
                self.assertEqual(reference_profile[agreement], 0)
            else:
                self.assertEqual(profiles.multiplied[agreement], profiles.response[agreement] * expected_combined)
                self.assert_fraction_equal(reference_profile[agreement], profiles.multiplied[agreement], profiles.combined_denominator)
        for queries in range(point.n + 1):
            row = grid.binomial_row(point.n, queries)
            increments = grid.binomial_increment_row(point.n, queries)
            for agreement in range(point.n + 1):
                self.assertEqual(row[agreement], math.comb(agreement, queries))
                expected_increment = row[agreement] - (row[agreement - 1] if agreement else 0)
                self.assertEqual(increments[agreement], expected_increment)
            common_choose = row[point.n]
            case_a = grid.integer_case_a_floor_numerators(point, variant, e, g, m, queries, unique)
            case_a_unclipped = grid.integer_case_a_unclipped_floor_numerators(point, variant, e, g, m, queries, unique)
            for floor in grid.admissible_floors(variant, point.n, point.k, point.d, e):
                reference_unclipped = grid.hypergeometric_ratio(floor, point.n, queries) + grid.case_a_response_excess(point, variant, e, g, m, floor, queries, unique)
                self.assert_fraction_equal(reference_unclipped, case_a_unclipped[floor], common_choose * profiles.combined_denominator)
                reference_case_a = min(Fraction(1), reference_unclipped)
                self.assert_fraction_equal(reference_case_a, case_a[floor], common_choose * profiles.combined_denominator)
            failure, arithmetic = grid.integer_case_b_numerators(point, variant, e, g, m, queries, unique)
            reference_failure, reference_arithmetic = grid.case_b_components(point, variant, e, g, m, queries, unique)
            self.assert_fraction_equal(reference_failure, failure, common_choose * profiles.failure_denominator)
            self.assert_fraction_equal(reference_arithmetic, arithmetic, common_choose * profiles.profile_denominator)
            reference_total, reference_floor = grid.theorem_bound(point, variant, e, g, m, queries, unique)
            integer_total, integer_floor = grid.integer_theorem_bound(point, variant, e, g, m, queries, unique)
            self.assertEqual(reference_floor, integer_floor)
            self.assert_fraction_equal(reference_total, integer_total.numerator, integer_total.denominator)
            pair_lower = grid.integer_pair_baseline_lower_bound(point, variant, e, queries)
            arithmetic_lower = grid.integer_arithmetic_only_lower_bound(point, variant, e, g, queries, unique)
            unit_response_lower = grid.integer_unit_response_lower_bound(point, variant, e, g, queries, unique)
            self.assertLessEqual(pair_lower.compare(integer_total), 0)
            self.assertLessEqual(unit_response_lower.compare(arithmetic_lower), 0)
            self.assertLessEqual(arithmetic_lower.compare(integer_total), 0)
            for target_bits in range(9):
                self.assertEqual(reference_total <= Fraction(1, 1 << target_bits), integer_total.le_target(target_bits))
if __name__ == '__main__':
    unittest.main()
