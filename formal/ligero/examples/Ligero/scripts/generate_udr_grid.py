"""Generate theorem-aligned, numerically optimized singleton-lift rows.

The default search uses a declared total-radius/residual neighborhood.  Lean
checks every emitted row and predecessor exactly; the table does not claim
global numerical optimality outside that neighborhood.
"""
from __future__ import annotations
import argparse
import math
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from fractions import Fraction
from functools import lru_cache
from pathlib import Path
import numpy as np
from generate_rigid_grid import Point, clique_threshold_row, hypergeometric_ratio, hypergeometric_row, integrated_failure_label, johnson_denominator, read_points
NUMERICAL_TOTAL_WINDOW: int | None = 16
NUMERICAL_RESIDUAL_LIMIT: int | None = 64

@dataclass(frozen=True)
class Result:
    point: Point
    variant: str
    e: int
    g: int
    m: int
    openings: int
    value: float

@lru_cache(maxsize=None)
def approximate_hypergeom_row(n: int, queries: int) -> np.ndarray:
    values = np.asarray([float(value) for value in hypergeometric_row(n, queries)], dtype=np.float64)
    values.setflags(write=False)
    return values

@lru_cache(maxsize=None)
def failure_labels(n: int, d: int, e: int, g: int, m: int) -> np.ndarray:
    labels = np.asarray([integrated_failure_label(n, d, e, g, m, agreement) for agreement in range(n + 1)], dtype=np.int64)
    labels.setflags(write=False)
    return labels

@lru_cache(maxsize=None)
def least_clique(n: int, d: int, e: int, g: int) -> int:
    return clique_threshold_row(n, d, e, g)[g]

@lru_cache(maxsize=None)
def singleton_arithmetic_labels(variant: str, n: int, k: int, field_bits: int):
    field = float(1 << field_bits)
    labels = np.empty(n + 1, dtype=np.float64)
    lam = 2 * k - 1
    threshold = math.isqrt(n * lam) + 1
    for agreement in range(n + 1):
        if agreement < threshold:
            labels[agreement] = field
        else:
            denominator = agreement * agreement - n * lam
            labels[agreement] = n * (agreement - lam) // denominator
    labels.setflags(write=False)
    return labels

def cover_increments(values: np.ndarray, n: int, e: int, g: int):
    agreements = np.arange(n + 1, dtype=np.int64)
    base = n - e - 1
    allowed = np.maximum(base, np.minimum(n, g + agreements))
    covers = values[allowed]
    increments = np.empty(n + 1, dtype=np.float64)
    increments[0] = covers[0]
    increments[1:] = covers[1:] - covers[:-1]
    return increments

def soundness(point: Point, variant: str, e: int, g: int, m: int, queries: int):
    values = approximate_hypergeom_row(point.n, queries)
    failure_tail = np.minimum(1.0, failure_labels(point.n, point.d, e, g, m) / float((1 << point.field_bits) - (g + 1)))
    failure_tail[-1] = min(failure_tail[-1], (g + 1) / float(1 << point.field_bits))
    threshold = math.isqrt(point.n * (2 * point.k - 1)) + 1
    baseline = max(point.n - e - 1, min(point.n, g + threshold - 1))
    increments = np.empty(point.n + 1, dtype=np.float64)
    increments[0] = values[0]
    increments[1:] = values[1:] - values[:-1]
    failure = float(np.dot(increments[baseline + 1:], failure_tail[baseline + 1:]))
    arithmetic_tail = np.minimum(1.0, singleton_arithmetic_labels(variant, point.n, point.k, point.field_bits) / float(1 << point.field_bits))
    arithmetic = float(np.dot(cover_increments(values, point.n, e, g), arithmetic_tail))
    return failure + arithmetic

def exact_soundness(point: Point, variant: str, e: int, g: int, m: int, queries: int) -> Fraction:
    labels = failure_labels(point.n, point.d, e, g, m)
    denominator = (1 << point.field_bits) - (g + 1)
    field = 1 << point.field_bits
    threshold = math.isqrt(point.n * (2 * point.k - 1)) + 1
    baseline = max(point.n - e - 1, min(point.n, g + threshold - 1))
    total = Fraction(0)
    previous = hypergeometric_ratio(baseline, point.n, queries)
    for a in range(baseline + 1, point.n + 1):
        current = hypergeometric_ratio(a, point.n, queries)
        tail = min(Fraction(1), Fraction(int(labels[a]), denominator))
        if a == point.n:
            tail = min(tail, Fraction(g + 1, field))
        total += (current - previous) * tail
        previous = current
    arithmetic = singleton_arithmetic_labels(variant, point.n, point.k, point.field_bits)
    previous = Fraction(0)
    base = point.n - e - 1
    for a in range(point.n + 1):
        allowed = max(base, min(point.n, g + a))
        current = hypergeometric_ratio(allowed, point.n, queries)
        total += (current - previous) * min(Fraction(1), Fraction(int(arithmetic[a]), field))
        previous = current
    return total

def candidate(point: Point, variant: str, e: int, g: int, best_openings: int | None) -> Result | None:
    if not 3 * g < point.d - e:
        return None
    if johnson_denominator(point.n, point.d, e + g) <= 0:
        return None
    m = least_clique(point.n, point.d, e, g)
    target = 2.0 ** (-point.target_bits)
    if best_openings is not None:
        previous = best_openings - 1
        previous_value = soundness(point, variant, e, g, m, previous)
        if previous_value > target:
            value = soundness(point, variant, e, g, m, best_openings)
            if value > target:
                return None
            return Result(point, variant, e, g, m, best_openings, value)
        high = previous
    else:
        high = point.n
    low = 1
    while low < high:
        middle = (low + high) // 2
        if soundness(point, variant, e, g, m, middle) <= target:
            high = middle
        else:
            low = middle + 1
    value = soundness(point, variant, e, g, m, low)
    return Result(point, variant, e, g, m, low, value)

def optimize(point: Point, variant: str) -> Result:
    target = 2.0 ** (-point.target_bits)
    best: Result | None = None
    candidates: list[Result] = []
    maximum_total = (point.d - 1) // 2
    minimum_total = 0 if NUMERICAL_TOTAL_WINDOW is None else max(0, maximum_total - NUMERICAL_TOTAL_WINDOW + 1)
    for total in range(maximum_total, minimum_total - 1, -1):
        if best is not None:
            optimistic = approximate_hypergeom_row(point.n, best.openings - 1)[point.n - total - 1]
            if optimistic > target:
                break
        maximum_g = min(total, (point.d - total - 1) // 2)
        if NUMERICAL_RESIDUAL_LIMIT is not None:
            maximum_g = min(maximum_g, NUMERICAL_RESIDUAL_LIMIT - 1)
        for g in range(maximum_g + 1):
            e = total - g
            result = candidate(point, variant, e, g, None if best is None else best.openings)
            if result is not None:
                candidates.append(result)
            if result is not None and (best is None or (result.openings, result.value, result.e, result.g) < (best.openings, best.value, best.e, best.g)):
                best = result
    if best is None:
        raise RuntimeError(f'no UDR candidate for {point.name}')
    exact_target = Fraction(1, 1 << point.target_bits)

    def exact_correction(result: Result) -> Result | None:
        if exact_soundness(point, variant, result.e, result.g, result.m, point.n) > exact_target:
            return None
        low, high = (1, point.n)
        while low < high:
            middle = (low + high) // 2
            if exact_soundness(point, variant, result.e, result.g, result.m, middle) <= exact_target:
                high = middle
            else:
                low = middle + 1
        exact_value = exact_soundness(point, variant, result.e, result.g, result.m, low)
        return Result(point, variant, result.e, result.g, result.m, low, float(exact_value))
    corrected = exact_correction(best)
    if corrected is not None:
        return corrected
    for result in sorted(candidates, key=lambda item: (item.openings, item.e, item.g, item.m)):
        corrected = exact_correction(result)
        if corrected is not None:
            return corrected
    raise RuntimeError(f'no theorem-feasible UDR candidate for {point.name}')

def emit_lean(results: list[Result]) -> None:
    for result in results:
        print(f'  {{ variant := .{result.variant}\n    certificate := Ligero.Examples.Grid.Data.{result.point.name}\n    e := {result.e}\n    g := {result.g}\n    m := {result.m}\n    openings := {result.openings} }},')

def optimize_all(points: list[Point], variant: str) -> list[Result]:
    results: list[Result] = []
    previous_shape: tuple[int, int, int] | None = None
    for point in points:
        shape = (point.n, point.k, point.d)
        if previous_shape is not None and shape != previous_shape:
            least_clique.cache_clear()
            failure_labels.cache_clear()
            singleton_arithmetic_labels.cache_clear()
            approximate_hypergeom_row.cache_clear()
            hypergeometric_row.cache_clear()
        results.append(optimize(point, variant))
        previous_shape = shape
    return results

def optimize_job(job: tuple[Point, str]) -> Result:
    point, variant = job
    clique_threshold_row.cache_clear()
    least_clique.cache_clear()
    failure_labels.cache_clear()
    singleton_arithmetic_labels.cache_clear()
    approximate_hypergeom_row.cache_clear()
    hypergeometric_row.cache_clear()
    result = optimize(point, variant)
    clique_threshold_row.cache_clear()
    least_clique.cache_clear()
    failure_labels.cache_clear()
    singleton_arithmetic_labels.cache_clear()
    approximate_hypergeom_row.cache_clear()
    hypergeometric_row.cache_clear()
    return result

def main() -> None:
    repository = Path(__file__).resolve().parents[4]
    parser = argparse.ArgumentParser()
    parser.add_argument('--variant', choices=('v1',), required=True)
    parser.add_argument('--name')
    parser.add_argument('--jobs', type=int, default=1)
    parser.add_argument('--total-window', type=int, default=16)
    parser.add_argument('--residual-limit', type=int, default=64)
    parser.add_argument('--data', type=Path, default=repository / 'ligero/examples/Ligero/Grid/Data.lean')
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    if args.total_window < 0 or args.residual_limit < 0:
        parser.error('numerical windows must be nonnegative')
    global NUMERICAL_TOTAL_WINDOW, NUMERICAL_RESIDUAL_LIMIT
    NUMERICAL_TOTAL_WINDOW = args.total_window or None
    NUMERICAL_RESIDUAL_LIMIT = args.residual_limit or None
    variants = (args.variant,)
    all_results: list[Result] = []
    for variant in variants:
        points = read_points(args.data, variant)
        if args.name:
            points = [point for point in points if point.name == args.name]
            if not points:
                parser.error(f'unknown point {args.name}')
        if args.jobs == 1:
            results = optimize_all(points, variant)
        else:
            with ProcessPoolExecutor(max_workers=args.jobs) as pool:
                results = list(pool.map(optimize_job, ((point, variant) for point in points), chunksize=1))
        all_results.extend(results)
    emit_lean(all_results)
if __name__ == '__main__':
    main()
