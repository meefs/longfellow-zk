"""V1 certificate generation."""
from __future__ import annotations
import argparse
import math
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from fractions import Fraction
from functools import lru_cache
from pathlib import Path
import numpy as np
from generate_rigid_grid import Point, arithmetic_label, exhaustive_residuals, hypergeometric_row, integrated_failure_label, johnson_list_bound, read_points

@dataclass(frozen=True)
class Result:
    point: Point
    variant: str
    g: int
    m: int
    openings: int
    value: Fraction
_approximate_cache: dict[tuple[str, int, int, int, int, int, int, int, int], float] = {}
_exact_parts_cache: dict[tuple[str, int, int, int, int, int, int, int, int], tuple[int, int]] = {}

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
def variant_arithmetic_labels(point: Point, variant: str, g: int) -> np.ndarray:
    labels = np.asarray([float(arithmetic_label(point, variant, point.e, g, agreement, False)) for agreement in range(point.n + 1)], dtype=np.float64)
    labels.setflags(write=False)
    return labels

def event_baseline(point: Point, variant: str, g: int) -> int:
    threshold = math.isqrt(point.n * (2 * point.k - 1)) + 1
    arithmetic_cap = threshold - 1
    return max(point.n - point.e - 1, min(point.n, g + arithmetic_cap))

def cover_increments(values: np.ndarray, point: Point, g: int) -> np.ndarray:
    agreements = np.arange(point.n + 1, dtype=np.int64)
    base = point.n - point.e - 1
    allowed = np.maximum(base, np.minimum(point.n, g + agreements))
    covers = values[allowed]
    increments = np.empty(point.n + 1, dtype=np.float64)
    increments[0] = covers[0]
    increments[1:] = covers[1:] - covers[:-1]
    return increments

def approximate_bound(point: Point, variant: str, g: int, m: int, queries: int) -> float:
    key = (variant, point.n, point.k, point.d, point.e, point.field_bits, g, m, queries)
    cached = _approximate_cache.get(key)
    if cached is not None:
        return cached
    values = approximate_hypergeom_row(point.n, queries)
    increments = np.empty(point.n + 1, dtype=np.float64)
    increments[0] = values[0]
    increments[1:] = values[1:] - values[:-1]
    field = 1 << point.field_bits
    failure_denominator = field - (g + 1)
    failure_tail = np.minimum(1.0, failure_labels(point.n, point.d, point.e, g, m) / float(failure_denominator))
    failure_tail[-1] = min(failure_tail[-1], (g + 1) / float(field))
    baseline = event_baseline(point, variant, g)
    failure = float(np.dot(increments[baseline + 1:], failure_tail[baseline + 1:]))
    arithmetic_tail = np.minimum(1.0, variant_arithmetic_labels(point, variant, g) / float(field))
    arithmetic = float(np.dot(cover_increments(values, point, g), arithmetic_tail))
    result = failure + arithmetic
    _approximate_cache[key] = result
    return result

def exact_bound_parts(point: Point, variant: str, g: int, m: int, queries: int) -> tuple[int, int]:
    key = (variant, point.n, point.k, point.d, point.e, point.field_bits, g, m, queries)
    cached = _exact_parts_cache.get(key)
    if cached is not None:
        return cached
    field = 1 << point.field_bits
    failure_denominator = field - (g + 1)
    failure_profile = failure_labels(point.n, point.d, point.e, g, m)
    baseline = event_baseline(point, variant, g)
    tails = [field * min(failure_denominator, int(label)) for label in failure_profile]
    tails[point.n] = min(tails[point.n], (g + 1) * failure_denominator)
    choose_total = math.comb(point.n, queries)

    def choose(allowed: int) -> int:
        if queries > allowed:
            return 0
        return math.comb(allowed, queries)
    if baseline == point.n:
        failure_numerator = 0
    else:
        failure_numerator = choose_total * tails[point.n] - choose(baseline) * tails[baseline + 1]
        for agreement in range(baseline + 1, point.n):
            difference = tails[agreement] - tails[agreement + 1]
            if difference:
                failure_numerator += choose(agreement) * difference
    list_size = johnson_list_bound(point.n, point.d, point.e + g)
    lam = 2 * point.k - 1
    threshold = math.isqrt(point.n * lam) + 1

    def arithmetic_label(agreement: int) -> int:
        if agreement < threshold:
            return field
        local_denominator = agreement * agreement - point.n * lam
        return list_size * point.n * (agreement - lam) // local_denominator
    base = point.n - point.e - 1

    def cover(agreement: int) -> int:
        return max(base, min(point.n, g + agreement))
    arithmetic_numerator = choose(cover(point.n)) * arithmetic_label(point.n) * failure_denominator
    next_label = arithmetic_label(point.n)
    for agreement in range(point.n - 1, -1, -1):
        label = arithmetic_label(agreement)
        difference = label - next_label
        if difference:
            arithmetic_numerator += choose(cover(agreement)) * difference * failure_denominator
        next_label = label
    result = (failure_numerator + arithmetic_numerator, choose_total * field * failure_denominator)
    _exact_parts_cache[key] = result
    return result

def exact_bound(point: Point, variant: str, g: int, m: int, queries: int) -> Fraction:
    numerator, denominator = exact_bound_parts(point, variant, g, m, queries)
    return Fraction(numerator, denominator)

def exact_passes(point: Point, variant: str, g: int, m: int, queries: int) -> bool:
    numerator, denominator = exact_bound_parts(point, variant, g, m, queries)
    return numerator * (1 << point.target_bits) <= denominator

def exact_candidate(point: Point, variant: str, g: int, m: int) -> Result | None:
    if not exact_passes(point, variant, g, m, point.n):
        return None
    low, high = (1, point.n)
    while low < high:
        middle = (low + high) // 2
        if exact_passes(point, variant, g, m, middle):
            high = middle
        else:
            low = middle + 1
    return Result(point, variant, g, m, low, exact_bound(point, variant, g, m, low))

def optimize(point: Point, variant: str) -> Result:
    target = 2.0 ** (-point.target_bits)
    approximate: list[tuple[int, float, int, int]] = []
    for g, m in exhaustive_residuals(point, point.e, False):
        low, high = (1, point.n)
        while low < high:
            middle = (low + high) // 2
            if approximate_bound(point, variant, g, m, middle) <= target:
                high = middle
            else:
                low = middle + 1
        approximate.append((low, approximate_bound(point, variant, g, m, low), g, m))
    if not approximate:
        raise RuntimeError(f'no flat candidate for {point.name}')
    best: Result | None = None
    for opening_hint, _value, g, m in sorted(approximate):
        candidate = exact_candidate(point, variant, g, m)
        if candidate is None:
            continue
        best = candidate
        break
    if best is None:
        raise RuntimeError(f'no theorem-feasible flat candidate for {point.name}')
    if best.openings > 1:
        for _opening_hint, _value, g, m in approximate:
            if g == best.g and m == best.m:
                continue
            if exact_passes(point, variant, g, m, best.openings - 1):
                candidate = exact_candidate(point, variant, g, m)
                if candidate is not None and (candidate.openings, candidate.g, candidate.m) < (best.openings, best.g, best.m):
                    best = candidate
    return best

def emit_lean(results: list[Result], variant: str) -> None:
    for result in results:
        print(f'  {{ certificate := Ligero.Examples.Grid.Data.{result.point.name}\n    g? := some {result.g}\n    m? := some {result.m}\n    openings := {result.openings} }},')

def main() -> None:
    repository = Path(__file__).resolve().parents[4]
    parser = argparse.ArgumentParser()
    parser.add_argument('--variant', choices=('v1',), required=True)
    parser.add_argument('--name')
    parser.add_argument('--jobs', type=int, default=1)
    parser.add_argument('--data', type=Path, default=repository / 'ligero/examples/Ligero/Grid/Data.lean')
    args = parser.parse_args()
    points = read_points(args.data, args.variant)
    if args.name:
        points = [point for point in points if point.name == args.name]
        if not points:
            parser.error(f'unknown point {args.name}')
    if args.jobs <= 1:
        results = [optimize(point, args.variant) for point in points]
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            results = list(pool.map(optimize, points, [args.variant] * len(points), chunksize=1))
    emit_lean(results, args.variant)
if __name__ == '__main__':
    main()
