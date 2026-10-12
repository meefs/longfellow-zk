"""V1 certificate generation."""
from __future__ import annotations
import argparse
import math
import re
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, replace
from fractions import Fraction
from functools import lru_cache
from pathlib import Path
from typing import Callable, Sequence
NUMERICAL_RADIUS_WINDOW: int | None = 16
NUMERICAL_RESIDUAL_LIMIT: int | None = 96

@dataclass(frozen=True)
class Point:
    name: str
    n: int
    k: int
    d: int
    e: int
    field_bits: int
    target_bits: int
    interactive_openings: int

@dataclass(frozen=True)
class Result:
    point: Point
    variant: str
    e: int
    g: int
    m: int
    unique: bool
    floor: int
    openings: int
    value: 'ExactRatio'
    candidates_checked: int

@dataclass(frozen=True)
class ExactRatio:
    """An unnormalized nonnegative rational compared by integer products.

    The optimizer never constructs ``Fraction`` objects.  Keeping
    the common theorem denominator visible also makes target checks literal
    integer cross multiplications.
    """
    numerator: int
    denominator: int

    def __post_init__(self) -> None:
        if self.numerator < 0 or self.denominator <= 0:
            raise ValueError('invalid nonnegative exact ratio')

    def compare(self, other: 'ExactRatio') -> int:
        left = self.numerator * other.denominator
        right = other.numerator * self.denominator
        return (left > right) - (left < right)

    def le_target(self, target_bits: int) -> bool:
        return self.numerator * (1 << target_bits) <= self.denominator

@dataclass(frozen=True)
class IntegerProfiles:
    failure: tuple[int, ...]
    arithmetic: tuple[int, ...]
    response: tuple[int, ...]
    combined: tuple[int, ...]
    multiplied: tuple[int, ...]
    failure_denominator: int
    profile_denominator: int
    combined_denominator: int
    event_baseline: int
    minimum_floor: int

@dataclass(frozen=True)
class IntegerComponents:
    case_a_numerator: int
    failure_numerator: int
    arithmetic_numerator: int
    total_numerator: int
    total_denominator: int
    floor: int

    @property
    def ratio(self) -> ExactRatio:
        return ExactRatio(self.total_numerator, self.total_denominator)

@dataclass(frozen=True)
class Winner:
    openings: int
    value: ExactRatio
    e: int
    g: int
    m: int
    floor: int
    unique: bool
DATA_PATTERN = re.compile('^def (N\\w+_(V1)_\\w+) : (?:V1)Certificate := certificate (\\d+) (\\d+) (\\d+) (\\d+) (\\d+) (\\d+) (\\d+) (\\d+) (\\d+)$', re.MULTILINE)

def read_points(path: Path, variant: str) -> list[Point]:
    wanted = 'V1'
    points: list[Point] = []
    for match in DATA_PATTERN.finditer(path.read_text()):
        if match.group(2) != wanted:
            continue
        name = match.group(1)
        n, k, d, e, _g, _m, field_bits, target_bits, openings = map(int, match.groups()[2:])
        points.append(Point(name, n, k, d, e, field_bits, target_bits, openings))
    if len(points) != 195:
        raise RuntimeError(f'expected 195 {wanted} points, found {len(points)}')
    return points

def choose3(x: int) -> int:
    return x * (x - 1) * (x - 2) // 6 if x >= 3 else 0

def balanced_choose_three(n: int, total: int) -> int:
    low, high = divmod(total, n)
    return (n - high) * choose3(low) + high * choose3(low + 1)

@lru_cache(maxsize=1 << 20)
def direct_clique(n: int, d: int, e: int, g: int, m: int) -> bool:
    if m < 3 or not n - d < n - e:
        return False
    occupancy = n // (g + 1)
    upper = (occupancy - 2) * (m * (m - 1) // 2) // 3
    return upper * (n - e - (n - d)) + choose3(m) * (n - d) < balanced_choose_three(n, m * (n - e))

@lru_cache(maxsize=None)
def clique_threshold_row(n: int, d: int, e: int, maximum_g: int) -> tuple[int, ...]:
    """Locally sharp valid threshold for every ``g <= maximum_g``.

    The sweep starts at the largest residual and moves downward.  Lean proves
    ``DirectCliqueCondition.mono_g``: validity at a smaller residual implies
    validity at every larger one.  Therefore, once ``m`` is the first valid
    threshold at ``g + 1``, every value below ``m`` is known invalid at ``g``.

    The fuel-bounded binary search mirrors ``Certificate.binaryCliqueSearch``.
    Its result and immediate predecessor are checked exactly.  Since the Lean
    development deliberately does not assume global monotonicity in the
    rounded threshold variable ``m``, this is a numerical-search accelerator,
    not a global optimality certificate.  Any failed endpoint check falls back
    to the old exact linear scan from the theorem-backed lower bound.
    """
    thresholds = [0 for _ in range(maximum_g + 1)]
    lower_bound = 3
    for g in range(maximum_g, -1, -1):
        upper_bound = lower_bound
        while not direct_clique(n, d, e, g, upper_bound):
            upper_bound = max(upper_bound + 1, 2 * upper_bound)
            if upper_bound > 1 << 50:
                raise RuntimeError('direct-clique search did not converge')
        candidate = binary_clique_search(n, d, e, g, 64, lower_bound, upper_bound)
        if not direct_clique(n, d, e, g, candidate) or (candidate > lower_bound and direct_clique(n, d, e, g, candidate - 1)):
            candidate = lower_bound
            while not direct_clique(n, d, e, g, candidate):
                candidate += 1
                if candidate > upper_bound:
                    raise RuntimeError('binary clique endpoint failed outside its bracket')
        thresholds[g] = candidate
        lower_bound = candidate
    return tuple(thresholds)

@lru_cache(maxsize=1 << 20)
def binary_clique_search(n: int, d: int, radius: int, g: int, fuel: int, low: int, high: int) -> int:
    """Literal counterpart of `Certificate.binaryCliqueSearch`."""
    while fuel and low < high:
        middle = (low + high) // 2
        if direct_clique(n, d, radius, g, middle):
            high = middle
        else:
            low = middle + 1
        fuel -= 1
    return high

def johnson_denominator(n: int, d: int, radius: int) -> int:
    return n * d - 2 * n * radius + radius * radius

def johnson_list_bound(n: int, distance: int, radius: int) -> int:
    agreement = n - radius
    cap = n - distance
    denominator = agreement * agreement - n * cap
    if denominator <= 0:
        raise ValueError('nonpositive Johnson denominator')
    return n * (agreement - cap) // denominator

def admissible_residuals(point: Point, e: int | None=None):
    e = point.e if e is None else e
    for g in range((point.d - e - 1) // 3 + 1):
        if johnson_denominator(point.n, point.d, e + g) > 0:
            yield g

def integrated_failure_label(n: int, d: int, e: int, g: int, m: int, agreement: int) -> int:
    """Exact integer counterpart of one optimized-failure profile label."""
    radius = n - agreement
    if 3 * radius < d:
        value = 1 + radius // (g + 1)
    else:
        value = m - 1
        if radius <= e:
            local_m = binary_clique_search(n, d, radius, g, 64, 3, m)
            value = min(value, local_m - 1)
    return value

@lru_cache(maxsize=None)
def integrated_local_valid(n: int, d: int, e: int, g: int, m: int) -> bool:
    """Literal finite premise checked by `integratedLocalValidBool`."""
    for agreement in range(n - e, n + 1):
        radius = n - agreement
        local_m = m if 3 * radius < d else binary_clique_search(n, d, radius, g, 64, 3, m)
        if not direct_clique(n, d, radius, g, local_m):
            return False
        if 3 * radius >= d and direct_clique(n, d, radius, g, local_m - 1):
            return False
    return True

def failure_profile_label(point: Point, e: int, g: int, m: int, agreement: int) -> int:
    """Literal `optimizedFailureProfile.labelsAtLeast` numerator."""
    field = 1 << point.field_bits
    small_denominator = field - (g + 1)
    raw = integrated_failure_label(point.n, point.d, e, g, m, agreement)
    if agreement == point.n:
        return min(field * raw, (g + 1) * small_denominator)
    return field * raw

def failure_denominator(point: Point, g: int) -> int:
    field = 1 << point.field_bits
    return field * (field - (g + 1))

def arithmetic_label(point: Point, variant: str, e: int, g: int, agreement: int, unique: bool) -> int:
    """Exact integer counterpart of one arithmetic-profile label."""
    field = 1 << point.field_bits
    list_size = 1 if unique else johnson_list_bound(point.n, point.d, e + g)
    lam = 2 * point.k - 1
    threshold = math.isqrt(point.n * lam) + 1
    if agreement < threshold:
        return field
    denominator = agreement * agreement - point.n * lam
    return list_size * point.n * (agreement - lam) // denominator

@lru_cache(maxsize=None)
def response_floor(variant: str, n: int, k: int, d: int, e: int) -> int:
    """Least level at which every pointwise response Johnson bound is valid."""
    del variant, d
    floor = max(n - e - 1, math.isqrt(n * (k - 1)), math.isqrt(n * (2 * k - 1)))
    response_distance = n - (2 * k - 1)
    radius = n - (floor + 1)
    if floor >= n or radius >= response_distance or johnson_denominator(n, response_distance, radius) <= 0:
        raise RuntimeError('no valid response floor')
    return floor

@lru_cache(maxsize=None)
def admissible_floors(variant: str, n: int, k: int, d: int, e: int) -> tuple[int, ...]:
    """Every floor accepted by the response-radius/denominator theorem."""
    minimum = response_floor(variant, n, k, d, e)
    response_distance = n - (2 * k - 1)
    return tuple((floor for floor in range(minimum, n) if n - (floor + 1) < response_distance and johnson_denominator(n, response_distance, n - (floor + 1)) > 0))

@lru_cache(maxsize=None)
def binomial_row(n: int, queries: int) -> tuple[int, ...]:
    """The exact row ``choose(a, queries)`` for ``0 <= a <= n``.

    Rows live only for one structural optimization group; the group cleanup
    below evicts them.  The explicit zero-query branch is required when the
    predecessor of a one-opening candidate is checked.
    """
    if queries < 0 or queries > n:
        raise ValueError('integer evaluator requires 0 <= queries <= n')
    if queries == 0:
        return tuple((1 for _ in range(n + 1)))
    values = [0 for _ in range(n + 1)]
    values[queries] = 1
    for agreement in range(queries + 1, n + 1):
        numerator = values[agreement - 1] * agreement
        divisor = agreement - queries
        quotient, remainder = divmod(numerator, divisor)
        if remainder:
            raise AssertionError('nonintegral binomial recurrence')
        values[agreement] = quotient
    return tuple(values)

@lru_cache(maxsize=None)
def binomial_increment_row(n: int, queries: int) -> tuple[int, ...]:
    """Forward increments of the exact binomial row."""
    values = binomial_row(n, queries)
    increments = [values[0]]
    increments.extend((values[agreement] - values[agreement - 1] for agreement in range(1, n + 1)))
    if any((value < 0 for value in increments)):
        raise AssertionError('binomial row is not monotone')
    return tuple(increments)

@lru_cache(maxsize=None)
def integer_profiles(point: Point, variant: str, e: int, g: int, m: int, unique: bool=False) -> IntegerProfiles:
    """All theorem-facing integer labels for one rigid candidate.

    Response Johnson multiplicities are evaluated only above the first valid
    floor.  Entries below that floor are deliberately zero because neither
    the Lean raw-excess sum nor the integer suffix reads them.
    """
    n = point.n
    field = 1 << point.field_bits
    failure_den = failure_denominator(point, g)
    combined_den = failure_den * field
    minimum_floor = response_floor(variant, n, point.k, point.d, e)
    arithmetic_cap = math.isqrt(n * (2 * point.k - 1))
    event_baseline = max(n - e - 1, min(n, g + arithmetic_cap))
    failure = tuple((failure_profile_label(point, e, g, m, agreement) for agreement in range(n + 1)))
    arithmetic = tuple((arithmetic_label(point, variant, e, g, agreement, unique) for agreement in range(n + 1)))
    combined = tuple((field * failure[agreement] + failure_den * arithmetic[max(0, agreement - g)] for agreement in range(n + 1)))
    response = [0 for _ in range(n + 1)]
    response_distance = n - (2 * point.k - 1)
    for agreement in range(minimum_floor + 1, n + 1):
        response[agreement] = johnson_list_bound(n, response_distance, n - agreement)
    multiplied = tuple((response[agreement] * combined[agreement] for agreement in range(n + 1)))
    return IntegerProfiles(failure, arithmetic, tuple(response), combined, multiplied, failure_den, field, combined_den, event_baseline, minimum_floor)

def integer_components(point: Point, variant: str, e: int, g: int, m: int, queries: int, unique: bool=False) -> IntegerComponents:
    """Evaluate the exact rigid coefficient using integers only."""
    profiles = integer_profiles(point, variant, e, g, m, unique)
    binomials = binomial_row(point.n, queries)
    common_choose = binomials[point.n]
    if common_choose <= 0:
        raise AssertionError('positive central binomial denominator required')
    case_a_by_floor = integer_case_a_floor_numerators(point, variant, e, g, m, queries, unique)
    case_a_numerator, floor = min(((case_a_by_floor[candidate_floor], candidate_floor) for candidate_floor in admissible_floors(variant, point.n, point.k, point.d, e)))
    failure_numerator, arithmetic_numerator = integer_case_b_numerators(point, variant, e, g, m, queries, unique)
    total_numerator = case_a_numerator + profiles.profile_denominator * failure_numerator + profiles.failure_denominator * arithmetic_numerator
    total_denominator = common_choose * profiles.combined_denominator
    return IntegerComponents(case_a_numerator, failure_numerator, arithmetic_numerator, total_numerator, total_denominator, floor)

@lru_cache(maxsize=None)
def integer_case_a_floor_numerators(point: Point, variant: str, e: int, g: int, m: int, queries: int, unique: bool=False) -> tuple[int, ...]:
    """Globally clipped Case-A numerator for every possible floor."""
    profiles = integer_profiles(point, variant, e, g, m, unique)
    binomials = binomial_row(point.n, queries)
    common_choose = binomials[point.n]
    unclipped = integer_case_a_unclipped_floor_numerators(point, variant, e, g, m, queries, unique)
    cap = common_choose * profiles.combined_denominator
    return tuple((min(cap, numerator) for numerator in unclipped))

@lru_cache(maxsize=None)
def integer_case_a_unclipped_floor_numerators(point: Point, variant: str, e: int, g: int, m: int, queries: int, unique: bool=False) -> tuple[int, ...]:
    """Unclipped ``B_q(f) D_c + S_f`` for every floor."""
    profiles = integer_profiles(point, variant, e, g, m, unique)
    binomials = binomial_row(point.n, queries)
    increments = binomial_increment_row(point.n, queries)
    suffixes = [0 for _ in range(point.n)]
    suffix = 0
    for agreement in range(point.n, profiles.minimum_floor, -1):
        suffix += increments[agreement] * profiles.multiplied[agreement]
        suffixes[agreement - 1] = suffix
    return tuple((binomials[floor] * profiles.combined_denominator + suffixes[floor] for floor in range(point.n)))

@lru_cache(maxsize=None)
def integer_case_b_numerators(point: Point, variant: str, e: int, g: int, m: int, queries: int, unique: bool=False) -> tuple[int, int]:
    """Failure-excess and general arithmetic numerators."""
    profiles = integer_profiles(point, variant, e, g, m, unique)
    binomials = binomial_row(point.n, queries)
    increments = binomial_increment_row(point.n, queries)
    failure_numerator = sum((increments[agreement] * min(profiles.failure_denominator, profiles.failure[agreement]) for agreement in range(profiles.event_baseline + 1, point.n + 1)))
    arithmetic_numerator = 0
    previous_cover = 0
    for agreement in range(point.n + 1):
        cover = max(point.n - e - 1, min(point.n, g + agreement))
        cover_binomial = binomials[cover]
        cover_increment = cover_binomial - previous_cover
        if cover_increment < 0:
            raise AssertionError('arithmetic cover is not monotone')
        arithmetic_numerator += cover_increment * min(profiles.profile_denominator, profiles.arithmetic[agreement])
        previous_cover = cover_binomial
    return (failure_numerator, arithmetic_numerator)

@lru_cache(maxsize=None)
def integer_theorem_bound(point: Point, variant: str, e: int, g: int, m: int, queries: int, unique: bool=False) -> tuple[ExactRatio, int]:
    components = integer_components(point, variant, e, g, m, queries, unique)
    return (components.ratio, components.floor)

@lru_cache(maxsize=None)
def integer_floor_lower_bound(point: Point, variant: str, e: int, queries: int) -> ExactRatio:
    row = binomial_row(point.n, queries)
    numerator = min((row[floor] for floor in admissible_floors(variant, point.n, point.k, point.d, e)))
    return ExactRatio(numerator, row[point.n])

@lru_cache(maxsize=None)
def integer_pair_baseline_lower_bound(point: Point, variant: str, e: int, queries: int) -> ExactRatio:
    """Two unavoidable nonnegative terms of the rigid coefficient.

    Case A contains its response-floor hypergeometric term.  The arithmetic
    profile has density one through its baseline agreement cap, so summing
    that prefix of cover increments telescopes to the cover probability at
    the cap.  Dropping ``g`` from that cover gives a candidate-independent
    lower bound for every residual and route at the fixed extraction radius.
    """
    row = binomial_row(point.n, queries)
    floor = min(admissible_floors(variant, point.n, point.k, point.d, e))
    arithmetic_cap = math.isqrt(point.n * (2 * point.k - 1))
    arithmetic_cover = max(point.n - e - 1, min(point.n, arithmetic_cap))
    numerator = row[floor] + row[arithmetic_cover]
    return ExactRatio(numerator, row[point.n])

@lru_cache(maxsize=None)
def integer_arithmetic_only_lower_bound(point: Point, variant: str, e: int, g: int, queries: int, unique: bool=False) -> ExactRatio:
    """Rigid lower bound using arithmetic and the universal failure floor.

    Case A retains the exact response multiplicity times the shifted
    arithmetic profile plus the pointwise failure lower bound ``1 / |F|``,
    and is globally clipped after minimizing over all admissible floors.
    Case B retains both the corresponding telescoping failure excess and the
    full-density arithmetic prefix.  All omitted summands are nonnegative.
    """
    n = point.n
    field = 1 << point.field_bits
    row = binomial_row(n, queries)
    increments = binomial_increment_row(n, queries)
    minimum_floor = response_floor(variant, n, point.k, point.d, e)
    response_distance = n - (2 * point.k - 1)
    suffixes = [0 for _ in range(n)]
    suffix = 0
    for agreement in range(n, minimum_floor, -1):
        multiplicity = johnson_list_bound(n, response_distance, n - agreement)
        shifted = max(0, agreement - g)
        suffix += increments[agreement] * multiplicity * (arithmetic_label(point, variant, e, g, shifted, unique) + 1)
        suffixes[agreement - 1] = suffix
    case_a_cap = row[n] * field
    case_a_numerator = min((min(case_a_cap, row[floor] * field + suffixes[floor]) for floor in admissible_floors(variant, n, point.k, point.d, e)))
    arithmetic_cap = math.isqrt(n * (2 * point.k - 1))
    arithmetic_cover = max(n - e - 1, min(n, g + arithmetic_cap))
    event_baseline = arithmetic_cover
    failure_floor_numerator = row[n] - row[event_baseline]
    total_numerator = case_a_numerator + failure_floor_numerator + field * row[arithmetic_cover]
    return ExactRatio(total_numerator, row[n] * field)

@lru_cache(maxsize=None)
def integer_unit_response_lower_bound(point: Point, variant: str, e: int, g: int, queries: int, unique: bool=False) -> ExactRatio:
    """Constant-time lower bound before pointwise response enumeration.

    Every Johnson response multiplicity is at least one.  The antitone
    arithmetic profile's last shifted label therefore lower-bounds every
    Case-A layer above the least admissible response floor.
    """
    n = point.n
    field = 1 << point.field_bits
    row = binomial_row(n, queries)
    floor = min(admissible_floors(variant, n, point.k, point.d, e))
    terminal_label = arithmetic_label(point, variant, e, g, max(0, n - g), unique)
    if not 1 <= terminal_label <= field:
        raise AssertionError('arithmetic tail label is not a probability count')
    case_a_unclipped = row[floor] * field + (row[n] - row[floor]) * terminal_label
    case_a_numerator = min(row[n] * field, case_a_unclipped)
    arithmetic_cap = math.isqrt(n * (2 * point.k - 1))
    arithmetic_cover = max(n - e - 1, min(n, g + arithmetic_cap))
    total_numerator = case_a_numerator + field * row[arithmetic_cover]
    return ExactRatio(total_numerator, row[n] * field)

def winner_less(candidate: Winner, incumbent: Winner) -> bool:
    if candidate.openings != incumbent.openings:
        return candidate.openings < incumbent.openings
    comparison = candidate.value.compare(incumbent.value)
    if comparison:
        return comparison < 0
    return (candidate.e, candidate.g, candidate.m, candidate.floor, candidate.unique) < (incumbent.e, incumbent.g, incumbent.m, incumbent.floor, incumbent.unique)

@lru_cache(maxsize=None)
def hypergeometric_row(n: int, queries: int) -> tuple[Fraction, ...]:
    """All exact hypergeometric ratios for one query count.

    Starting from ``H(q) = 1 / choose(n,q)``, the exact recurrence
    ``H(a) = H(a-1) * a / (a-q)`` replaces one large binomial computation per
    agreement level.  It is only an evaluator for Lean's unchanged
    ``hypergeometricRatio`` expression.
    """
    values = [Fraction(0) for _ in range(n + 1)]
    if queries > n:
        return tuple(values)
    if queries == 0:
        return tuple((Fraction(1) for _ in range(n + 1)))
    value = Fraction(1, math.comb(n, queries))
    values[queries] = value
    for allowed in range(queries + 1, n + 1):
        value *= Fraction(allowed, allowed - queries)
        values[allowed] = value
    return tuple(values)

def hypergeometric_ratio(allowed: int, n: int, queries: int) -> Fraction:
    return hypergeometric_row(n, queries)[allowed]

def tail_contribution(point: Point, tails: Sequence[Fraction], queries: int, cover: Callable[[int], int]) -> Fraction:
    """Exact compressed layer cake from already-normalized rational tails."""
    total = hypergeometric_ratio(cover(point.n), point.n, queries) * tails[point.n]
    for agreement in range(point.n):
        difference = tails[agreement] - tails[agreement + 1]
        if difference:
            total += hypergeometric_ratio(cover(agreement), point.n, queries) * difference
    return total

@lru_cache(maxsize=None)
def case_b_tail_profiles(point: Point, variant: str, e: int, g: int, m: int, unique: bool=False) -> tuple[tuple[Fraction, ...], tuple[Fraction, ...]]:
    field = 1 << point.field_bits
    failure_den = failure_denominator(point, g)
    arithmetic_cap = math.isqrt(point.n * (2 * point.k - 1))
    baseline = max(point.n - e - 1, min(point.n, g + arithmetic_cap))
    failure_tails = [Fraction(0) for _ in range(point.n + 1)]
    for agreement in range(baseline + 1, point.n + 1):
        label = failure_profile_label(point, e, g, m, agreement)
        failure_tails[agreement] = Fraction(min(failure_den, label), failure_den)
    arithmetic_tails = [Fraction(min(field, arithmetic_label(point, variant, e, g, agreement, unique)), field) for agreement in range(point.n + 1)]
    return (tuple(failure_tails), tuple(arithmetic_tails))

@lru_cache(maxsize=None)
def case_b_components(point: Point, variant: str, e: int, g: int, m: int, queries: int, unique: bool=False) -> tuple[Fraction, Fraction]:
    failure_tails, arithmetic_tails = case_b_tail_profiles(point, variant, e, g, m, unique)
    failure = tail_contribution(point, failure_tails, queries, lambda agreement: agreement)
    arithmetic_part = tail_contribution(point, arithmetic_tails, queries, lambda agreement: max(point.n - e - 1, min(point.n, g + agreement)))
    return (failure, arithmetic_part)

def case_b_pair_bound(point: Point, variant: str, e: int, g: int, m: int, queries: int, unique: bool=False) -> Fraction:
    failure, arithmetic = case_b_components(point, variant, e, g, m, queries, unique)
    return failure + arithmetic

@lru_cache(maxsize=None)
def case_a_raw_profile(point: Point, variant: str, e: int, g: int, m: int, unique: bool=False) -> tuple[Fraction, ...]:
    n = point.n
    field = 1 << point.field_bits
    failure_den = failure_denominator(point, g)
    combined_denominator = failure_den * field
    response_distance = n - (2 * point.k - 1)
    raw_profile = [Fraction(0) for _ in range(n + 1)]
    minimum_floor = response_floor(variant, n, point.k, point.d, e)
    for agreement in range(minimum_floor + 1, n + 1):
        failure_label = failure_profile_label(point, e, g, m, agreement)
        shifted_arithmetic = arithmetic_label(point, variant, e, g, max(0, agreement - g), unique)
        combined_label = field * failure_label + failure_den * shifted_arithmetic
        multiplicity = johnson_list_bound(n, response_distance, n - agreement)
        multiplied_label = multiplicity * combined_label
        raw_profile[agreement] = Fraction(multiplied_label, combined_denominator)
    return tuple(raw_profile)

@lru_cache(maxsize=None)
def case_a_floor_excesses(point: Point, variant: str, e: int, g: int, m: int, queries: int, unique: bool=False) -> tuple[Fraction, ...]:
    """Lean's raw response excess for every floor, in one exact sweep.

    ``rawExcessContribution`` is literally the sum, over ``a > floor``, of
    the hypergeometric forward increment at ``a`` times the unclipped
    multiplied profile at ``a``.  Computing those level contributions once
    and taking suffix sums avoids rebuilding an O(n) layer cake separately
    for every admissible floor.  No candidate or floor is pruned here.
    """
    n = point.n
    minimum_floor = response_floor(variant, n, point.k, point.d, e)
    raw_profile = case_a_raw_profile(point, variant, e, g, m, unique)
    covers = hypergeometric_row(n, queries)
    level_contributions = [Fraction(0) for _ in range(n + 1)]
    previous_cover = covers[minimum_floor]
    for agreement in range(minimum_floor + 1, n + 1):
        cover = covers[agreement]
        level_contributions[agreement] = (cover - previous_cover) * raw_profile[agreement]
        previous_cover = cover
    excesses = [Fraction(0) for _ in range(n)]
    suffix = Fraction(0)
    for agreement in range(n, minimum_floor, -1):
        suffix += level_contributions[agreement]
        excesses[agreement - 1] = suffix
    return tuple(excesses)

def case_a_response_excess(point: Point, variant: str, e: int, g: int, m: int, floor: int, queries: int, unique: bool=False) -> Fraction:
    """Lean's raw response-agreement excess, with no pointwise clipping."""
    return case_a_floor_excesses(point, variant, e, g, m, queries, unique)[floor]

def rigid_bound(point: Point, variant: str, e: int, g: int, m: int, floor: int, queries: int, unique: bool=False) -> Fraction:
    pair = case_b_pair_bound(point, variant, e, g, m, queries, unique)
    response_excess = case_a_response_excess(point, variant, e, g, m, floor, queries, unique)
    case_a = min(Fraction(1), hypergeometric_ratio(floor, point.n, queries) + response_excess)
    return case_a + pair

@lru_cache(maxsize=None)
def theorem_bound(point: Point, variant: str, e: int, g: int, m: int, queries: int, unique: bool=False) -> tuple[Fraction, int]:
    """Exact compiler bound minimized over every theorem-admissible floor."""
    pair = case_b_pair_bound(point, variant, e, g, m, queries, unique)
    excesses = case_a_floor_excesses(point, variant, e, g, m, queries, unique)
    return min(((min(Fraction(1), hypergeometric_ratio(floor, point.n, queries) + excesses[floor]) + pair, floor) for floor in admissible_floors(variant, point.n, point.k, point.d, e)))

@lru_cache(maxsize=None)
def floor_lower_bound(point: Point, variant: str, e: int, queries: int) -> Fraction:
    """Certified candidate-independent lower bound on the rigid coefficient.

    This is the minimum floor term over every admissible floor.  Its use is
    justified by ``Result.floorTerm_le_workNormalizedBound``.
    """
    return min((hypergeometric_ratio(floor, point.n, queries) for floor in admissible_floors(variant, point.n, point.k, point.d, e)))

def exhaustive_residuals(point: Point, e: int, unique: bool, maximum_g: int | None=None):
    """Every theorem-admissible ``g``; no occupancy/list frontier pruning."""
    residuals = tuple((g for g in admissible_residuals(point, e) if maximum_g is None or g <= maximum_g))
    if not residuals:
        return
    thresholds = clique_threshold_row(point.n, point.d, e, residuals[-1])
    for g in residuals:
        if unique and (not 2 * (e + g) < point.d):
            continue
        m = thresholds[g]
        yield (g, m)

def formula_point(point: Point) -> Point:
    """Canonical cache key for rows sharing one numerical formula."""
    return replace(point, name='formula', target_bits=0, interactive_openings=0)

def optimize_group(points: list[Point], variant: str) -> list[Result]:
    """Numerically optimize target bits in one shared integer-only pass.

    Candidate bounds and target decisions are exact.  The lower-bound screens
    and binary opening search are search accelerators, not a proof that the
    returned row is globally optimal; emitted rows are independently checked
    by Lean's theorem-facing expression.
    """
    if not points:
        return []
    shape = (points[0].n, points[0].k, points[0].d, points[0].e, points[0].field_bits)
    if any(((point.n, point.k, point.d, point.e, point.field_bits) != shape for point in points)):
        raise ValueError('optimize_group received unlike structural points')
    model = formula_point(points[0])
    numerical_variant = variant
    target_bits_set = {point.target_bits for point in points}
    best: dict[int, Winner] = {}
    candidates_checked = 0
    for unique in (False, True):
        maximum_e = min(model.e, (model.d - 1) // 2) if unique else model.e
        minimum_e = 0 if NUMERICAL_RADIUS_WINDOW is None else max(0, maximum_e - NUMERICAL_RADIUS_WINDOW + 1)
        for e in range(maximum_e, minimum_e - 1, -1):
            residuals = tuple((g for g in admissible_residuals(model, e) if not unique or 2 * (e + g) < model.d if NUMERICAL_RESIDUAL_LIMIT is None or g < NUMERICAL_RESIDUAL_LIMIT))
            candidates_checked += len(residuals)
            active_targets = {target_bits for target_bits in target_bits_set if (winner := best.get(target_bits)) is None or (winner.openings > 1 and integer_pair_baseline_lower_bound(model, numerical_variant, e, winner.openings - 1).le_target(target_bits))}
            if not active_targets:
                continue
            maximum_g = None if NUMERICAL_RESIDUAL_LIMIT is None else NUMERICAL_RESIDUAL_LIMIT - 1
            for g, m in exhaustive_residuals(model, e, unique, maximum_g):
                for target_bits in active_targets:
                    winner = best.get(target_bits)
                    high = model.n if winner is None else winner.openings - 1
                    if high < 1:
                        continue
                    if not integer_pair_baseline_lower_bound(model, numerical_variant, e, high).le_target(target_bits):
                        continue
                    if not integer_unit_response_lower_bound(model, numerical_variant, e, g, high, unique).le_target(target_bits):
                        continue
                    if not integer_arithmetic_only_lower_bound(model, numerical_variant, e, g, high, unique).le_target(target_bits):
                        continue
                    high_value, high_floor = integer_theorem_bound(model, numerical_variant, e, g, m, high, unique)
                    if not high_value.le_target(target_bits):
                        continue
                    low = 1
                    while low < high:
                        middle = (low + high) // 2
                        value, floor = integer_theorem_bound(model, numerical_variant, e, g, m, middle, unique)
                        if value.le_target(target_bits):
                            high = middle
                            high_value = value
                            high_floor = floor
                        else:
                            low = middle + 1
                    value, floor = integer_theorem_bound(model, numerical_variant, e, g, m, low, unique)
                    candidate = Winner(low, value, e, g, m, floor, unique)
                    if winner is None or winner_less(candidate, winner):
                        if integrated_local_valid(model.n, model.d, e, g, m):
                            best[target_bits] = candidate
                case_b_tail_profiles.cache_clear()
                case_b_components.cache_clear()
                case_a_raw_profile.cache_clear()
                case_a_floor_excesses.cache_clear()
                theorem_bound.cache_clear()
                integer_profiles.cache_clear()
                integer_case_a_unclipped_floor_numerators.cache_clear()
                integer_case_a_floor_numerators.cache_clear()
                integer_case_b_numerators.cache_clear()
                integer_theorem_bound.cache_clear()
    results: list[Result] = []
    for point in points:
        winner = best.get(point.target_bits)
        if winner is None:
            raise RuntimeError(f'no theorem-feasible residual for {point.name}')
        openings, value, e, g, m, floor, unique = (winner.openings, winner.value, winner.e, winner.g, winner.m, winner.floor, winner.unique)
        results.append(Result(point, variant, e, g, m, unique, floor, openings, value, candidates_checked))
    return results

def optimize(point: Point, variant: str) -> Result:
    return optimize_group([point], variant)[0]

def emit_lean(results: list[Result]) -> None:
    for result in results:
        print(f'  {{ variant := .{result.variant}\n    certificate := Ligero.Examples.Grid.Data.{result.point.name}\n    overrideE := true\n    e := {result.e}\n    g := {result.g}\n    m := {result.m}\n    floor := {result.floor}\n    overrideFloor := true\n    openings := {result.openings}\n    unique := {str(result.unique).lower()} }},')

def exact_bit_interval(value: Fraction) -> str:
    """Exact dyadic bracket; no logarithm or floating-point conversion."""
    if value == 0:
        return '0'
    if value < 0:
        raise ValueError('negative bound component')
    bits = max(0, value.denominator.bit_length() - value.numerator.bit_length())
    while value <= Fraction(1, 1 << bits + 1):
        bits += 1
    while bits and Fraction(1, 1 << bits) < value:
        bits -= 1
    return f'2^-{bits + 1} < x <= 2^-{bits}'

def print_decomposition(point: Point, variant: str, e: int, g: int, m: int, queries: int, unique: bool, requested_floor: int | None) -> None:
    if requested_floor is None:
        total, floor = theorem_bound(point, variant, e, g, m, queries, unique)
    else:
        floor = requested_floor
        total = rigid_bound(point, variant, e, g, m, floor, queries, unique)
    floor_term = hypergeometric_ratio(floor, point.n, queries)
    response_excess = case_a_response_excess(point, variant, e, g, m, floor, queries, unique)
    case_a = min(Fraction(1), floor_term + response_excess)
    failure, arithmetic = case_b_components(point, variant, e, g, m, queries, unique)
    components = (('floor', floor_term), ('case_a_response_excess', response_excess), ('case_a', case_a), ('case_b_failure_excess', failure), ('case_b_arithmetic', arithmetic), ('case_b', failure + arithmetic), ('total', total), ('target', Fraction(1, 1 << point.target_bits)))
    print(f'point={point.name} variant={variant} e={e} g={g} m={m} floor={floor} openings={queries} unique={unique}')
    for label, value in components:
        print(f'{label}: {value.numerator}/{value.denominator}')
        print(f'{label}_dyadic: {exact_bit_interval(value)}')
    print(f'passes_target: {total <= Fraction(1, 1 << point.target_bits)}')

def clear_formula_caches() -> None:
    direct_clique.cache_clear()
    binary_clique_search.cache_clear()
    response_floor.cache_clear()
    admissible_floors.cache_clear()
    floor_lower_bound.cache_clear()
    integer_floor_lower_bound.cache_clear()
    integer_pair_baseline_lower_bound.cache_clear()
    integer_arithmetic_only_lower_bound.cache_clear()
    integer_unit_response_lower_bound.cache_clear()
    binomial_row.cache_clear()
    binomial_increment_row.cache_clear()
    integer_profiles.cache_clear()
    integer_case_a_unclipped_floor_numerators.cache_clear()
    integer_case_a_floor_numerators.cache_clear()
    integer_case_b_numerators.cache_clear()
    integer_theorem_bound.cache_clear()
    hypergeometric_row.cache_clear()
    case_b_tail_profiles.cache_clear()
    case_b_components.cache_clear()
    case_a_raw_profile.cache_clear()
    case_a_floor_excesses.cache_clear()
    theorem_bound.cache_clear()

def optimize_group_job(job: tuple[list[Point], str]) -> list[Result]:
    group, variant = job
    clear_formula_caches()
    results = optimize_group(group, variant)
    clear_formula_caches()
    return results

def optimize_point_job(job: tuple[Point, str]) -> Result:
    point, variant = job
    clear_formula_caches()
    result = optimize(point, variant)
    clear_formula_caches()
    return result

def optimize_all(points: list[Point], variant: str, jobs: int=1) -> list[Result]:
    grouped: dict[tuple[int, int, int, int, int], list[Point]] = {}
    for point in points:
        shape = (point.n, point.k, point.d, point.e, point.field_bits)
        grouped.setdefault(shape, []).append(point)
    groups = list(grouped.values())
    if jobs == 1:
        grouped_results = [optimize_group_job((group, variant)) for group in groups]
        by_name = {result.point.name: result for group_results in grouped_results for result in group_results}
    else:
        with ProcessPoolExecutor(max_workers=jobs) as executor:
            point_results = list(executor.map(optimize_point_job, ((point, variant) for point in points), chunksize=1))
        by_name = {result.point.name: result for result in point_results}
    return [by_name[point.name] for point in points]

def main() -> None:
    repository = Path(__file__).resolve().parents[4]
    parser = argparse.ArgumentParser()
    parser.add_argument('--variant', choices=('v1',), required=True)
    parser.add_argument('--name')
    parser.add_argument('--decompose-openings', type=int)
    parser.add_argument('--decompose-e', type=int)
    parser.add_argument('--decompose-g', type=int)
    parser.add_argument('--decompose-m', type=int)
    parser.add_argument('--decompose-floor', type=int)
    parser.add_argument('--decompose-unique', action='store_true')
    parser.add_argument('--jobs', type=int, default=1, help='independent structural groups to optimize in parallel')
    parser.add_argument('--radius-window', type=int, default=16, help='top extraction radii searched per route; 0 searches every radius (slow, required only for exhaustive numerical search)')
    parser.add_argument('--residual-limit', type=int, default=96, help='number of residuals g=0,... searched at each radius; 0 searches every residual (slow, required only for exhaustive numerical search)')
    parser.add_argument('--data', type=Path, default=repository / 'ligero/examples/Ligero/Grid/Data.lean')
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    if args.radius_window < 0:
        parser.error('--radius-window must be nonnegative')
    if args.residual_limit < 0:
        parser.error('--residual-limit must be nonnegative')
    global NUMERICAL_RADIUS_WINDOW, NUMERICAL_RESIDUAL_LIMIT
    NUMERICAL_RADIUS_WINDOW = args.radius_window or None
    NUMERICAL_RESIDUAL_LIMIT = args.residual_limit or None
    variants = (args.variant,)
    results: list[Result] = []
    completed: dict[str, list[Result]] = {}
    for variant in variants:
        points = read_points(args.data, variant)
        if args.name:
            points = [point for point in points if point.name == args.name]
            if not points:
                parser.error(f'unknown point {args.name} for {variant}')
        if args.decompose_openings is not None:
            if len(variants) != 1 or len(points) != 1:
                parser.error('decomposition requires one --variant and one --name')
            if None in (args.decompose_e, args.decompose_g, args.decompose_m):
                parser.error('decomposition requires --decompose-e/g/m')
            print_decomposition(points[0], variant, args.decompose_e, args.decompose_g, args.decompose_m, args.decompose_openings, args.decompose_unique, args.decompose_floor)
            return
        variant_results = optimize_all(points, variant, args.jobs)
        completed[variant] = variant_results
        results.extend(variant_results)
    emit_lean(results)
if __name__ == '__main__':
    main()
