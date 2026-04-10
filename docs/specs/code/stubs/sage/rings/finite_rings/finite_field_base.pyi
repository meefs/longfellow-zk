from typing import Any

from sage.rings.finite_rings.element_base import FiniteRingElement
from sage.rings.integer import Integer
from sage.rings.polynomial.polynomial_element import Polynomial
from sage.rings.polynomial.multi_polynomial_ring_base import MPolynomialRing_base


class FiniteField:
    def zero(self) -> FiniteRingElement: ...

    def one(self) -> FiniteRingElement: ...

    # Parent defines __call__(), which typically dispatches to
    # _element_constructor_() on the implementation-specific field class.
    def __call__(self, x: int) -> FiniteRingElement: ...

    # Hoisted from Parent.
    def __contains__(self, x: Any) -> bool: ...

    def extension(self, poly: Polynomial, name: str) -> MPolynomialRing_base: ...

    def order(self) -> Integer: ...

    def from_integer(self, n: int | Integer, reverse: bool = False): ...
