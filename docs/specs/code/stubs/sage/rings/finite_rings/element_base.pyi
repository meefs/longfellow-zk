from typing import Self

from sage.rings.finite_rings.finite_field_base import FiniteField


class FiniteRingElement:
    def __add__(self, other: Self) -> Self: ...

    def __sub__(self, other: Self) -> Self: ...

    def __mul__(self, other: Self) -> Self: ...

    def is_zero(self) -> bool: ...

    # While this is actually defined on SageObject, we want to declare it
    # with different types depending on the child class.
    def parent(self) -> FiniteField: ...
