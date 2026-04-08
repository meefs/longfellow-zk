from sage.rings.finite_rings.element_base import FiniteRingElement


class FiniteField:
    def zero(self) -> FiniteRingElement: ...

    def one(self) -> FiniteRingElement: ...
