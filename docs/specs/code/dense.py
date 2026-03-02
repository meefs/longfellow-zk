from __future__ import annotations

import sage.all
from sage.rings.finite_rings.element_base import FiniteRingElement


class DenseArray:
    entries: list[FiniteRingElement]

    def __init__(self, field, values: list[FiniteRingElement]) -> None:
        self.field = field
        self.values = values

    def __iter__(self):
        return iter(self.values)

    def __getitem__(self, index: int) -> FiniteRingElement:
        if index < len(self.values):
            return self.values[index]
        else:
            return self.field.zero()

    def bind(self, x: FiniteRingElement) -> DenseArray:
        new = []
        for i in range(0, len(self.values), 2):
            new.append(
                (self.field.one() - x) * self[i * 2]
                + x * self[i * 2 + 1]
            )
        return DenseArray(self.field, new)
