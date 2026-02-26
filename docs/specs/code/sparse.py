import collections
import copy
from typing import DefaultDict, Self


class SparseArray[V]:
    entries: DefaultDict[tuple[int, ...], V]

    def __init__(self, field) -> None:
        self.field = field
        self.entries = collections.defaultdict(field.zero)

    def __getitem__(self, key: tuple[int, ...]) -> V:
        return self.entries[key]

    def __setitem__(self, key: tuple[int, ...], value: V) -> None:
        self.entries[key] = value

    def __mul__(self, other: V) -> Self:
        result: SparseArray[tuple[int, ...], V] = SparseArray(self.field)
        for key, value in self.entries.items():
            result.entries[key] = value * other
        return result

    def __rmul__(self, other: V) -> Self:
        return self * other

    def __add__(self, other: Self) -> Self:
        result = copy.copy(self)
        for key, value in other.entries.items():
            result.entries[key] += value
        return result

    def bind(self, x: V, axis=0) -> Self:
        result = SparseArray(x.parent())
        for key, value in self.entries.items():
            new_key = key[:axis] + (key[axis] // 2,) + key[axis + 1:]
            if key[axis] & 1:
                result[new_key] += x * value
            else:
                result[new_key] += value - x * value
        return result

    def bindv(self, xs: list[V], axis=0) -> Self:
        result = self
        for x in xs:
            result = result.bind(x, axis)
        return result

    def drop_dimension(self) -> Self:
        """
        Removes the first dimension from a sparse array.

        Every nonzero element should already have a zero index along
        this dimension.
        """
        result = SparseArray(self.field)
        for key, value in self.entries.items():
            if key[0] != 0:
                raise ValueError("Tried to drop dimension with non-zero indices")
            result[key[1:]] = value
        return result
