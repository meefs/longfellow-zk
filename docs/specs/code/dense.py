from typing import Self


class DenseArray[V]:
    entries: list[V]

    def __init__(self, field, values: list[V]) -> None:
        self.field = field
        self.values = values

    def __iter__(self):
        return iter(self.values)

    def __getitem__(self, index: int) -> V:
        if index < len(self.values):
            return self.values[index]
        else:
            return self.field.zero()

    def bind(self, x: V) -> Self:
        new = []
        for i in range(0, len(self.values), 2):
            new.append(
                (self.field.one() - x) * self[i * 2]
                + x * self[i * 2 + 1]
            )
        return DenseArray(self.field, new)
