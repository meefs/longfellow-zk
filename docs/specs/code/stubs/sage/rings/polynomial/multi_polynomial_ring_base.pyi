from typing import overload

from sage.rings.polynomial.multi_polynomial import MPolynomial

class MPolynomialRing_base:
    def gens(self) -> tuple[MPolynomial, ...]: ...

    # Hoisted from Ring, so we can exactly specify the return type.
    def zero(self) -> MPolynomial: ...
