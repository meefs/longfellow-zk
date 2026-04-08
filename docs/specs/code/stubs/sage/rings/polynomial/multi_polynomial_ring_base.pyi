from sage.rings.polynomial.multi_polynomial import MPolynomial

class MPolynomialRing_base:
    def gens(self) -> tuple[MPolynomial, ...]: ...
