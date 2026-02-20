import unittest

import sage.all
from sage.rings.finite_rings.finite_field_constructor import GF

from sumcheck import bindeq


class TestSumcheck(unittest.TestCase):
    def test_bindeq(self):
        gf17 = GF(17)
        assert bindeq(gf17, 0, []) == [gf17.one()]
        assert bindeq(gf17, 1, [2]) == [gf17(16), gf17(2)]
        assert bindeq(gf17, 2, [2, 5]) == [
            gf17(16) * gf17(13),
            gf17(2) * gf17(13),
            gf17(16) * gf17(5),
            gf17(2) * gf17(5),
        ]

