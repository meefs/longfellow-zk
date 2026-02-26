import copy
import unittest

import sage.all
from sage.rings.finite_rings.finite_field_constructor import GF

from circuit import Circuit, CircuitLayer, Quad
from fs import Transcript
from sumcheck import (
    bindeq, constraints_circuit, construct_concrete_pad,
    construct_symbolic_variables, sumcheck_circuit,
)


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

    def test_smoke_test_witness(self):
        gf17 = GF(17)
        circuit = make_test_circuit(gf17)
        construct_symbolic_variables(gf17, circuit)
        construct_concrete_pad(gf17, circuit)

    def test_smoke_test_sumcheck_prover(self):
        gf17 = GF(17)
        circuit = make_test_circuit(gf17)
        transcript = Transcript()
        transcript.init(b"unit test")
        constraints_transcript = copy.deepcopy(transcript)
        inputs = [gf17.one(), gf17(2)]
        wires = circuit.evaluate(inputs)
        (pad_layers, _pad_flattened) = construct_concrete_pad(gf17, circuit)
        proof = sumcheck_circuit(
            gf17,
            circuit,
            wires,
            pad_layers,
            transcript,
        )
        sym_private_inputs, sym_pad = construct_symbolic_variables(
            gf17,
            circuit,
        )
        (_, _) = constraints_circuit(
            gf17,
            circuit,
            inputs[:1],
            sym_private_inputs,
            sym_pad,
            constraints_transcript,
            proof,
        )


def make_test_circuit(field):
    """
    Constructs a very small circuit for use in tests.

    This circuit outputs (x - 1) * (x - 2), and has an in-circuit assrtion
    checking x - 2 = 0. This circuit assumes that the field has large
    characteristic.
    """
    layer_0 = CircuitLayer(
        3,
        [
            # Propagate x^2 - 3x + 2 to output.
            # V[0][0] = 1 * V[1][1] * V[1][0]
            Quad(0, 1, 0, field(1)),
        ],
        field,
    )
    layer_1 = CircuitLayer(
        4,
        [
            # Propagate 1 to next layer.
            # V[1][0] = 1 * V[2][0] * V[2][0]
            Quad(0, 0, 0, field(1)),
            # Propagate x^2 - 3x + 2 to next layer.
            # V[1][1] = 1 * V[2][1] * V[2][0]
            Quad(1, 1, 0, field(1)),
            # Assert x - 2 = 0.
            # 0 = V[2][2] * V[2][0] + V[2][3] * V[2][0]
            Quad(2, 2, 0, field(0)),
            Quad(2, 3, 0, field(0)),
        ],
        field,
    )
    layer_2 = CircuitLayer(
        2,
        [
            # Propagate 1 to next layer.
            # V[2][0] = 1 * V[3][0] * V[3][0]
            Quad(0, 0, 0, field(1)),
            # Calculate x^2 - 3x + 2x.
            # V[2][1] = 1 * V[3][1] * V[3][1] + -3 * V[3][1] * V[3][0]
            #           + 2 * V[3][0] * V[3][0]
            Quad(1, 1, 1, field(1)),
            Quad(1, 1, 0, -field(3)),
            Quad(1, 0, 0, field(2)),
            # Propagate x to next layer (for assertion).
            # V[2][2] = 1 * V[3][1] * V[3][0]
            Quad(2, 1, 0, field(1)),
            # Calculate -2 (for assertion).
            # V[2][3] = -2 * V[3][0] * V[3][0]
            Quad(3, 0, 0, -field(2)),
        ],
        field,
    )
    return Circuit(
        1,
        1,
        2,
        [layer_0, layer_1, layer_2],
    )
