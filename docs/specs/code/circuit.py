from __future__ import annotations

import sage.all
from sage.rings.finite_rings.element_base import FiniteRingElement

from sparse import SparseArray


class Circuit:
    def __init__(
            self,
            num_outputs: int,
            num_public_inputs: int,
            num_inputs: int,
            layers: list[CircuitLayer]) -> None:
        self.num_outputs = num_outputs
        self.log_num_outputs = num_outputs.bit_length()
        self.pub_in = num_public_inputs
        self.ninputs = num_inputs
        self.layers = layers

    def evaluate(self, inputs: list[FiniteRingElement]) -> list[list[FiniteRingElement]]:
        """
        Evaluates the circuit and returns all wire values.

        This takes in the circuit's inputs as a list of field elements. By
        convention, the first field element in the input list should be one.
        """
        field = inputs[0].parent()
        wires: list[list[FiniteRingElement]] = [[] for layer in self.layers]
        wires.append(inputs)
        for j in range(len(self.layers) - 1, -1, -1):
            layer = self.layers[j]
            inputs = wires[j + 1]
            outputs = wires[j]
            if j == 0:
                num_outputs = self.num_outputs
            else:
                num_outputs = self.layers[j - 1].nw
            outputs += [field.zero() for _ in range(num_outputs)]
            z_gates = set()
            for quad in layer.quads:
                if quad.v.is_zero():
                    z_gates.add(quad.g)
                    outputs[quad.g] += inputs[quad.h0] * inputs[quad.h1]
                else:
                    outputs[quad.g] += (
                        quad.v * inputs[quad.h0] * inputs[quad.h1]
                    )
            for g in z_gates:
                if not outputs[g].is_zero():
                    raise ValueError("In-circuit assertion failed")
        return wires


class CircuitLayer:
    def __init__(self, num_input_wires: int, quads: list[Quad], field) -> None:
        """
        Constructs a layer of a circuit.

        Arguments:
        * `num_input_wires`: Number of input wires for this layer.
        * `quads`: List of quad terms in this layer, following the
          circuit serialization conventions. A value of zero indicates
          the term is part of the Z quad instead.
        """
        self.logw = num_input_wires.bit_length()
        self.nw = num_input_wires
        self.quads = quads
        self.quad = SparseArray(field)
        self.Z = SparseArray(field)
        for quad in quads:
            if quad.v.is_zero():
                self.Z[quad.g, quad.h0, quad.h1] = quad.v.parent().one()
            else:
                self.quad[quad.g, quad.h0, quad.h1] = quad.v


class Quad:
    def __init__(self, g: int, h0: int, h1: int, v: FiniteRingElement) -> None:
        self.g = g
        self.h0 = h0
        self.h1 = h1
        self.v = v
