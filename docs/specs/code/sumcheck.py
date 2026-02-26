import copy
import math

import sage.all
from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing

from circuit import Circuit, CircuitLayer, Quad
from dense import DenseArray
from fields import random_element
from fs import Transcript
from sparse import SparseArray


def bindeq(field, log_n, challenges):
    if log_n == 0:
        return [field.one()]
    n = 2 ** log_n
    b = [None for _ in range(n)]
    a = bindeq(field, log_n - 1, challenges[1:])
    for i in range(n // 2):
        b[2 * i] = (field.one() - challenges[0]) * a[i]
        b[2 * i + 1] = challenges[0] * a[i]
    return b


class SumcheckPolynomial:
    def __init__(self, p0, p2):
        self.p0 = p0
        self.p2 = p2


class LayerPad:
    def __init__(self, evals, vl, vr, vl_vr):
        self.evals = evals
        self.vl = vl
        self.vr = vr
        self.vl_vr = vl_vr


class LayerProof:
    def __init__(self, evals, vl, vr):
        self.evals = evals
        self.vl = vl
        self.vr = vr


def construct_symbolic_variables(field, circuit):
    num_private_inputs = circuit.ninputs - circuit.pub_in
    witness_length = (
        num_private_inputs
        + sum(l.logw for l in circuit.layers) * 4
        + len(circuit.layers) * 3
    )
    ring = PolynomialRing(field, witness_length, "w")
    variables = ring.gens()
    witness_variables = variables[:num_private_inputs]
    pad_variables = variables[num_private_inputs:]
    return (
        witness_variables,
        construct_symbolic_pad(field, circuit, pad_variables)
    )


def construct_symbolic_pad(field, circuit, variables):
    it = iter(variables)
    layers = []
    for layer in circuit.layers:
        evals = []
        for _ in range(layer.logw):
            for _ in range(2):
                evals.append([
                    SumcheckPolynomial(
                        next(it),
                        next(it),
                    ),
                ])
        vl = next(it)
        vr = next(it)
        vl_vr = next(it)
        layers.append(LayerPad(
            evals,
            vl,
            vr,
            vl_vr,
        ))
    return layers


def construct_concrete_pad(field, circuit):
    """
    Chooses one-time pad values, and returns them in strucuted and
    flattened forms.
    """
    layers = []
    flattened = []
    for layer in circuit.layers:
        evals = []
        for _ in range(layer.nw):
            for _ in range(2):
                p0 = random_element(field)
                p2 = random_element(field)
                evals.append(SumcheckPolynomial(p0, p2))
                flattened.append(p0)
                flattened.append(p2)
        vl = random_element(field)
        vr = random_element(field)
        vl_vr = vl * vr
        layers.append(LayerPad(
            evals,
            vl,
            vr,
            vl_vr,
        ))
        flattened.append(vl)
        flattened.append(vr)
        flattened.append(vl_vr)
    return (layers, flattened)


def quadratic_constraints(pad: list[LayerPad]):
    for layer_pad in pad:
        yield layer_pad.vl, layer_pad.vr, layer_pad.vl_vr


def sumcheck_circuit(
        field,
        circuit: Circuit,
        wires: list[list],
        pad: list[LayerPad],
        transcript: Transcript) -> list[LayerProof]:
    challenges = [
        transcript.generate_field(field)
        for _ in range(circuit.lv)
    ]
    G = [challenges, copy.copy(challenges)]
    proof: list[LayerProof] = []
    for j, layer in enumerate(circuit.layers):
        alpha = transcript.generate_field(field)

        # Form the combined quad, QZ = Q + beta * Z, to handle
        # in-circuit assertions.
        beta = transcript.generate_field(field)
        QZ = layer.quad + beta * layer.Z

        # QZ is three-dimensional, QZ[g, l, r].
        QUAD = QZ.bindv(G[0]) + alpha * QZ.bindv(G[1])
        # Having bound g, QUAD is now effectively two-dimensional,
        # QUAD[l, r].
        QUAD = QUAD.drop_dimension()

        layer_proof, G = sumcheck_layer(
            field,
            QUAD,
            wires[j],
            layer.logw,
            pad[j],
            transcript,
        )
        proof.append(layer_proof)
    return proof


def sumcheck_layer(
        field,
        QUAD: SparseArray,
        wires: list,
        logw: int,
        layer_pad: LayerPad,
        transcript: Transcript) -> tuple[LayerProof, list[list]]:
    VL = DenseArray(field, wires)
    VR = DenseArray(field, wires)
    P2 = sumcheck_p2(field)
    evals = []
    G = ([], [])
    for round in range(logw):
        evals.append([])
        for hand in range(2):
            # Consider the following polynomial.
            #
            # p(x) = \sum_{l, r} bind(QUAD, x)[l, r]
            #                    * bind(VL, x)[l]
            #                    * VR[r]
            #
            # We evaluate this polynomial at the points P0 and P2. The
            # sum of p(P0) and p(P1) is implicitly known already, so
            # p(P1) does not need to be calculated.
            #
            # Implementation note: this can be computed more efficiently
            # by first computing the intermediate array defined as
            # follows:
            #
            # A[l] = \sum_{r} QUAD[l, r] * VR[r]
            #
            # This allows performing only one pass over the quad, and
            # binding only 1-D arrays with length equal to the number
            # of wires.
            eval_p0 = sum(
                v * VL[k[hand]] * VR[k[1 - hand]]
                for (k, v) in QUAD.entries.items()
                if k[hand] & 1 == 0
            )
            eval_p2 = field.zero()
            for (k, v) in QUAD.entries.items():
                if k[hand] & 1 == 0:
                    eval_p2 += (
                        (1 - P2) * v * VL[k[hand]] * VR[k[1 - hand]]
                    )
                else:
                    eval_p2 += P2 * v * VL[k[hand]] * VR[k[1 - hand]]
            evals[round].append([eval_p0, eval_p2])
            transcript.write_field(eval_p0)
            transcript.write_field(eval_p2)
            challenge = transcript.generate_field(field)
            G[hand].append(challenge)

            # Bind the current index variable to the challenge.
            VL = VL.bind(challenge)
            QUAD = QUAD.bind(challenge, axis=hand)

            # Swap VL and VR.
            (VL, VR) = (VR, VL)

    layer_proof = LayerProof(
        evals,
        VL[0] - layer_pad.vl,
        VR[0] - layer_pad.vr,
    )
    transcript.write_field_element_array([
        layer_proof.vl,
        layer_proof.vr,
    ])
    return (layer_proof, G)


def sumcheck_p2(field):
    """
    Returns the point P2 used to define sumcheck polynomials.
    """
    if field.characteristic() == 2:
        return NotImplementedError()
    else:
        return field(2)
