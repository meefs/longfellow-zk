import math

import sage.all
from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing

from circuit import Circuit, CircuitLayer, Quad
from fields import random_element


def bindeq(field, log_n, challenges):
    if log_n == 0:
        return [field.one()]
    n = 2 ** log_n
    b = [None] * n
    a = bindeq(field, log_n - 1, challenges[1:])
    for i in range(n // 2):
        b[2 * i] = (field.one() - challenges[0]) * a[i]
        b[2 * i + 1] = challenges[0] * a[i]
    return b


class SumcheckPolynomial:
    def __init__(self, p0, p2):
        self.p0 = p0
        self.p2 = p2


class LayerProof:
    def __init__(self, evals, vl, vr, vl_vr):
        self.evals = evals
        self.vl = vl
        self.vr = vr
        self.vl_vr = vl_vr


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
        layers.append(LayerProof(
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
        layers.append(LayerProof(
            evals,
            vl,
            vr,
            vl_vr,
        ))
        flattened.append(vl)
        flattened.append(vr)
        flattened.append(vl_vr)
    return (layers, flattened)
