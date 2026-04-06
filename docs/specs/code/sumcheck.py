from typing import Any

import sage.all
from sage.rings.finite_rings.element_base import FiniteRingElement
from sage.rings.finite_rings.finite_field_base import FiniteField
from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing
from sage.rings.polynomial.multi_polynomial import MPolynomial

from circuit import Circuit
from dense import DenseArray
from fields import random_element
from fs import Transcript
from sparse import SparseArray

MAX_BINDINGS = 40


def bindeq(
        field: FiniteField,
        challenges: list[FiniteRingElement]) -> list[FiniteRingElement]:
    log_n = len(challenges)
    if log_n == 0:
        return [field.one()]
    n = 2 ** log_n
    b = [field.zero() for _ in range(n)]
    a = bindeq(field, challenges[1:])
    for i in range(n // 2):
        b[2 * i] = (field.one() - challenges[0]) * a[i]
        b[2 * i + 1] = challenges[0] * a[i]
    return b


class SumcheckPolynomial:
    def __init__(self, p0, p2):
        self.p0 = p0
        self.p2 = p2


class LayerPad:
    def __init__(
            self,
            evals: list[list[SumcheckPolynomial]],
            vl,
            vr,
            vl_vr):
        self.evals = evals
        self.vl = vl
        self.vr = vr
        self.vl_vr = vl_vr


class LayerProof:
    def __init__(
            self,
            evals: list[list[SumcheckPolynomial]],
            vl,
            vr):
        self.evals = evals
        self.vl = vl
        self.vr = vr


def construct_symbolic_variables(
        field,
        circuit: Circuit,
        ) -> tuple[tuple[MPolynomial, ...], list[LayerPad]]:
    num_private_inputs = circuit.ninputs - circuit.pub_in
    witness_length = (
        num_private_inputs
        + sum(l.log_num_input_wires for l in circuit.layers) * 4
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


def construct_symbolic_pad(
        field,
        circuit: Circuit, variables) -> list[LayerPad]:
    it = iter(variables)
    layers = []
    for layer in circuit.layers:
        evals: list[list[SumcheckPolynomial]] = []
        for round in range(layer.log_num_input_wires):
            evals.append([])
            for _ in range(2):
                evals[round].append(
                    SumcheckPolynomial(
                        next(it),
                        next(it),
                    ),
                )
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


def construct_concrete_pad(
        field: FiniteField,
        circuit: Circuit,
        pad_prg=random_element,
        ) -> tuple[list[LayerPad], list[FiniteRingElement]]:
    """
    Chooses one-time pad values, and returns them in structured and
    flattened forms.
    """
    layers = []
    flattened = []
    for layer in circuit.layers:
        evals: list[list[SumcheckPolynomial]] = []
        for round in range(layer.num_input_wires):
            evals.append([])
            for _ in range(2):
                p0 = pad_prg(field)
                p2 = pad_prg(field)
                evals[round].append(SumcheckPolynomial(p0, p2))
                flattened.append(p0)
                flattened.append(p2)
        vl = pad_prg(field)
        vr = pad_prg(field)
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


def sumcheck_circuit(
        field,
        circuit: Circuit,
        wires: list[list],
        pad: list[LayerPad],
        transcript: Transcript) -> list[LayerProof]:
    for _ in range(MAX_BINDINGS):
        # Discard initial challenges. These are reserved for possible
        # future use.
        _ = transcript.generate_field(field)
    challenges = [
        transcript.generate_field(field)
        for _ in range(MAX_BINDINGS)
    ]
    G = (
        challenges[:circuit.log_num_outputs],
        challenges[:circuit.log_num_outputs],
    )
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
            wires[j + 1],
            layer.log_num_input_wires,
            pad[j],
            transcript,
        )
        proof.append(layer_proof)
    return proof


def sumcheck_layer(
        field,
        QUAD: SparseArray,
        wires: list,
        log_num_input_wires: int,
        layer_pad: LayerPad,
        transcript: Transcript) -> tuple[LayerProof, tuple[list, list]]:
    VL = DenseArray(field, wires)
    VR = DenseArray(field, wires)
    P2 = sumcheck_p2(field)
    evals: list[list[SumcheckPolynomial]] = []
    G: tuple[list, list] = ([], [])
    for round in range(log_num_input_wires):
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
                (
                    v * VL[k[hand]] * VR[k[1 - hand]]
                    for (k, v) in QUAD.entries.items()
                    if k[hand] & 1 == 0
                ),
                start=field.zero(),
            )
            eval_p2 = field.zero()
            for (k, v) in QUAD.entries.items():
                if k[hand] & 1 == 0:
                    eval_p2 += (
                        (1 - P2) * v * VL[k[hand]] * VR[k[1 - hand]]
                    )
                else:
                    eval_p2 += P2 * v * VL[k[hand]] * VR[k[1 - hand]]
            blinded_p0 = eval_p0 - layer_pad.evals[round][hand].p0
            blinded_p2 = eval_p2 - layer_pad.evals[round][hand].p2
            evals[round].append(SumcheckPolynomial(blinded_p0, blinded_p2))
            transcript.write_field(blinded_p0)
            transcript.write_field(blinded_p2)
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


class QuadraticConstraint:
    """
    A quadratic constraint, representing x * y = z.
    """

    def __init__(self, x, y, z):
        self.x = x
        self.y = y
        self.z = z


def constraints_circuit(
        field,
        circuit: Circuit,
        public_inputs: list,
        sym_private_inputs: list,
        sym_pad: list[LayerPad],
        transcript: Transcript,
        proof: list[LayerProof]) -> tuple[list, list[QuadraticConstraint]]:
    """
    Processes a sumcheck proof, and produces lists of constraints for
    verification.

    Linear constrants are returned as expressions of the form
    `k + SUM_{i} a[i] sym_w[i]`, representing
    `k + SUM_{i} a[i] sym_w[i] = 0`, and quadratic constraints are
    returned as objects holding three variables, representing
    `w_x * w_y = w_z`.
    """
    for _ in range(MAX_BINDINGS):
        # Discard initial challenges. These are reserved for possible
        # future use.
        _ = transcript.generate_field(field)
    challenges = [
        transcript.generate_field(field)
        for _ in range(MAX_BINDINGS)
    ]
    G = (
        challenges[:circuit.log_num_outputs],
        challenges[:circuit.log_num_outputs],
    )
    claims = (field.zero(), field.zero())
    linear_constraints = []
    quadratic_constraints = []
    for j, layer in enumerate(circuit.layers):
        alpha = transcript.generate_field(field)
        beta = transcript.generate_field(field)
        QZ = layer.quad + beta * layer.Z
        QUAD = QZ.bindv(G[0]) + alpha * QZ.bindv(G[1])
        QUAD = QUAD.drop_dimension()
        (
            G,
            claims,
            linear_constraint,
            quadratic_constraint,
        ) = constraints_layer(
            field,
            QUAD,
            layer.log_num_input_wires,
            sym_pad[j],
            transcript,
            proof[j],
            claims,
            alpha,
        )
        linear_constraints.append(linear_constraint)
        quadratic_constraints.append(quadratic_constraint)

    # Add a constraint checking that the two final claims equal the
    # binding of sym_inputs with G[0] and G[1].
    gamma = transcript.generate_field(field)
    # eq2 = bindv(EQ, G[0]) + gamma * bindv(EQ, G[1])
    eq2 = [
        a + gamma * b
        for a, b in zip(
            bindeq(field, G[0]),
            bindeq(field, G[1]),
        )
    ]
    sym_layer_pad = sym_pad[-1]
    num_private_inputs = circuit.ninputs - circuit.pub_in
    final_constraint = (
        claims[0]
        + sym_layer_pad.vl
        + gamma * claims[1]
        + gamma * sym_layer_pad.vr
        - sum(
            eq2[i] * public_inputs[i]
            for i in range(circuit.pub_in)
        )
        - sum(
            eq2[i + circuit.pub_in] * sym_private_inputs[i]
            for i in range(num_private_inputs)
        )
    )
    linear_constraints.append(final_constraint)
    return linear_constraints, quadratic_constraints


def constraints_layer(
        field,
        QUAD: SparseArray,
        log_num_input_wires: int,
        sym_layer_pad: LayerPad,
        transcript: Transcript,
        layer_proof: LayerProof,
        claims: tuple[Any, Any],
        alpha):
    # Initial claim. This is a known constant during the first round,
    # but it will be a symbolic affine expression in subsequent rounds.
    sym_claim = claims[0] + alpha * claims[1]

    # Lagrange basis polynomials
    R = field["x"]
    lag_0 = R.lagrange_polynomial([
        (field.zero(), field.one()),
        (field.one(), field.zero()),
        (sumcheck_p2(field), field.zero()),
    ])
    lag_1 = R.lagrange_polynomial([
        (field.zero(), field.zero()),
        (field.one(), field.one()),
        (sumcheck_p2(field), field.zero()),
    ])
    lag_2 = R.lagrange_polynomial([
        (field.zero(), field.zero()),
        (field.one(), field.zero()),
        (sumcheck_p2(field), field.one()),
    ])

    G: tuple[list, list] = ([], [])
    for round in range(log_num_input_wires):
        for hand in range(2):
            hp = layer_proof.evals[round][hand]
            sym_hpad = sym_layer_pad.evals[round][hand]

            transcript.write_field(hp.p0)
            transcript.write_field(hp.p2)
            challenge = transcript.generate_field(field)
            G[hand].append(challenge)

            # After decrypting, the polynomial evaluations are expected
            # to be:
            #
            #   p(P0) = hp.p0 + sym_hpad.p0
            #   p(P2) = hp.p2 + sym_hpad.p2
            sym_p0 = hp.p0 + sym_hpad.p0
            sym_p2 = hp.p2 + sym_hpad.p2

            # Compute the implied evaluation, p(P1) = claim - p(P0), in
            # symbolic form.
            sym_p1 = sym_claim - sym_p0

            # Given p(P0), p(P1), and p(P2), interpolate the new claim
            # symbolically.
            sym_claim = (
                lag_0(challenge) * sym_p0
                + lag_1(challenge) * sym_p1
                + lag_2(challenge) * sym_p2
            )

            QUAD = QUAD.bind(challenge, axis=hand)

    # Now the bound QUAD is a 1x1 array.
    Q = QUAD.drop_dimension().drop_dimension()[()]

    # We want to verify that
    #
    #   sym_claim = Q * VL * VR
    #
    # where VL = layer_proof.vl + sym_layer_pad.vl
    #   and VR = layer_proof.vr + sym_layer_pad.vr
    #
    # To keep this constraint linear, we expand the multiplication, and
    # replace sym_layer_pad.vl * sym_layer_pad.vr with
    # sym_layer_pad.vl_vr, checking that these quantities are equal in a
    # separate quadratic constraint.

    linear_constraint = (
        Q * (
            layer_proof.vl * layer_proof.vr
            + layer_proof.vr * sym_layer_pad.vl
            + layer_proof.vl * sym_layer_pad.vr
            + sym_layer_pad.vl_vr
        )
        - sym_claim
    )
    quadratic_constraint = QuadraticConstraint(
        sym_layer_pad.vl,
        sym_layer_pad.vr,
        sym_layer_pad.vl_vr,
    )

    transcript.write_field_element_array([
        layer_proof.vl,
        layer_proof.vr,
    ])

    return (
        G,
        (layer_proof.vl, layer_proof.vr),
        linear_constraint,
        quadratic_constraint,
    )
