class Circuit:
    def __init__(self, num_outputs, num_public_inputs, num_inputs, layers):
        self.nv = num_outputs
        self.pub_in = num_public_inputs
        self.ninputs = num_inputs
        self.layers = layers


class CircuitLayer:
    def __init__(self, num_wires, quads):
        self.logw = num_wires.bit_length()
        self.nw = num_wires
        self.quads = quads


class Quad:
    def __init__(self, g, h0, h1, v):
        self.g = g
        self.h0 = h0
        self.h1 = h1
        self.v = v
