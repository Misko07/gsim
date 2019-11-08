from gsim.results import Results
from collections import deque

# Todo: Add a 'Module' class and all other modules will inherit of it


class Queue(deque):

    def __init__(self, inputs=None, outputs=None, model=None, sim=None, name=None):
        self.model = model
        self.sim = sim
        self.outputs = outputs
        self.name = name
        self.results = Results()
        deque.__init__(self)

    def _register_with_model(self, model):
        self.model = model

    def _register_with_sim(self, sim):
        self.sim = sim


class Server:

    def __init__(self, inputs=None, outputs=None, service_rate=None, model=None, sim=None, name=None, busy=False):
        self.model = model
        self.sim = sim
        self.inputs = inputs
        self.outputs = outputs
        self.service_rate = service_rate
        self.name = name
        self.busy = busy
        self.results = Results()

    def set_inputs(self, inputs):
        self.inputs = inputs

    def _register_with_model(self, model):
        self.model = model

    def _register_with_sim(self, sim):
        self.sim = sim


class AnomalyDetector:

    def __init__(self, tp_rate, fp_rate, inputs=None, outputs=None, outputs_detected=None, service_rate=None,
                 model=None, sim=None, name=None, busy=None):
        self.tp_rate = tp_rate
        self.fp_rate = fp_rate
        self.model = model
        self.sim = sim
        self.inputs = inputs
        self.outputs = outputs
        self.outputs_detected = outputs_detected
        self.service_rate = service_rate
        self.name = name
        self.busy = busy
        self.results = Results()

    def _register_with_model(self, model):
        self.model = model

    def _register_with_sim(self, sim):
        self.sim = sim


class PermitConnector:
    """
    A PermitConnector is a module that connects a stream of packets and a stream of permits. It matches a single packet
    with a single permit, then forwards the packet, and discards the permit. The idea behind it is to allow modeling of
    systems where the rate of packets will be limited (by the permit rate).

    This module can store one packet or one permit. It forwards the packet to the module's outputs immediately after
    a permit and a packet have been recorded.
    """

    def __init__(self, inputs_pkt=None, inputs_prm=None, outputs=None, model=None, sim=None, name=None):
        self.inputs_pkt = inputs_pkt
        self.inputs_prm = inputs_prm
        self.outputs = outputs
        self.model = model
        self.sim = sim
        self.name = name
        self.results = Results()
        self._packet = None  # current packet
        self._permit = None  # current permit

    def _register_with_model(self, model):
        self.model = model

    def _register_with_sim(self, sim):
        self.sim = sim

    def _has_packet(self):
        return self._packet is not None

    def _has_permit(self):
        return self._permit is not None
