from results import Results

from collections import deque


class Queue(deque):

    def __init__(self, inputs=None, outputs=None, model=None, sim=None, name=None):
        self.model = model
        self.sim = sim
        self.inputs = inputs
        self.outputs = outputs
        self.name = name
        self.results = Results()
        deque.__init__(self)

    def register_with_model(self, model):
        self.model = model

    def register_with_sim(self, sim):
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

    def set_outputs(self, outputs):
        self.outputs = outputs

    def set_service_rate(self, service_rate):
        self.service_rate = service_rate

    def register_with_model(self, model):
        self.model = model

    def register_with_sim(self, sim):
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

    def set_inputs(self, inputs):
        self.inputs = inputs

    def set_outputs(self, outputs):
        self.outputs = outputs

    def set_service_rate(self, service_rate):
        self.service_rate = service_rate

    def register_with_model(self, model):
        self.model = model

    def register_with_sim(self, sim):
        self.sim = sim


# Todo: Add a 'Module' class and all other modules will inherit of it
