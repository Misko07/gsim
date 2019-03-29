
import queue
from results import Results

# Queue = queue.Queue
# PriorityQueue = queue.Queue
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


class Packet:

    def __init__(self, model=None, sim=None, size=None, malicious=False, active=True, module_id=None, generation_time=None, name=None):
        self.model = model
        self.sim = sim
        self.__malicious = malicious
        self.__size = size
        self.active = active  # inactive when reaches destination
        self.module_id = module_id  # the current module it's in
        self.generation_time = generation_time
        self.name = name

    def get_size(self):
        return self.__size

    def is_malicious(self):
        return self.__malicious

    def set_module(self, module_id):
        old_module_id = self.module_id
        old_module = self.model.get_module(old_module_id)
        if hasattr(old_module, 'results'):
            old_module.results.add_packet_departure(id(self), self.sim.get_time())
        new_module = self.model.get_module(module_id)
        if hasattr(new_module, 'results'):
            new_module.results.add_packet_arrival(id(self), self.sim.get_time())
        self.module_id = module_id

    def copy(self):
        return Packet(self.__size, self.__malicious, self.active, self.module_id, self.packet_id)

    def register_with_model(self, model):
        self.model = model

    def register_with_sim(self, sim):
        self.sim = sim



