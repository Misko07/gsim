
import queue

# Queue = queue.Queue
# PriorityQueue = queue.Queue
from collections import deque


class Queue(deque):

    def __init__(self, inputs=None, outputs=None, model=None, name=None):
        self.inputs = inputs
        self.outputs = outputs
        self.model = model
        self.name = name
        deque.__init__(self)

    def register_with_model(self, model):
        self.model = model


class Server:

    def __init__(self, inputs=None, outputs=None, service_rate=None, model=None, name=None, busy=False):
        self.inputs = inputs
        self.outputs = outputs
        self.service_rate = service_rate
        self.model = model
        self.name = name
        self.busy = busy

    def set_inputs(self, inputs):
        self.inputs = inputs

    def set_outputs(self, outputs):
        self.outputs = outputs

    def set_service_rate(self, service_rate):
        self.service_rate = service_rate

    def register_with_model(self, model):
        self.model = model


class Packet:

    def __init__(self, model=None, size=None, malicious=False, active=True, module_id=None, generation_time=None, name=None):
        self.model = model
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
        self.module_id = module_id

    def copy(self):
        return Packet(self.__size, self.__malicious, self.active, self.module_id, self.packet_id)

    def register_with_model(self, model):
        self.model = model
    #
    # def send(self, destination_id):
    #     destination = self.model.get_module(destination_id)
    #     if destination:
    #         destination.



