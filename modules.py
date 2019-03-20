
import queue

# Queue = queue.Queue
# PriorityQueue = queue.Queue
from collections import deque


class Queue(deque):

    def __init__(self, inputs=None, outputs=None):
        self.inputs = inputs
        self.outputs = outputs
        deque.__init__(self)


class Server:

    def __init__(self, inputs=None, outputs=None, service_rate=None):
        self.inputs = inputs
        self.outputs = outputs
        self.service_rate = service_rate

    def set_inputs(self, inputs):
        self.inputs = inputs

    def set_outputs(self, outputs):
        self.outputs = outputs

    def set_service_rate(self, service_rate):
        self.service_rate = service_rate


class Packet:

    def __init__(self, size=None, malicious=False, active=True, module_id=None, generation_time=None):
        self.__malicious = malicious
        self.__size = size
        self.active = active  # inactive when reaches destination
        self.module_id = module_id  # the current module it's in
        self.generation_time = generation_time

    def get_size(self):
        return self.__size

    def is_malicious(self):
        return self.__malicious

    def set_module(self, module_id):
        self.module_id = module_id

    def copy(self):
        return Packet(self.__size, self.__malicious, self.active, self.module_id, self.packet_id)



