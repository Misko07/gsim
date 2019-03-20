from queue import PriorityQueue
from threading import Thread


class Simulation:

    def __init__(self, duration, model=None, sources=None, destinations=None):
        self.duration = duration
        self.model = model
        self.pq = PriorityQueue()
        self.sources = sources
        self.destinations = destinations
        self.time = 0

    def process_event(self, event):
        if event.etype == 'SERVICE_COMPLETE':
            # todo: get the server which completed service, forward packet to server's outputs, and get a new packet from queue (if existing)
            module = self.model.get_module(event.get_module_id())
            packet = self.model.get_packet(event.get_packet_id())

            print(type(module))
            print(type(packet))
        elif event.etype == 'PACKET_GENERATION':
            # generate a new packet
            source = event.module_id
            source.generate_packet()

    def add_model(self, model):
        self.model = model

    def get_model(self):
        return self.model

    def get_time(self):
        return self.time

    def add_event(self, event):
        self.pq.put(event)

    def get_duration(self):
        return self.duration

    def run(self):
        # start data generators
        for source in self.sources:
            thread = Thread(target=source.generate_packet)
            thread.start()

        while self.pq.qsize() > 0:
            event = self.pq.get()
            print("%s -- event type: %s" % (self.get_time(), event.etype))
            self.time = event.get_timestamp()
            self.process_event(event)


class Model:

    def __init__(self, inputs=None, outputs=None):
        self.inputs = inputs
        self.outputs = outputs
        self.modules = {}
        self.packets = {}

    def set_inputs(self, inputs):
        self.inputs = inputs

    def set_outputs(self, outputs):
        self.outputs = outputs

    def add_module(self, module):
        self.modules[id(module)] = module

    def set_modules(self, modules):
        for module in modules:
            self.add_module(module)

    def get_module(self, module_id):
        return self.modules[module_id]

    def add_packet(self, packet):
        self.packets[id(packet)] = packet

    def get_packet(self, packet_id):
        return self.packets[packet_id]


if __name__ == '__main__':
    from modules import Queue
    from generators import Source

    sim = Simulation(duration=10)

    q1 = Queue()
    source = Source(rate=1, outputs=[{'module': q1, 'prob': 1}], sim=sim)

    m = Model()
    m.add_module(q1)
    m.add_module(source)

    sim.sources = [source]
    m.inputs = [source]

    sim.add_model(m)
    sim.run()
