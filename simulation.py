from queue import PriorityQueue
from threading import Thread
import gsim_utils as gu
from modules import Queue, Server
from generators import Source
from events import Event
import numpy as np


class Simulation:

    def __init__(self, duration, model=None):
        self.duration = duration
        self.model = model
        self.pq = PriorityQueue()
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
            source_id = event.module_id
            source = self.model.get_module(source_id)
            source.generate_packet()
            del event

        elif event.etype == 'QUEUE_PACKET_ARRIVAL':
            # A packet has arrived in a queue
            queue_id = event.get_module_id()
            packet_id = event.get_packet_id()
            queue = self.model.get_module(queue_id)
            packet = self.model.get_packet(packet_id)
            packet.module_id = queue_id
            queue.appendleft(packet)

            # if packet is first in the queue, inform the output module of this
            print('len(queue)', len(queue))
            if len(queue) == 1:
                destination = gu.choose_output(queue.outputs)
                if type(destination) == Server and not destination.busy:
                    # move packet to server
                    event = Event(
                        timestamp=self.get_time(),
                        etype='SERVER_PACKET_ARRIVAL',
                        module_id=id(destination),
                        packet_id=packet_id
                    )
                    self.add_event(event)

        elif event.etype == 'SERVER_PACKET_ARRIVAL':
            server_id = event.get_module_id()
            packet_id = event.get_packet_id()
            server = self.model.get_module(server_id)
            packet = self.model.get_packet(packet_id)

            if not server.busy:
                server.busy = True

            # start service
            # todo: get exponentially distributed interval with mean server.rate ** (-1) and schedule an event


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
        model = self.model
        for _, source in model.sources.items():
            # thread = Thread(target=source.generate_packet)
            # thread.start()
            source.generate_packet()

        while self.pq.qsize() > 0:
            event = self.pq.get()
            self.time = event.get_timestamp()
            print("time: %s -- event type: %s at node: %s" %
                  (self.get_time(), event.etype, self.model.get_module(event.module_id)))
            self.process_event(event)


class Model:

    def __init__(self, name=None):
        self.modules = {}
        self.packets = {}
        self.sources = {}
        self.destinations = {}
        self.name = name

    def add_module(self, module):
        module.register_with_model(self)
        self.modules[id(module)] = module

        print('here', type(module))
        if type(module) == Source:
            print('yahoo')
            self.sources[id(module)] = module
        else:
            print('non yahoo')

    def get_module(self, module_id):
        return self.modules[module_id]

    def add_packet(self, packet):
        self.packets[id(packet)] = packet

    def get_packet(self, packet_id):
        return self.packets[packet_id]


if __name__ == '__main__':


    sim = Simulation(duration=20)
    m = Model(name='model1')

    # Declare model's components
    q1 = Queue(name='q1')
    s1 = Server(name='s1')
    q2 = Queue(name='destination')

    # Add component's details
    gen = Source(rate=5, outputs=[{'module': q1, 'prob': 1}], sim=sim)
    q1.outputs = [{'module': s1, 'prob': 1}]
    s1.inputs = [{'module': q1, 'prob': 1}]
    s1.outputs = [{'module': q2, 'prob': 1}]

    # Register components to model
    m = Model()
    m.add_module(q1)
    m.add_module(s1)
    m.add_module(q2)
    m.add_module(gen)

    sim.add_model(m)
    sim.run()
