from queue import PriorityQueue
import gsim_utils as gu
from modules import Queue, Server
from generators import Source
from events import Event
import numpy as np
import logging
import os


if os.path.isfile('logs.log'):
    os.unlink('logs.log')

logging.basicConfig(filename='logs.log', level=logging.DEBUG)


class Simulation:

    def __init__(self, duration, model=None):
        self.duration = duration
        self.model = model
        self.pq = PriorityQueue()
        self.time = 0

    def process_event(self, event):
        # Each event has a module and packet associated with it

        if event.etype == 'SERVICE_COMPLETE':
            server_id = event.get_module_id()
            packet_id = event.get_packet_id()
            server = self.model.get_module(server_id)
            packet = self.model.get_packet(packet_id)
            logging.info("%d -- %s at node %s, packet id: %s" %
                         (self.get_time(), event.etype, server.name, str(packet_id)[-3:]))
            del event
            server.busy = False

            # Send to one of the module's outputs
            destination = gu.choose_output(server.outputs)
            if type(destination) == Server and not destination.busy:
                # move packet to server
                event = Event(
                    timestamp=self.get_time(),
                    etype='SERVER_PACKET_ARRIVAL',
                    module_id=id(destination),
                    packet_id=packet_id
                )
                self.add_event(event)
            elif type(destination) == Queue:
                # Schedule a queue packet arrival event
                event = Event(
                    timestamp=self.get_time(),
                    etype='QUEUE_PACKET_ARRIVAL',
                    module_id=id(destination),
                    packet_id=id(packet)
                )
                self.add_event(event)

            # Get a new packet from inputs
            # todo: Implement multiple inputs to a server
            input_module = server.inputs[0]['module']

            logging.debug("Server %s asks input %s (len: %d) for more packets" %
                          (server.name, input_module.name, len(input_module)))
            if type(input_module) == Queue and len(input_module) > 0:
                new_packet = input_module.pop()
                event = Event(
                    timestamp=self.get_time(),
                    etype='SERVER_PACKET_ARRIVAL',
                    module_id=server_id,
                    packet_id=id(new_packet)
                )
                self.add_event(event)

        elif event.etype == 'PACKET_GENERATION':
            # generate a new packet
            source_id = event.get_module_id()
            packet_id = event.get_packet_id()
            source = self.model.get_module(source_id)
            logging.info("%d -- %s at node %s, packet id: %s" %
                         (self.get_time(), event.etype, source.name, str(packet_id)[-3:]))
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
            logging.info("%d -- %s at node %s (qlen: %d), packet id: %s" %
                         (self.get_time(), event.etype, queue.name, len(queue), str(packet_id)[-3:]))
            del event

            # if packet is first in the queue, inform the output module of this
            if len(queue) == 1:
                destination = gu.choose_output(queue.outputs)
                if destination is None:
                    # Current module has no outputs
                    return

                if type(destination) == Server and not destination.busy:
                    # move packet to server
                    event = Event(
                        timestamp=self.get_time(),
                        etype='SERVER_PACKET_ARRIVAL',
                        module_id=id(destination),
                        packet_id=packet_id
                    )
                    self.add_event(event)
                    queue.pop()
                elif type(destination) == Queue:
                    # Schedule a queue packet arrival event
                    event = Event(
                        timestamp=self.get_time(),
                        etype='QUEUE_PACKET_ARRIVAL',
                        module_id=id(destination),
                        packet_id=id(packet)
                    )
                    self.add_event(event)
                    queue.pop()

        elif event.etype == 'SERVER_PACKET_ARRIVAL':
            server_id = event.get_module_id()
            packet_id = event.get_packet_id()
            server = self.model.get_module(server_id)
            packet = self.model.get_packet(packet_id)
            packet.module_id = server_id

            if not server.busy:
                server.busy = True

            # Schedule service end time
            service_duration = np.random.exponential(1 / server.service_rate)

            logging.info("%d -- %s at node %s, packet id: %s, service duration: %d" %
                         (self.get_time(), event.etype, server.name, str(packet_id)[-3:], service_duration))
            del event

            timestamp = service_duration + self.get_time()
            event = Event(
                timestamp=timestamp,
                etype='SERVICE_COMPLETE',
                module_id=server_id,
                packet_id=packet_id
            )
            self.add_event(event)

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

        # Start data generators
        model = self.model
        for _, source in model.sources.items():
            source.generate_packet()

        while self.pq.qsize() > 0:

            # Get next event from queue
            event = self.pq.get()
            self.time = event.get_timestamp()

            # Check if simulation end reached
            if self.time > self.duration:
                break

            # Process event
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

        if type(module) == Source:
            self.sources[id(module)] = module

    def get_module(self, module_id):
        return self.modules[module_id]

    def add_packet(self, packet):
        self.packets[id(packet)] = packet

    def get_packet(self, packet_id):
        return self.packets[packet_id]


if __name__ == '__main__':

    sim = Simulation(duration=50)
    m = Model(name='model1')

    # Declare model's components
    q1 = Queue(name='q1')
    s1 = Server(name='s1', service_rate=0.2)
    q2 = Queue(name='destination')

    # Add component's inputs and outputs
    gen = Source(rate=5, outputs=[{'module': q1, 'prob': 1}], sim=sim, name='gen')
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
